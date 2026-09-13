import { enrollmentStatement } from "@bap/core/src/dbap.ts";

import type {
  BapProofPayload,
  DraftCommitment,
  ProofCommitment,
} from "@/features/bap/lib/bapApproval";
import type { DigestSigner } from "@/features/bap/lib/ucan";
import { invokeTauri, signDigest } from "@/shared/api/tauri";
import {
  getStorageItem,
  removeStorageItem,
  setStorageItem,
} from "@/shared/lib/safeStorage";

/**
 * Native DBAP authenticator (macOS Touch ID, Secure Enclave key) — the
 * in-app replacement for the hosted wallet page's passkey ceremony:
 *
 *   enrol    /register/challenge → dbap_authenticator_enroll → /register
 *            → sign the enrollment statement with the identity key (sign_digest)
 *            → localStorage `NATIVE_ENROLLMENT_STORAGE_KEY`
 *   approve  /challenge → dbap_authenticator_assert (Touch ID) → /verify
 *            → the same `BapProofPayload` the deep link used to carry
 *
 * RP calls go through Rust (`dbap_rp_post`): the RP only answers CORS for
 * its own origin. IO is injectable so the flow itself is unit-tested.
 */

/** `{issuer_did, credential_id, cose_key, signature}` — the `attested-enrollment` the RP verifies. */
export const NATIVE_ENROLLMENT_STORAGE_KEY = "buzz.bap.nativeEnrollment";

export type NativeAuthenticatorStatus = {
  available: boolean;
  enrolled: boolean;
  credential_id?: string;
  reason?: string;
};

export type NativeRegistration = {
  attestation_object: string;
  client_data_json: string;
  credential_id: string;
  cose_key: string;
};

export type NativeAssertion = {
  credential_id: string;
  authenticator_data: string;
  client_data_json: string;
  signature: string;
};

export type NativeEnrollment = {
  issuer_did: string;
  credential_id: string;
  cose_key: string;
  /** BIP-340 hex over sha256(enrollmentStatement), by the identity key. */
  signature: string;
};

export type NativeIo = {
  status: () => Promise<NativeAuthenticatorStatus>;
  enroll: (
    rpId: string,
    origin: string,
    challenge: string,
  ) => Promise<NativeRegistration>;
  assert: (
    rpId: string,
    origin: string,
    challenge: string,
  ) => Promise<NativeAssertion>;
  rpPost: (
    rpBase: string,
    path: string,
    body: unknown,
  ) => Promise<Record<string, unknown>>;
  signDigest: DigestSigner;
};

export const tauriNativeIo: NativeIo = {
  status: () =>
    invokeTauri<NativeAuthenticatorStatus>("dbap_authenticator_status"),
  enroll: (rpId, origin, challenge) =>
    invokeTauri<NativeRegistration>("dbap_authenticator_enroll", {
      rpId,
      origin,
      challenge,
    }),
  assert: (rpId, origin, challenge) =>
    invokeTauri<NativeAssertion>("dbap_authenticator_assert", {
      rpId,
      origin,
      challenge,
    }),
  rpPost: (rpBase, path, body) =>
    invokeTauri<Record<string, unknown>>("dbap_rp_post", {
      rpBase,
      path,
      body,
    }),
  signDigest,
};

const isString = (v: unknown): v is string => typeof v === "string" && v !== "";

function parseEnrollment(raw: string | null): NativeEnrollment | null {
  if (!raw) return null;
  try {
    const v = JSON.parse(raw) as Record<string, unknown>;
    return isString(v.issuer_did) &&
      isString(v.credential_id) &&
      isString(v.cose_key) &&
      isString(v.signature)
      ? {
          issuer_did: v.issuer_did,
          credential_id: v.credential_id,
          cose_key: v.cose_key,
          signature: v.signature,
        }
      : null;
  } catch {
    return null;
  }
}

/** The stored enrollment, only if it belongs to `issuerDid`. */
export function loadNativeEnrollment(
  issuerDid: string,
): NativeEnrollment | null {
  const e = parseEnrollment(getStorageItem(NATIVE_ENROLLMENT_STORAGE_KEY));
  return e?.issuer_did === issuerDid ? e : null;
}

export function clearNativeEnrollment(): void {
  removeStorageItem(NATIVE_ENROLLMENT_STORAGE_KEY);
}

const hex = (bytes: Uint8Array) =>
  Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");

async function sha256Hex(text: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(text),
  );
  return hex(new Uint8Array(digest));
}

function rpError(body: Record<string, unknown>, what: string): Error {
  return new Error(
    `RP ${what}: ${typeof body.error === "string" ? body.error : "unexpected response"}`,
  );
}

/**
 * Enrol this Mac's Secure Enclave credential for `issuerDid` and persist the
 * signed enrollment. The statement is recomputed locally and must match the
 * RP's — the identity key never signs text the RP chose.
 */
export async function enrollNativeAuthenticator(
  rpBase: string,
  issuerDid: string,
  io: NativeIo = tauriNativeIo,
): Promise<NativeEnrollment> {
  const ch = await io.rpPost(rpBase, "/register/challenge", {
    issuer_did: issuerDid,
  });
  if (!isString(ch.challenge) || !isString(ch.rp_id) || !isString(ch.origin)) {
    throw rpError(ch, "refused the registration challenge");
  }
  const reg = await io.enroll(ch.rp_id, ch.origin, ch.challenge);
  const r = await io.rpPost(rpBase, "/register", {
    nonce: ch.nonce,
    attestation_object: reg.attestation_object,
    client_data_json: reg.client_data_json,
  });
  if (!isString(r.credential_id) || !isString(r.cose_key)) {
    throw rpError(r, "refused the registration");
  }
  if (r.credential_id !== reg.credential_id || r.cose_key !== reg.cose_key) {
    throw new Error("RP registered a different credential than this Mac made");
  }
  const statement = enrollmentStatement(issuerDid, r.credential_id, r.cose_key);
  if (r.statement !== statement) {
    throw new Error("RP enrollment statement does not match the credential");
  }
  const enrollment: NativeEnrollment = {
    issuer_did: issuerDid,
    credential_id: r.credential_id,
    cose_key: r.cose_key,
    signature: await io.signDigest(await sha256Hex(statement)),
  };
  if (
    !setStorageItem(NATIVE_ENROLLMENT_STORAGE_KEY, JSON.stringify(enrollment))
  ) {
    throw new Error("Could not save the enrollment on this Mac");
  }
  return enrollment;
}

/** Native path is usable: enrolled here, and the Secure Enclave key matches. */
export async function nativeAuthenticatorReady(
  enrollment: NativeEnrollment | null,
  io: NativeIo = tauriNativeIo,
): Promise<boolean> {
  if (!enrollment) return false;
  try {
    const s = await io.status();
    return (
      s.available && s.enrolled && s.credential_id === enrollment.credential_id
    );
  } catch {
    return false;
  }
}

/**
 * DBAP 1.0 ceremony in-app, mirroring `runCeremony` in the wallet page:
 * RP challenge → Touch ID assertion → RP verify → proof payload.
 */
export async function runNativeCeremony(
  rpBase: string,
  draft: DraftCommitment,
  enrollment: NativeEnrollment,
  io: NativeIo = tauriNativeIo,
): Promise<BapProofPayload> {
  if (enrollment.issuer_did !== draft.issuer_did) {
    throw new Error(
      `This Mac is enrolled for ${enrollment.issuer_did}, not ${draft.issuer_did}`,
    );
  }
  const ch = await io.rpPost(rpBase, "/challenge", { commitment: draft });
  if (!isString(ch.challenge) || !isString(ch.rp_id) || !ch.commitment) {
    throw rpError(ch, "refused the challenge");
  }
  const origin = new URL(rpBase).origin;
  const a = await io.assert(ch.rp_id, origin, ch.challenge);
  const proof: BapProofPayload["proof"] = {
    type: "DeviceBoundApprovalProof",
    dbap_version: "1.0",
    commitment: ch.commitment as ProofCommitment,
    webauthn: { rp_id: ch.rp_id, ...a },
    credential_binding: {
      method: "attested-enrollment",
      value: `${enrollment.issuer_did}#dbap`,
      enrollment,
    },
  };
  const v = await io.rpPost(rpBase, "/verify", { proof });
  if (v.ok !== true || !isString(v.commitment_hash)) {
    throw rpError(v, "rejected the proof");
  }
  return { proof, verify: { ok: true, commitment_hash: v.commitment_hash } };
}
