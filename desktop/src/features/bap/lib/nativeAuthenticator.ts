import { coseP256ToPoint, didKeyP256 } from "@bap/core/src/dbap.ts";

import {
  type BapProofPayload,
  type DraftCommitment,
  type ProofCommitment,
  delegationPayloadFromCommitment,
} from "@/features/bap/lib/bapApproval";
import { b64url, finishUcan, ucanSigningInput } from "@/features/bap/lib/ucan";
import { invokeTauri } from "@/shared/api/tauri";
import {
  getStorageItem,
  removeStorageItem,
  setStorageItem,
} from "@/shared/lib/safeStorage";

/**
 * Native DBAP authenticator (macOS Touch ID, Secure Enclave keys) — the
 * in-app replacement for the hosted wallet page's passkey ceremony. Since
 * M18 the passkey IS the approver (`sign-extension` binding):
 *
 *   enrol    /register/challenge → dbap_authenticator_enroll (credential key
 *            + SIGNING key, `client_extension_results`) → /register
 *            → approver DID = did:key(sign_key) → localStorage
 *   approve  /challenge → UCAN signing input (iss = approver DID), tbs
 *            → dbap_authenticator_assert (Touch ID) →
 *            dbap_authenticator_sign_digest (Touch ID; the extension
 *            signature IS the UCAN's ES256 signature) → /verify {proof, ucan}
 *
 * Enrolments made before the sign key (`signature` instead of `sign_key`)
 * keep the `attested-enrollment` ceremony, with the identity key signing
 * the grant afterwards, until the user re-enrols.
 *
 * RP calls go through Rust (`dbap_rp_post`): the RP only answers CORS for
 * its own origin. IO is injectable so the flow itself is unit-tested.
 */

export const NATIVE_ENROLLMENT_STORAGE_KEY = "buzz.bap.nativeEnrollment";

export type NativeAuthenticatorStatus = {
  available: boolean;
  enrolled: boolean;
  credential_id?: string;
  sign_key?: string;
  reason?: string;
};

export type NativeRegistration = {
  attestation_object: string;
  client_data_json: string;
  client_extension_results: {
    sign: {
      generatedKey: { publicKey: string; keyHandle: string; algorithm: number };
    };
  };
  credential_id: string;
  cose_key: string;
};

export type NativeAssertion = {
  credential_id: string;
  authenticator_data: string;
  client_data_json: string;
  signature: string;
};

/**
 * Stored enrolment. `owner_did` is the identity did:key the enrolment was
 * made under (the lookup key); `issuer_did` is the approver DID — the sign
 * key's `did:key:zDn…` — or, for a pre-M18 enrolment, the identity did:key.
 */
export type NativeEnrollment =
  | {
      owner_did: string;
      issuer_did: string;
      credential_id: string;
      cose_key: string;
      sign_key: string;
      key_handle: string;
      signature?: undefined;
    }
  | {
      /** Pre-M18 `attested-enrollment`: issuer is the identity did:key. */
      owner_did?: undefined;
      issuer_did: string;
      credential_id: string;
      cose_key: string;
      sign_key?: undefined;
      /** BIP-340 hex over sha256(enrollmentStatement), by the identity key. */
      signature: string;
    };

export const enrollmentOwner = (e: NativeEnrollment) =>
  e.owner_did ?? e.issuer_did;
export const enrollmentSigns = (
  e: NativeEnrollment,
): e is Extract<NativeEnrollment, { sign_key: string }> =>
  typeof e.sign_key === "string";

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
  /** ES256 by the signing key over `tbs` (base64url, 32 B) as the digest → raw r||s base64url. */
  signExtension: (
    credentialId: string,
    tbs: string,
  ) => Promise<{ signature: string }>;
  rpPost: (
    rpBase: string,
    path: string,
    body: unknown,
  ) => Promise<Record<string, unknown>>;
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
  signExtension: (credentialId, tbs) =>
    invokeTauri<{ signature: string }>("dbap_authenticator_sign_digest", {
      credentialId,
      tbs,
    }),
  rpPost: (rpBase, path, body) =>
    invokeTauri<Record<string, unknown>>("dbap_rp_post", {
      rpBase,
      path,
      body,
    }),
};

const isString = (v: unknown): v is string => typeof v === "string" && v !== "";

export function parseNativeEnrollment(
  raw: string | null,
): NativeEnrollment | null {
  if (!raw) return null;
  try {
    const v = JSON.parse(raw) as Record<string, unknown>;
    if (
      !isString(v.issuer_did) ||
      !isString(v.credential_id) ||
      !isString(v.cose_key)
    ) {
      return null;
    }
    const base = {
      issuer_did: v.issuer_did,
      credential_id: v.credential_id,
      cose_key: v.cose_key,
    };
    if (
      isString(v.sign_key) &&
      isString(v.key_handle) &&
      isString(v.owner_did)
    ) {
      return {
        ...base,
        owner_did: v.owner_did,
        sign_key: v.sign_key,
        key_handle: v.key_handle,
      };
    }
    return isString(v.signature) ? { ...base, signature: v.signature } : null;
  } catch {
    return null;
  }
}

/** The stored enrollment, only if it was made under `ownerDid`. */
export function loadNativeEnrollment(
  ownerDid: string,
): NativeEnrollment | null {
  const e = parseNativeEnrollment(
    getStorageItem(NATIVE_ENROLLMENT_STORAGE_KEY),
  );
  return e && enrollmentOwner(e) === ownerDid ? e : null;
}

export function clearNativeEnrollment(): void {
  removeStorageItem(NATIVE_ENROLLMENT_STORAGE_KEY);
}

function rpError(body: Record<string, unknown>, what: string): Error {
  return new Error(
    `RP ${what}: ${typeof body.error === "string" ? body.error : "unexpected response"}`,
  );
}

/**
 * Enrol this Mac's Secure Enclave credential and signing key with the RP
 * under `ownerDid` (the identity did:key). The approver DID is derived
 * locally from the sign key this Mac made — the RP's answer only confirms it.
 */
export async function enrollNativeAuthenticator(
  rpBase: string,
  ownerDid: string,
  io: NativeIo = tauriNativeIo,
): Promise<NativeEnrollment> {
  // No `issuer_did`: for a sign-extension enrolment the RP learns the
  // approver DID from the ceremony itself.
  const ch = await io.rpPost(rpBase, "/register/challenge", {});
  if (!isString(ch.challenge) || !isString(ch.rp_id) || !isString(ch.origin)) {
    throw rpError(ch, "refused the registration challenge");
  }
  const reg = await io.enroll(ch.rp_id, ch.origin, ch.challenge);
  const generated = reg.client_extension_results.sign.generatedKey;
  const r = await io.rpPost(rpBase, "/register", {
    nonce: ch.nonce,
    attestation_object: reg.attestation_object,
    client_data_json: reg.client_data_json,
    client_extension_results: reg.client_extension_results,
  });
  if (!isString(r.credential_id) || !isString(r.cose_key)) {
    throw rpError(r, "refused the registration");
  }
  if (!isString(r.sign_key)) {
    throw new Error(
      "RP did not accept the passkey signing key (it needs sign-extension support)",
    );
  }
  if (
    r.credential_id !== reg.credential_id ||
    r.cose_key !== reg.cose_key ||
    r.sign_key !== generated.publicKey ||
    r.key_handle !== generated.keyHandle
  ) {
    throw new Error("RP registered a different credential than this Mac made");
  }
  const issuerDid = didKeyP256(coseP256ToPoint(generated.publicKey));
  if (r.issuer_did !== issuerDid) {
    throw new Error("RP approver DID does not match this Mac's signing key");
  }
  const enrollment: NativeEnrollment = {
    owner_did: ownerDid,
    issuer_did: issuerDid,
    credential_id: r.credential_id,
    cose_key: r.cose_key,
    sign_key: generated.publicKey,
    key_handle: generated.keyHandle,
  };
  if (
    !setStorageItem(NATIVE_ENROLLMENT_STORAGE_KEY, JSON.stringify(enrollment))
  ) {
    throw new Error("Could not save the enrollment on this Mac");
  }
  return enrollment;
}

/** Native path is usable: enrolled here, and the Secure Enclave keys match. */
export async function nativeAuthenticatorReady(
  enrollment: NativeEnrollment | null,
  io: NativeIo = tauriNativeIo,
): Promise<boolean> {
  if (!enrollment) return false;
  try {
    const s = await io.status();
    return (
      s.available &&
      s.enrolled &&
      s.credential_id === enrollment.credential_id &&
      (!enrollmentSigns(enrollment) || s.sign_key === enrollment.sign_key)
    );
  } catch {
    return false;
  }
}

export type NativeCeremonyResult = {
  payload: BapProofPayload;
  /** The grant UCAN, already signed by the passkey; absent on the legacy path. */
  token?: string;
};

/**
 * DBAP 1.0 ceremony in-app: RP challenge → Touch ID assertion (→ passkey
 * signature over the UCAN digest) → RP verify → proof payload (+ token).
 * `chainRoot` is the request's chain root, the grant's `sub`.
 */
export async function runNativeCeremony(
  rpBase: string,
  draft: DraftCommitment,
  enrollment: NativeEnrollment,
  chainRoot: string,
  io: NativeIo = tauriNativeIo,
): Promise<NativeCeremonyResult> {
  if (enrollment.issuer_did !== draft.issuer_did) {
    throw new Error(
      `This Mac is enrolled for ${enrollment.issuer_did}, not ${draft.issuer_did}`,
    );
  }
  const ch = await io.rpPost(rpBase, "/challenge", { commitment: draft });
  if (!isString(ch.challenge) || !isString(ch.rp_id) || !ch.commitment) {
    throw rpError(ch, "refused the challenge");
  }
  const commitment = ch.commitment as ProofCommitment;
  const origin = new URL(rpBase).origin;
  const a = await io.assert(ch.rp_id, origin, ch.challenge);
  const base = {
    type: "DeviceBoundApprovalProof" as const,
    dbap_version: "1.0" as const,
    commitment,
  };
  if (!enrollmentSigns(enrollment)) {
    const proof: BapProofPayload["proof"] = {
      ...base,
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
    return {
      payload: {
        proof,
        verify: { ok: true, commitment_hash: v.commitment_hash },
      },
    };
  }
  // sign-extension: tbs = sha256(UCAN signing input); the passkey's signature
  // over it is the token's signature segment (spec §Credential binding).
  const { signingInput, tbs } = ucanSigningInput(
    delegationPayloadFromCommitment(commitment, chainRoot),
  );
  const tbsB64 = b64url(tbs);
  const { signature } = await io.signExtension(
    enrollment.credential_id,
    tbsB64,
  );
  const { token } = finishUcan(signingInput, signature);
  const proof: BapProofPayload["proof"] = {
    ...base,
    webauthn: {
      rp_id: ch.rp_id,
      ...a,
      extensions: { sign: { tbs: tbsB64, signature } },
    },
    credential_binding: {
      method: "sign-extension",
      value: `${enrollment.issuer_did}#sign`,
      enrollment: {
        credential_id: enrollment.credential_id,
        cose_key: enrollment.cose_key,
        sign_key: enrollment.sign_key,
        key_handle: enrollment.key_handle,
      },
    },
  };
  const v = await io.rpPost(rpBase, "/verify", { proof, ucan: token });
  if (v.ok !== true || !isString(v.commitment_hash)) {
    throw rpError(v, "rejected the proof");
  }
  return {
    payload: {
      proof,
      verify: { ok: true, commitment_hash: v.commitment_hash },
    },
    token,
  };
}
