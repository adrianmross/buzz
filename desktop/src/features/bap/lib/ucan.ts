import { signExtensionTbs } from "@bap/core/src/dbap.ts";
import { didKeyCodec } from "@bap/core/src/did.ts";
import { jcs } from "@bap/core/src/jcs.ts";
import {
  type DelegationPayload,
  UCAN_VERSION,
  algOfCodec,
  validatePayload,
  verifyDelegation,
} from "@bap/core/src/ucan.ts";

/**
 * `signDelegation` from bap-core with the signature step externalised: no
 * signing key ever reaches TS, so the JCS/JWT assembly happens here and only
 * the 32-byte digest of the signing input crosses the IPC boundary:
 *
 *   secp256k1 `iss` (identity did:key)  → `sign_digest`, BIP-340, hex back
 *   P-256 `iss` (passkey did:key, M18)   → `dbap_authenticator_sign_digest`,
 *                                          ES256 over the digest, raw r||s
 *
 * Token layout is bap-core's exactly:
 * b64url(JCS header).b64url(JCS payload).b64url(sig over sha256(input)),
 * header `alg` chosen by the issuer's key type (`algOfCodec`).
 */

export type DigestSigner = (digestHex: string) => Promise<string>;

const utf8 = (s: string) => new TextEncoder().encode(s);
export const b64url = (bytes: Uint8Array) =>
  btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
const hex = (bytes: Uint8Array) =>
  Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
const unhex = (s: string) => {
  if (!/^[0-9a-f]{128}$/i.test(s))
    throw new Error("signature must be 64 bytes hex");
  return Uint8Array.from(s.match(/../g) ?? [], (b) => Number.parseInt(b, 16));
};

/**
 * The JWS signing input `b64url(JCS header).b64url(JCS payload)` for a
 * validated payload, plus its sha256 — the sign extension's `tbs` and the
 * digest bap-core's own signer hashes (`signExtensionTbs`).
 */
export function ucanSigningInput(payload: unknown): {
  payload: DelegationPayload;
  signingInput: string;
  tbs: Uint8Array;
} {
  const p = validatePayload(payload);
  const header = {
    alg: algOfCodec(didKeyCodec(p.iss)),
    typ: "JWT",
    ucv: UCAN_VERSION,
  };
  const signingInput = `${b64url(utf8(jcs(header)))}.${b64url(utf8(jcs(p)))}`;
  return { payload: p, signingInput, tbs: signExtensionTbs(signingInput) };
}

/**
 * `signingInput.signature` as a verified token. Fails closed: the signature
 * must be the `iss` key's over the input and the encoding canonical.
 */
export function finishUcan(
  signingInput: string,
  signatureB64url: string,
): { token: string; payload: DelegationPayload } {
  const token = `${signingInput}.${signatureB64url}`;
  const verified = verifyDelegation(token);
  return { token, payload: verified.payload };
}

/** Identity-key (secp256k1 `iss`) path: the Rust `sign_digest` signs the hash. */
export async function assembleUcan(
  payload: unknown,
  signDigest: DigestSigner,
): Promise<{ token: string; payload: DelegationPayload }> {
  const { signingInput, tbs } = ucanSigningInput(payload);
  return finishUcan(signingInput, b64url(unhex(await signDigest(hex(tbs)))));
}
