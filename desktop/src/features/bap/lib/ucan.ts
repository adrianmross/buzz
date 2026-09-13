import { jcs } from "@bap/core/src/jcs.ts";
import {
  ALG,
  type DelegationPayload,
  UCAN_VERSION,
  validatePayload,
  verifyDelegation,
} from "@bap/core/src/ucan.ts";

/**
 * `signDelegation` from bap-core with the signature step externalised: the
 * desktop's identity key never leaves Rust, so the JCS/JWT assembly happens
 * here and only the 32-byte digest crosses the IPC boundary to be signed
 * (BIP-340 Schnorr). Token layout is bap-core's exactly:
 * b64url(JCS header).b64url(JCS payload).b64url(sig over sha256(input)).
 */

export type DigestSigner = (digestHex: string) => Promise<string>;

const utf8 = (s: string) => new TextEncoder().encode(s);
const b64url = (bytes: Uint8Array) =>
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

export async function assembleUcan(
  payload: unknown,
  signDigest: DigestSigner,
): Promise<{ token: string; payload: DelegationPayload }> {
  const p = validatePayload(payload);
  const header = { alg: ALG, typ: "JWT", ucv: UCAN_VERSION };
  const signingInput = `${b64url(utf8(jcs(header)))}.${b64url(utf8(jcs(p)))}`;
  const digest = new Uint8Array(
    await crypto.subtle.digest("SHA-256", utf8(signingInput)),
  );
  const sig = unhex(await signDigest(hex(digest)));
  const token = `${signingInput}.${b64url(sig)}`;
  // Fail closed: the signer must be the `iss` key and the encoding canonical.
  const verified = verifyDelegation(token);
  return { token, payload: verified.payload };
}
