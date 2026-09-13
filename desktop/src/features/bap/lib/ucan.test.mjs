import assert from "node:assert/strict";
import test from "node:test";

import { p256 } from "@noble/curves/p256";
import { schnorr } from "@noble/curves/secp256k1";
import { didKeyFromNostrPubkey } from "@bap/core/src/did.ts";
import { grantWithinCommitment, signExtensionTbs } from "@bap/core/src/dbap.ts";
import {
  didOfP256,
  signDelegation,
  verifyDelegation,
} from "@bap/core/src/ucan.ts";

import { assembleUcan, b64url, finishUcan, ucanSigningInput } from "./ucan.ts";
import { delegationPayloadFromCommitment } from "./bapApproval.ts";

const hex = (b) =>
  Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
const unhex = (s) =>
  Uint8Array.from(s.match(/../g), (x) => Number.parseInt(x, 16));

// Deterministic test keys (never real identities).
const sk = "11".repeat(32);
const iss = didKeyFromNostrPubkey(hex(schnorr.getPublicKey(unhex(sk))));
const agentSk = "22".repeat(32);
const aud = didKeyFromNostrPubkey(hex(schnorr.getPublicKey(unhex(agentSk))));

// Stands in for the Rust `sign_digest` command: BIP-340 over the digest.
const rustLikeSigner = async (digestHex) =>
  hex(schnorr.sign(unhex(digestHex), unhex(sk)));

const commitment = {
  dbap_version: "1.0",
  grant_type: "ucan-delegation",
  issuer_did: iss,
  audience_did: aud,
  command: "/git/merge",
  resource: "nostr:git/naddr1/refs/heads/main",
  policy: [["==", ".action_digest", `sha256:${"ef".repeat(32)}`]],
  not_before: 1_000,
  expires: 1_900,
  request_ref: "req-1",
  nonce: "AAAAAAAAAAAAAAAAAAAAAA",
};

test("assembleUcan_producesTokenBapCoreVerifies_withinCommitment", async () => {
  const payload = delegationPayloadFromCommitment(commitment, iss);
  grantWithinCommitment(payload, commitment); // the approve path's guard
  const { token } = await assembleUcan(payload, rustLikeSigner);
  const parsed = verifyDelegation(token);
  assert.equal(parsed.payload.iss, iss);
  assert.equal(parsed.payload.aud, aud);
  assert.equal(parsed.payload.nonce, "grant-req-1");
  assert.equal(parsed.payload.exp, 1_900);
  assert.deepEqual(parsed.payload.flags, {
    binding: "action",
    subdelegation: false,
  });
  // Same header/payload segments as bap-core's own signer (only the sig differs).
  const reference = signDelegation(payload, { privkeyHex: sk });
  assert.equal(
    token.split(".").slice(0, 2).join("."),
    reference.split(".").slice(0, 2).join("."),
  );
});

test("assembleUcan_failsClosed_onWrongSigner_orInvalidPayload", async () => {
  const payload = delegationPayloadFromCommitment(commitment, iss);
  const wrongKey = async (d) => hex(schnorr.sign(unhex(d), unhex(agentSk)));
  await assert.rejects(assembleUcan(payload, wrongKey), /bad signature/);
  await assert.rejects(
    assembleUcan(payload, async () => "zz"),
    /64 bytes/,
  );
  await assert.rejects(
    assembleUcan({ ...payload, cmd: "not-a-command" }, rustLikeSigner),
    /cmd/,
  );
});

// M18: the passkey is the issuer. A P-256 test key stands in for the Secure
// Enclave signing key: ES256 over `tbs` AS THE DIGEST (no re-hash), raw r||s.
const passkeySk = "33".repeat(32);
const passkeyIss = didOfP256(passkeySk);
const enclaveLikeSigner = (tbs) =>
  b64url(
    p256
      .sign(tbs, unhex(passkeySk), { lowS: true, prehash: false })
      .toCompactRawBytes(),
  );

test("ucanSigningInput_tbs_isBapCoreSignExtensionTbs_andHeaderFollowsIssuer", () => {
  const es256 = ucanSigningInput(
    delegationPayloadFromCommitment(
      { ...commitment, issuer_did: passkeyIss },
      iss,
    ),
  );
  assert.deepEqual(es256.tbs, signExtensionTbs(es256.signingInput));
  assert.equal(es256.tbs.length, 32);
  const [header] = es256.signingInput.split(".");
  assert.deepEqual(
    JSON.parse(atob(header.replace(/-/g, "+").replace(/_/g, "/"))),
    {
      alg: "ES256",
      typ: "JWT",
      ucv: "1.0.0-rc.1",
    },
  );
  const schnorrHeader = ucanSigningInput(
    delegationPayloadFromCommitment(commitment, iss),
  ).signingInput.split(".")[0];
  assert.match(atob(schnorrHeader.replace(/_/g, "/")), /ES256K-Schnorr/);
});

test("finishUcan_withThePasskeySignature_isBapCoreES256Token", () => {
  const payload = delegationPayloadFromCommitment(
    { ...commitment, issuer_did: passkeyIss },
    iss,
  );
  const { signingInput, tbs } = ucanSigningInput(payload);
  const { token, payload: verified } = finishUcan(
    signingInput,
    enclaveLikeSigner(tbs),
  );
  const parsed = verifyDelegation(token);
  assert.equal(parsed.alg, "ES256");
  assert.equal(parsed.payload.iss, passkeyIss);
  assert.equal(verified.iss, passkeyIss);
  // RFC 6979 on both sides: byte-identical to bap-core's own signer.
  assert.equal(
    token,
    signDelegation(payload, { privkeyHex: passkeySk, keyType: "p256" }),
  );
  // The extension signature must be the token's signature segment, verbatim.
  assert.equal(token.split(".")[2], enclaveLikeSigner(tbs));
  // Fails closed: another key, or the identity key's Schnorr over the same digest.
  const other = b64url(
    p256
      .sign(tbs, unhex("44".repeat(32)), { prehash: false })
      .toCompactRawBytes(),
  );
  assert.throws(() => finishUcan(signingInput, other), /bad signature/);
  assert.throws(
    () => finishUcan(signingInput, b64url(schnorr.sign(tbs, unhex(sk)))),
    /bad signature/,
  );
});
