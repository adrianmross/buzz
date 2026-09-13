import assert from "node:assert/strict";
import test from "node:test";

import { schnorr } from "@noble/curves/secp256k1";
import { didKeyFromNostrPubkey } from "@bap/core/src/did.ts";
import { grantWithinCommitment } from "@bap/core/src/dbap.ts";
import { signDelegation, verifyDelegation } from "@bap/core/src/ucan.ts";

import { assembleUcan } from "./ucan.ts";
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
