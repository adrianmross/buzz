import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import test from "node:test";

import { schnorr } from "@noble/curves/secp256k1";
import { didKeyFromNostrPubkey } from "@bap/core/src/did.ts";
import {
  challengeFor,
  enrollmentStatement,
  verifyProof,
} from "@bap/core/src/dbap.ts";
import { jcs } from "@bap/core/src/jcs.ts";
import { verifyRegistration } from "@bap/core/src/webauthn-register.ts";

// Minimal localStorage for node (same shim as the sidebar watermark tests).
const store = new Map();
if (typeof globalThis.window === "undefined") globalThis.window = {};
globalThis.window.localStorage = {
  getItem: (k) => store.get(k) ?? null,
  setItem: (k, v) => store.set(k, v),
  removeItem: (k) => store.delete(k),
};

const {
  NATIVE_ENROLLMENT_STORAGE_KEY,
  enrollNativeAuthenticator,
  loadNativeEnrollment,
  nativeAuthenticatorReady,
  runNativeCeremony,
} = await import("./nativeAuthenticator.ts");

const hex = (b) =>
  Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
const unhex = (s) =>
  Uint8Array.from(s.match(/../g), (x) => Number.parseInt(x, 16));
const utf8 = (s) => new TextEncoder().encode(s);
const sha256 = (bytes) =>
  new Uint8Array(createHash("sha256").update(bytes).digest());

// Deterministic test identity: its did:key is the vector commitment's issuer.
const sk = "11".repeat(32);
const pk = schnorr.getPublicKey(unhex(sk));
const iss = didKeyFromNostrPubkey(hex(pk));
const rustLikeSigner = async (digestHex) =>
  hex(schnorr.sign(unhex(digestHex), unhex(sk)));
const verifyEnrollmentSig = (_iss, stmt, sig) =>
  schnorr.verify(unhex(sig), sha256(utf8(stmt)), pk);

/**
 * Emitted by the Rust module's `interop_vector_for_bap_core` test
 * (`BAP_DBAP_VECTOR_OUT=… cargo test dbap_authenticator`): a registration and
 * an assertion made by the desktop's encoder with a real ES256 key.
 */
const vector = JSON.parse(
  readFileSync(
    new URL("./nativeAuthenticator.vector.json", import.meta.url),
    "utf8",
  ),
);
const RP = vector.rp_id;
const RP_BASE = `https://${RP}`;
const commitment = JSON.parse(vector.commitment_jcs);

const enrollmentFor = (reg) => ({
  issuer_did: iss,
  credential_id: reg.credential_id,
  cose_key: reg.cose_key,
  signature: hex(
    schnorr.sign(
      sha256(utf8(enrollmentStatement(iss, reg.credential_id, reg.cose_key))),
      unhex(sk),
    ),
  ),
});

test("Rust registration passes bap-core verifyRegistration (fmt none, UV, AT, P-256)", () => {
  const reg = verifyRegistration(
    vector.registration,
    vector.enroll_challenge,
    RP,
    vector.origin,
  );
  assert.equal(reg.credential_id, vector.registration.credential_id);
  assert.equal(reg.cose_key, vector.registration.cose_key);
  assert.equal(reg.aaguid, "0".repeat(32));
  assert.throws(
    () =>
      verifyRegistration(
        vector.registration,
        vector.enroll_challenge,
        RP,
        "https://evil.example",
      ),
    /origin/,
  );
});

test("Rust assertion passes bap-core verifyProof with an attested enrollment", () => {
  assert.equal(jcs(commitment), vector.commitment_jcs);
  assert.equal(commitment.issuer_did, iss);
  assert.equal(challengeFor(commitment), vector.assert_challenge);
  const enrollment = enrollmentFor(vector.registration);
  const proof = {
    type: "DeviceBoundApprovalProof",
    dbap_version: "1.0",
    commitment,
    webauthn: { rp_id: RP, ...vector.assertion },
    credential_binding: {
      method: "attested-enrollment",
      value: `${iss}#dbap`,
      enrollment,
    },
  };
  const ctx = { now: 1500, rpId: RP, verifyEnrollmentSig };
  const ok = verifyProof(proof, ctx);
  assert.equal(ok.commitment.request_ref, "req-1");
  // Fails closed on a tampered signature and on a foreign RP.
  const bad = structuredClone(proof);
  bad.webauthn.signature = bad.webauthn.signature.replace(/.$/, (c) =>
    c === "A" ? "B" : "A",
  );
  assert.throws(() => verifyProof(bad, ctx), /signature invalid/);
  assert.throws(
    () => verifyProof(proof, { ...ctx, rpId: "other.localhost" }),
    /rp_id/,
  );
});

/** A fake RP + fake Tauri commands, replaying the vector through real bap-core checks. */
function fakeIo({ status, statement } = {}) {
  const calls = [];
  return {
    calls,
    status: async () =>
      status ?? {
        available: true,
        enrolled: true,
        credential_id: vector.registration.credential_id,
      },
    enroll: async (rpId, origin, challenge) => {
      calls.push(["enroll", rpId, origin, challenge]);
      return vector.registration;
    },
    assert: async (rpId, origin, challenge) => {
      calls.push(["assert", rpId, origin, challenge]);
      assert.equal(challenge, vector.assert_challenge);
      return vector.assertion;
    },
    rpPost: async (rpBase, path, body) => {
      calls.push(["rpPost", rpBase, path]);
      assert.equal(rpBase, RP_BASE);
      switch (path) {
        case "/register/challenge":
          return {
            nonce: "n1",
            challenge: vector.enroll_challenge,
            rp_id: RP,
            origin: vector.origin,
          };
        case "/register": {
          assert.equal(body.nonce, "n1");
          const r = verifyRegistration(
            body,
            vector.enroll_challenge,
            RP,
            vector.origin,
          );
          return {
            ...r,
            statement:
              statement ??
              enrollmentStatement(iss, r.credential_id, r.cose_key),
          };
        }
        case "/challenge":
          assert.equal(body.commitment.request_ref, "req-1");
          return {
            nonce: commitment.nonce,
            commitment,
            challenge: challengeFor(commitment),
            rp_id: RP,
          };
        case "/verify": {
          const r = verifyProof(body.proof, {
            now: 1500,
            rpId: RP,
            verifyEnrollmentSig,
          });
          return { ok: true, commitment_hash: r.commitmentHashHex };
        }
        default:
          throw new Error(`unexpected ${path}`);
      }
    },
    signDigest: rustLikeSigner,
  };
}

test("enrolNativeAuthenticator: challenge → enroll → register → signed statement in localStorage", async () => {
  store.clear();
  const io = fakeIo();
  const enrollment = await enrollNativeAuthenticator(RP_BASE, iss, io);
  assert.deepEqual(
    io.calls.map((c) => c.slice(0, 3)),
    [
      ["rpPost", RP_BASE, "/register/challenge"],
      ["enroll", RP, vector.origin],
      ["rpPost", RP_BASE, "/register"],
    ],
  );
  assert.equal(enrollment.credential_id, vector.registration.credential_id);
  assert.ok(
    verifyEnrollmentSig(
      iss,
      enrollmentStatement(iss, enrollment.credential_id, enrollment.cose_key),
      enrollment.signature,
    ),
  );
  assert.deepEqual(
    JSON.parse(store.get(NATIVE_ENROLLMENT_STORAGE_KEY)),
    enrollment,
  );
  assert.deepEqual(loadNativeEnrollment(iss), enrollment);
  assert.equal(loadNativeEnrollment("did:key:zOther"), null);
});

test("enrolNativeAuthenticator never signs a statement the RP altered", async () => {
  store.clear();
  const io = fakeIo({ statement: '{"dbap_enrollment":"1.0","evil":true}' });
  await assert.rejects(
    enrollNativeAuthenticator(RP_BASE, iss, io),
    /statement does not match/,
  );
  assert.equal(store.has(NATIVE_ENROLLMENT_STORAGE_KEY), false);
});

test("runNativeCeremony: challenge → Touch ID assertion → verify → proof payload", async () => {
  const enrollment = enrollmentFor(vector.registration);
  const { nonce: _nonce, ...draft } = commitment;
  const io = fakeIo();
  const payload = await runNativeCeremony(RP_BASE, draft, enrollment, io);
  assert.equal(payload.verify.ok, true);
  assert.equal(payload.proof.commitment.nonce, commitment.nonce);
  assert.equal(payload.proof.webauthn.rp_id, RP);
  assert.equal(payload.proof.credential_binding.method, "attested-enrollment");
  assert.deepEqual(
    io.calls.find((c) => c[0] === "assert"),
    ["assert", RP, RP_BASE, vector.assert_challenge],
  );
  await assert.rejects(
    runNativeCeremony(
      RP_BASE,
      draft,
      { ...enrollment, issuer_did: "did:key:zOther" },
      io,
    ),
    /enrolled for did:key:zOther/,
  );
});

test("nativeAuthenticatorReady requires availability, enrolment and the same credential", async () => {
  const enrollment = enrollmentFor(vector.registration);
  assert.equal(await nativeAuthenticatorReady(null, fakeIo()), false);
  assert.equal(await nativeAuthenticatorReady(enrollment, fakeIo()), true);
  assert.equal(
    await nativeAuthenticatorReady(
      enrollment,
      fakeIo({ status: { available: false, enrolled: false } }),
    ),
    false,
  );
  assert.equal(
    await nativeAuthenticatorReady(
      enrollment,
      fakeIo({
        status: { available: true, enrolled: true, credential_id: "stale" },
      }),
    ),
    false,
  );
});
