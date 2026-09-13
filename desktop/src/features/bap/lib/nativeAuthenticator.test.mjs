import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import test from "node:test";

import { p256 } from "@noble/curves/p256";
import { schnorr } from "@noble/curves/secp256k1";
import { didKeyFromNostrPubkey } from "@bap/core/src/did.ts";
import {
  challengeFor,
  coseP256ToPoint,
  didKeyP256,
  enrollmentStatement,
  signExtensionTbs,
  softwareAuthenticator,
  validateCommitment,
  verifyProof,
  verifySignExtensionUcan,
} from "@bap/core/src/dbap.ts";
import { jcs } from "@bap/core/src/jcs.ts";
import { signDelegation, verifyDelegation } from "@bap/core/src/ucan.ts";
import {
  softwareRegistration,
  verifyRegistration,
} from "@bap/core/src/webauthn-register.ts";

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
  enrollmentSigns,
  loadNativeEnrollment,
  nativeAuthenticatorReady,
  parseNativeEnrollment,
  runNativeCeremony,
} = await import("./nativeAuthenticator.ts");
const { delegationPayloadFromCommitment } = await import("./bapApproval.ts");

const hex = (b) =>
  Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
const unhex = (s) =>
  Uint8Array.from(s.match(/../g), (x) => Number.parseInt(x, 16));
const utf8 = (s) => new TextEncoder().encode(s);
const sha256 = (bytes) =>
  new Uint8Array(createHash("sha256").update(bytes).digest());
const b64 = (bytes) =>
  btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
const unb64 = (s) =>
  Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (c) =>
    c.charCodeAt(0),
  );
const P256_HALF_N = p256.CURVE.n / 2n;

// Deterministic test identity: its did:key is the vector commitment's issuer
// and the `owner_did` every enrolment is filed under.
const sk = "11".repeat(32);
const pk = schnorr.getPublicKey(unhex(sk));
const iss = didKeyFromNostrPubkey(hex(pk));
const verifyEnrollmentSig = (_iss, stmt, sig) =>
  schnorr.verify(unhex(sig), sha256(utf8(stmt)), pk);

/**
 * Emitted by the Rust module's `interop_vector_for_bap_core` test
 * (`BAP_DBAP_VECTOR_OUT=… cargo test dbap_authenticator`): a registration
 * (with the `sign` extension's client output), an assertion, and a
 * sign-extension signature, all made by the desktop's encoder with real
 * ES256 keys.
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
const CHAIN_ROOT = "did:key:zQ3shdg8nhyhD7WgKpQd82tCtAjUvfSgyHYzT2gUG4FajUmoh";

const legacyEnrollmentFor = (reg) => ({
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

test("Rust registration passes bap-core verifyRegistration and yields sign_key/key_handle", () => {
  const reg = verifyRegistration(
    vector.registration,
    vector.enroll_challenge,
    RP,
    vector.origin,
  );
  assert.equal(reg.credential_id, vector.registration.credential_id);
  assert.equal(reg.cose_key, vector.registration.cose_key);
  assert.equal(reg.aaguid, "0".repeat(32));
  const generated =
    vector.registration.client_extension_results.sign.generatedKey;
  assert.equal(generated.algorithm, -7);
  assert.equal(reg.sign_key, generated.publicKey);
  assert.equal(reg.key_handle, generated.keyHandle);
  assert.equal(unb64(reg.key_handle).length, 16);
  assert.notEqual(reg.sign_key, reg.cose_key, "distinct signing key");
  assert.match(didKeyP256(coseP256ToPoint(reg.sign_key)), /^did:key:zDn/);
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

test("Rust sign-extension signature is ES256 over tbs as the digest, raw r||s, low-S", () => {
  const { signing_input, tbs, signature } = vector.sign_extension;
  assert.deepEqual(unb64(tbs), signExtensionTbs(signing_input));
  const sig = unb64(signature);
  assert.equal(sig.length, 64);
  assert.ok(
    BigInt(`0x${hex(sig.subarray(32))}`) <= P256_HALF_N,
    "low-S normalised",
  );
  const signKey = coseP256ToPoint(
    vector.registration.client_extension_results.sign.generatedKey.publicKey,
  );
  assert.equal(p256.verify(sig, unb64(tbs), signKey, { prehash: false }), true);
  // Not a signature over sha256(tbs) — the enclave hashed nothing itself.
  assert.equal(p256.verify(sig, unb64(tbs), signKey, { prehash: true }), false);
  // And not by the credential key.
  assert.equal(
    p256.verify(
      sig,
      unb64(tbs),
      coseP256ToPoint(vector.registration.cose_key),
      {
        prehash: false,
      },
    ),
    false,
  );
});

test("Rust assertion passes bap-core verifyProof with a pre-M18 attested enrollment", () => {
  assert.equal(jcs(commitment), vector.commitment_jcs);
  assert.equal(commitment.issuer_did, iss);
  assert.equal(challengeFor(commitment), vector.assert_challenge);
  const enrollment = legacyEnrollmentFor(vector.registration);
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

/**
 * A fake RP (real bap-core verifiers) + fake Tauri commands. The enclave is
 * bap-core's deterministic software authenticator: credential key for
 * `assert`, its distinct sign key for `signExtension` (ES256 over the digest).
 */
function fakeIo({ status, register } = {}) {
  const auth = softwareAuthenticator("55".repeat(32));
  const calls = [];
  const issued = new Set();
  return {
    auth,
    calls,
    status: async () =>
      status ?? {
        available: true,
        enrolled: true,
        credential_id: auth.credential_id,
        sign_key: auth.sign_key,
      },
    enroll: async (rpId, origin, challenge) => {
      calls.push(["enroll", rpId, origin, challenge]);
      // bap-core's software registration in the Rust command's shape.
      const r = softwareRegistration({
        rp_id: rpId,
        origin,
        challenge,
        point: auth.point,
        credential_id: auth.credential_id,
        sign: { sign_key: auth.sign_key, key_handle: auth.key_handle },
      });
      return {
        ...r,
        credential_id: auth.credential_id,
        cose_key: auth.cose_key,
      };
    },
    assert: async (rpId, origin, challenge) => {
      calls.push(["assert", rpId, origin, challenge]);
      const { rp_id: _rp, ...a } = auth.assert(challenge, rpId, { origin });
      return a;
    },
    signExtension: async (credentialId, tbs) => {
      calls.push(["signExtension", credentialId, tbs]);
      assert.equal(credentialId, auth.credential_id);
      return { signature: auth.signExtension(unb64(tbs)) };
    },
    rpPost: async (rpBase, path, body) => {
      calls.push(["rpPost", rpBase, path]);
      assert.equal(rpBase, RP_BASE);
      switch (path) {
        case "/register/challenge":
          assert.deepEqual(
            body,
            {},
            "no issuer_did: the passkey is the approver",
          );
          return {
            nonce: "n1",
            challenge: "dbap:enroll:n1",
            rp_id: RP,
            origin: RP_BASE,
          };
        case "/register": {
          assert.equal(body.nonce, "n1");
          const r = verifyRegistration(body, "dbap:enroll:n1", RP, RP_BASE);
          const issuer_did = didKeyP256(coseP256ToPoint(r.sign_key));
          return register
            ? register({ ...r, issuer_did })
            : { ...r, issuer_did };
        }
        case "/challenge": {
          const nonce = "AAAAAAAAAAAAAAAAAAAAAA";
          const c = validateCommitment({ ...body.commitment, nonce });
          issued.add(nonce);
          return {
            nonce,
            commitment: c,
            challenge: challengeFor(c),
            rp_id: RP,
          };
        }
        case "/verify": {
          const r = verifyProof(body.proof, {
            now: 1500,
            rpId: RP,
            verifyEnrollmentSig,
          });
          if (r.tbsHex) {
            assert.equal(
              typeof body.ucan,
              "string",
              "sign-extension needs the UCAN",
            );
            verifySignExtensionUcan(body.ucan, body.proof);
          }
          assert.ok(issued.delete(body.proof.commitment.nonce), "nonce issued");
          return { ok: true, commitment_hash: r.commitmentHashHex };
        }
        default:
          throw new Error(`unexpected ${path}`);
      }
    },
  };
}

test("enrolNativeAuthenticator: challenge → enroll (sign extension) → register → passkey DID in localStorage", async () => {
  store.clear();
  const io = fakeIo();
  const enrollment = await enrollNativeAuthenticator(RP_BASE, iss, io);
  assert.deepEqual(
    io.calls.map((c) => c.slice(0, 3)),
    [
      ["rpPost", RP_BASE, "/register/challenge"],
      ["enroll", RP, RP_BASE],
      ["rpPost", RP_BASE, "/register"],
    ],
  );
  assert.deepEqual(enrollment, {
    owner_did: iss,
    issuer_did: io.auth.sign_did,
    credential_id: io.auth.credential_id,
    cose_key: io.auth.cose_key,
    sign_key: io.auth.sign_key,
    key_handle: io.auth.key_handle,
  });
  assert.equal(enrollmentSigns(enrollment), true);
  assert.deepEqual(
    JSON.parse(store.get(NATIVE_ENROLLMENT_STORAGE_KEY)),
    enrollment,
  );
  assert.deepEqual(loadNativeEnrollment(iss), enrollment);
  assert.equal(loadNativeEnrollment("did:key:zOther"), null);
  assert.equal(
    loadNativeEnrollment(io.auth.sign_did),
    null,
    "keyed by owner, not approver",
  );
});

test("enrolNativeAuthenticator refuses an RP that swaps the key or the DID, or lacks the extension", async () => {
  store.clear();
  await assert.rejects(
    enrollNativeAuthenticator(
      RP_BASE,
      iss,
      fakeIo({ register: (r) => ({ ...r, issuer_did: "did:key:zDnEvil" }) }),
    ),
    /approver DID does not match/,
  );
  await assert.rejects(
    enrollNativeAuthenticator(
      RP_BASE,
      iss,
      fakeIo({ register: (r) => ({ ...r, sign_key: r.cose_key }) }),
    ),
    /different credential/,
  );
  await assert.rejects(
    enrollNativeAuthenticator(
      RP_BASE,
      iss,
      fakeIo({ register: ({ sign_key: _s, key_handle: _k, ...r }) => r }),
    ),
    /sign-extension support/,
  );
  assert.equal(store.has(NATIVE_ENROLLMENT_STORAGE_KEY), false);
});

test("parseNativeEnrollment: pre-M18 and M18 shapes load; anything else is null", () => {
  const legacy = legacyEnrollmentFor(vector.registration);
  const parsedLegacy = parseNativeEnrollment(JSON.stringify(legacy));
  assert.deepEqual(parsedLegacy, legacy);
  assert.equal(enrollmentSigns(parsedLegacy), false);
  store.clear();
  store.set(NATIVE_ENROLLMENT_STORAGE_KEY, JSON.stringify(legacy));
  assert.deepEqual(
    loadNativeEnrollment(iss),
    legacy,
    "legacy: owner is the issuer",
  );
  const m18 = {
    owner_did: iss,
    issuer_did: "did:key:zDnX",
    credential_id: "c",
    cose_key: "k",
    sign_key: "s",
    key_handle: "h",
  };
  assert.deepEqual(parseNativeEnrollment(JSON.stringify(m18)), m18);
  // A sign key without its owner or handle is neither shape.
  const { owner_did: _o, ...noOwner } = m18;
  assert.equal(parseNativeEnrollment(JSON.stringify(noOwner)), null);
  assert.equal(
    parseNativeEnrollment(JSON.stringify({ ...m18, sign_key: "" })),
    null,
  );
  assert.equal(parseNativeEnrollment("{"), null);
  assert.equal(parseNativeEnrollment(null), null);
});

test("runNativeCeremony (sign-extension): challenge → assert → passkey signs the UCAN digest → verify {proof, ucan}", async () => {
  store.clear();
  const io = fakeIo();
  const enrollment = await enrollNativeAuthenticator(RP_BASE, iss, io);
  io.calls.length = 0;
  const { nonce: _nonce, ...draft } = {
    ...commitment,
    issuer_did: io.auth.sign_did,
  };
  const { payload, token } = await runNativeCeremony(
    RP_BASE,
    draft,
    enrollment,
    CHAIN_ROOT,
    io,
  );
  assert.deepEqual(
    io.calls.map((c) => c[0]),
    ["rpPost", "assert", "signExtension", "rpPost"],
  );
  // The proof carries the vector's binding shape.
  const { proof } = payload;
  assert.equal(proof.credential_binding.method, "sign-extension");
  assert.equal(proof.credential_binding.value, `${io.auth.sign_did}#sign`);
  assert.deepEqual(Object.keys(proof.credential_binding.enrollment), [
    "credential_id",
    "cose_key",
    "sign_key",
    "key_handle",
  ]);
  assert.deepEqual(Object.keys(proof.webauthn.extensions), ["sign"]);
  assert.deepEqual(Object.keys(proof.webauthn.extensions.sign), [
    "tbs",
    "signature",
  ]);
  // The token is bap-core's ES256 delegation by the passkey, and the extension
  // signature is its signature segment.
  const parsed = verifyDelegation(token);
  assert.equal(parsed.alg, "ES256");
  assert.equal(parsed.payload.iss, io.auth.sign_did);
  assert.equal(parsed.payload.sub, CHAIN_ROOT);
  assert.equal(parsed.payload.nonce, "grant-req-1");
  assert.equal(token.split(".")[2], proof.webauthn.extensions.sign.signature);
  assert.equal(
    b64(signExtensionTbs(token.split(".").slice(0, 2).join("."))),
    proof.webauthn.extensions.sign.tbs,
  );
  // Byte-identical to signDelegation with the software authenticator's sign key.
  const signPriv = sha256(
    new Uint8Array([
      ...utf8("dbap:sign-extension:"),
      ...unhex("55".repeat(32)),
    ]),
  );
  assert.equal(
    token,
    signDelegation(
      delegationPayloadFromCommitment(proof.commitment, CHAIN_ROOT),
      { privkeyHex: hex(signPriv), keyType: "p256" },
    ),
  );
  assert.equal(payload.verify.ok, true);
});

test("runNativeCeremony (sign-extension) fails closed on a wrong extension signature", async () => {
  store.clear();
  const io = fakeIo();
  const enrollment = await enrollNativeAuthenticator(RP_BASE, iss, io);
  const { nonce: _nonce, ...draft } = {
    ...commitment,
    issuer_did: io.auth.sign_did,
  };
  const other = softwareAuthenticator("66".repeat(32));
  io.signExtension = async (_id, tbs) => ({
    signature: other.signExtension(unb64(tbs)),
  });
  await assert.rejects(
    runNativeCeremony(RP_BASE, draft, enrollment, CHAIN_ROOT, io),
    /bad signature/,
  );
  await assert.rejects(
    runNativeCeremony(RP_BASE, commitment, enrollment, CHAIN_ROOT, io),
    new RegExp(`enrolled for ${io.auth.sign_did}`),
  );
});

test("runNativeCeremony (pre-M18 enrolment): attested-enrollment proof, no token", async () => {
  const enrollment = legacyEnrollmentFor(vector.registration);
  const { nonce: _nonce, ...draft } = commitment;
  const io = fakeIo();
  io.assert = async (rpId, origin, challenge) => {
    io.calls.push(["assert", rpId, origin, challenge]);
    assert.equal(challenge, vector.assert_challenge);
    return vector.assertion;
  };
  const { payload, token } = await runNativeCeremony(
    RP_BASE,
    draft,
    enrollment,
    CHAIN_ROOT,
    io,
  );
  assert.equal(token, undefined);
  assert.equal(payload.verify.ok, true);
  assert.equal(payload.proof.commitment.nonce, commitment.nonce);
  assert.equal(payload.proof.credential_binding.method, "attested-enrollment");
  assert.equal(payload.proof.webauthn.extensions, undefined);
  assert.equal(
    io.calls.some((c) => c[0] === "signExtension"),
    false,
    "the passkey never signs on the legacy path",
  );
});

test("nativeAuthenticatorReady requires availability, enrolment and the same keys", async () => {
  const io = fakeIo();
  const m18 = {
    owner_did: iss,
    issuer_did: io.auth.sign_did,
    credential_id: io.auth.credential_id,
    cose_key: io.auth.cose_key,
    sign_key: io.auth.sign_key,
    key_handle: io.auth.key_handle,
  };
  assert.equal(await nativeAuthenticatorReady(null, io), false);
  assert.equal(await nativeAuthenticatorReady(m18, io), true);
  const withStatus = (status) => fakeIo({ status });
  assert.equal(
    await nativeAuthenticatorReady(
      m18,
      withStatus({ available: false, enrolled: false }),
    ),
    false,
  );
  assert.equal(
    await nativeAuthenticatorReady(
      m18,
      withStatus({
        available: true,
        enrolled: true,
        credential_id: io.auth.credential_id,
        sign_key: "stale",
      }),
    ),
    false,
    "the enclave's sign key must be the enrolled one",
  );
  // A pre-M18 enrolment is ready without a sign key on the enclave.
  const legacy = legacyEnrollmentFor(vector.registration);
  assert.equal(
    await nativeAuthenticatorReady(
      legacy,
      withStatus({
        available: true,
        enrolled: true,
        credential_id: vector.registration.credential_id,
      }),
    ),
    true,
  );
  assert.equal(
    await nativeAuthenticatorReady(
      legacy,
      withStatus({ available: true, enrolled: true, credential_id: "stale" }),
    ),
    false,
  );
});
