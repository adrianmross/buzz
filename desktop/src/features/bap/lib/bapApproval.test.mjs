import assert from "node:assert/strict";
import test from "node:test";

import {
  buildDelegationEventTags,
  buildDraftCommitment,
  buildRpApproveUrl,
  decodeFragmentJson,
  delegationPayloadFromCommitment,
  encodeFragmentJson,
  isRequestAddressedTo,
  parseBapRequestEvent,
  parseProofDeepLinkPayload,
  selectPendingRequests,
} from "./bapApproval.ts";

const ME = "ab".repeat(32);
const OTHER = "cd".repeat(32);
const me = { pubkey: ME, didKey: "did:key:zMe" };
const CHANNEL = "11111111-2222-4333-8444-555555555555";

function requestEvent(overrides = {}, body = {}) {
  return {
    id: overrides.id ?? "e1".padEnd(64, "0"),
    kind: 4550,
    pubkey: OTHER,
    created_at: overrides.created_at ?? 1_000,
    tags: overrides.tags ?? [
      ["h", CHANNEL],
      ["p", ME],
    ],
    content: JSON.stringify({
      type: "https://didcomm.org/agent-approval/1.0/request-approval",
      id: overrides.reqId ?? "req-1",
      from: "did:key:zAgent",
      to: overrides.to ?? ["did:key:zMe"],
      created_time: 1_000,
      expires_time: overrides.expires ?? 5_000,
      body: {
        command: "/git/merge",
        resource: "nostr:git/naddr1/refs/heads/main",
        action_digest: `sha256:${"ef".repeat(32)}`,
        justification: "merge it",
        requested_ttl: 900,
        requested_policy: [["==", ".pr", "7"]],
        delegation_context: {
          chain_root: "did:key:zOwner",
          presented_chain: "",
        },
        risk: "high",
        ...body,
      },
    }),
  };
}

test("parseBapRequestEvent_readsChannelAndApprover", () => {
  const req = parseBapRequestEvent(requestEvent());
  assert.equal(req.channelId, CHANNEL);
  assert.equal(req.approverPubkey, ME);
  assert.equal(req.request.command, "/git/merge");
  assert.equal(parseBapRequestEvent({ ...requestEvent(), kind: 9 }), null);
  assert.equal(parseBapRequestEvent({ ...requestEvent(), content: "x" }), null);
});

test("isRequestAddressedTo_pTag_didNostr_didKey", () => {
  assert.equal(
    isRequestAddressedTo(parseBapRequestEvent(requestEvent()), me),
    true,
  );
  const byDidNostr = parseBapRequestEvent(
    requestEvent({ tags: [], to: [`did:nostr:${ME}`] }),
  );
  assert.equal(isRequestAddressedTo(byDidNostr, me), true);
  const byDidKey = parseBapRequestEvent(
    requestEvent({ tags: [], to: ["did:key:zMe"] }),
  );
  assert.equal(isRequestAddressedTo(byDidKey, me), true);
  const someoneElse = parseBapRequestEvent(
    requestEvent({ tags: [["p", OTHER]], to: ["did:key:zOther"] }),
  );
  assert.equal(isRequestAddressedTo(someoneElse, me), false);
  // M18: a request naming the enrolled passkey DID is mine too.
  const byPasskey = parseBapRequestEvent(
    requestEvent({ tags: [], to: ["did:key:zDnPasskey"] }),
  );
  assert.equal(isRequestAddressedTo(byPasskey, me), false);
  assert.equal(
    isRequestAddressedTo(byPasskey, {
      ...me,
      approverDid: "did:key:zDnPasskey",
    }),
    true,
  );
});

test("selectPendingRequests_dropsAnswered_expired_foreign_andSortsNewestFirst", () => {
  const older = requestEvent({ id: "a".repeat(64), created_at: 100 });
  const newer = requestEvent({ id: "b".repeat(64), created_at: 200 });
  const answered = requestEvent({ id: "c".repeat(64), created_at: 300 });
  const expired = requestEvent({
    id: "d".repeat(64),
    created_at: 400,
    expires: 1_500,
  });
  const foreign = requestEvent({
    id: "e".repeat(64),
    created_at: 500,
    tags: [["p", OTHER]],
    to: ["did:key:zOther"],
  });
  const grants = [
    { kind: 4551, tags: [["req", "c".repeat(64)]] },
    { kind: 9, tags: [["req", "b".repeat(64)]] }, // not a grant
  ];
  const pending = selectPendingRequests(
    [older, newer, answered, expired, foreign],
    grants,
    me,
    2_000,
  );
  assert.deepEqual(
    pending.map((r) => r.eventId),
    ["b".repeat(64), "a".repeat(64)],
  );
});

test("buildDraftCommitment_matchesWalletCli", () => {
  const req = parseBapRequestEvent(requestEvent());
  const draft = buildDraftCommitment(req, "did:key:zMe", 10_000);
  assert.deepEqual(draft, {
    dbap_version: "1.0",
    grant_type: "ucan-delegation",
    issuer_did: "did:key:zMe",
    audience_did: "did:key:zAgent",
    command: "/git/merge",
    resource: "nostr:git/naddr1/refs/heads/main",
    policy: [
      ["==", ".pr", "7"],
      ["==", ".action_digest", `sha256:${"ef".repeat(32)}`],
    ],
    not_before: 10_000,
    expires: 10_900,
    request_ref: "req-1",
  });
  // ttl never above the request's.
  assert.equal(buildDraftCommitment(req, "did:key:zMe", 0, 5_000).expires, 900);
  assert.equal(buildDraftCommitment(req, "did:key:zMe", 0, 60).expires, 60);
});

test("fragmentJson_roundTrips_andRpUrlUsesFragment", () => {
  const draft = { a: 1, s: "ü/+=" };
  const encoded = encodeFragmentJson(draft);
  assert.match(encoded, /^[A-Za-z0-9_-]+$/);
  assert.deepEqual(decodeFragmentJson(encoded), draft);
  assert.equal(decodeFragmentJson("%%%"), null);
  const url = buildRpApproveUrl("https://approve.example/", draft);
  assert.equal(url, `https://approve.example/#req=${encoded}`);
  assert.equal(new URL(url).search, "");
});

const commitment = {
  dbap_version: "1.0",
  grant_type: "ucan-delegation",
  issuer_did: "did:key:zMe",
  audience_did: "did:key:zAgent",
  command: "/git/merge",
  resource: "nostr:git/naddr1/refs/heads/main",
  policy: [["==", ".action_digest", "sha256:00"]],
  not_before: 1,
  expires: 901,
  request_ref: "req-1",
  nonce: "AAAAAAAAAAAAAAAAAAAAAA",
};
const proofPayload = {
  proof: {
    type: "DeviceBoundApprovalProof",
    dbap_version: "1.0",
    commitment,
    webauthn: { rp_id: "approve.example" },
    credential_binding: {
      method: "attested-enrollment",
      value: "did:key:zMe#dbap",
    },
  },
  verify: { ok: true, commitment_hash: "ff".repeat(32) },
};

test("parseProofDeepLinkPayload_acceptsVerifiedProof_rejectsRest", () => {
  const parsed = parseProofDeepLinkPayload(encodeFragmentJson(proofPayload));
  assert.equal(parsed.proof.commitment.request_ref, "req-1");
  assert.equal(parseProofDeepLinkPayload("garbage"), null);
  assert.equal(
    parseProofDeepLinkPayload(
      encodeFragmentJson({
        ...proofPayload,
        verify: { ok: false, error: "no" },
      }),
    ),
    null,
  );
  assert.equal(
    parseProofDeepLinkPayload(
      encodeFragmentJson({
        ...proofPayload,
        proof: {
          ...proofPayload.proof,
          commitment: { ...commitment, nonce: "" },
        },
      }),
    ),
    null,
  );
  assert.equal(
    parseProofDeepLinkPayload(
      encodeFragmentJson({
        ...proofPayload,
        proof: { ...proofPayload.proof, type: "x" },
      }),
    ),
    null,
  );
});

test("delegationPayloadFromCommitment_andEventTags", () => {
  const payload = delegationPayloadFromCommitment(commitment, "did:key:zOwner");
  assert.deepEqual(payload, {
    iss: "did:key:zMe",
    aud: "did:key:zAgent",
    sub: "did:key:zOwner",
    cmd: "/git/merge",
    res: ["nostr:git/naddr1/refs/heads/main"],
    pol: commitment.policy,
    nonce: "grant-req-1",
    nbf: 1,
    exp: 901,
    flags: { binding: "action", subdelegation: false },
  });
  const tags = buildDelegationEventTags(payload, {
    audiencePubkey: OTHER,
    requestEventId: "a".repeat(64),
    channelId: CHANNEL,
  });
  assert.deepEqual(tags, [
    ["h", CHANNEL],
    ["p", OTHER],
    ["aud", "did:key:zAgent"],
    ["cmd", "/git/merge"],
    ["res", "nostr:git/naddr1/refs/heads/main"],
    ["expiration", "901"],
    ["req", "a".repeat(64)],
  ]);
  const noAudience = buildDelegationEventTags(payload, {
    audiencePubkey: undefined,
    requestEventId: "a".repeat(64),
    channelId: null,
  });
  assert.equal(
    noAudience.some((t) => t[0] === "p" || t[0] === "h"),
    false,
  );
});
