import assert from "node:assert/strict";
import test from "node:test";

import {
  bapKindTitle,
  eventToBapCard,
  parseBapRequestApproval,
} from "./bapCard.ts";

const REQUEST = {
  type: "https://didcomm.org/agent-approval/1.0/request-approval",
  id: "req-1",
  from: "did:key:zAgent",
  to: ["did:key:zApprover"],
  created_time: 1_000,
  expires_time: 4_600,
  body: {
    command: "/git/merge",
    resource: "nostr:git/naddr1/refs/heads/main",
    action_digest: `sha256:${"ab".repeat(32)}`,
    justification: "merge PR #7 <script>",
    requested_ttl: 900,
    requested_policy: [["==", ".pr", "7"]],
    delegation_context: { chain_root: "did:key:zOwner", presented_chain: "" },
    risk: "high",
  },
};

const field = (card, label) => card.fields.find((f) => f.label === label);

test("eventToBapCard_request_digestFirstFields", () => {
  const card = eventToBapCard({
    kind: 4550,
    tags: [["p", "ab".repeat(32)]],
    content: JSON.stringify(REQUEST),
  });
  assert.equal(card.title, "Approval request");
  assert.equal(card.request.id, "req-1");
  assert.equal(field(card, "command").value, "/git/merge");
  assert.equal(field(card, "action digest").value, REQUEST.body.action_digest);
  assert.equal(field(card, "requester").value, "did:key:zAgent");
  assert.equal(field(card, "requested").value, "ttl 900s · risk high");
  assert.equal(field(card, "policy").value, '[["==",".pr","7"]]');
  assert.equal(field(card, "expires").value, "1970-01-01T01:16:40.000Z");
  // Free text is flagged so the renderer keeps it visually subordinate.
  assert.equal(field(card, "justification").untrusted, true);
  // Machine fields lead; the untrusted text is last.
  assert.equal(card.fields.at(-1).label, "justification");
});

test("eventToBapCard_request_malformedContent_fallsBackToTags", () => {
  const card = eventToBapCard({
    kind: 4550,
    tags: [
      ["cmd", "/git/push"],
      ["res", "nostr:git/x/main"],
      ["ttl", "60"],
    ],
    content: "not json",
  });
  assert.equal(card.request, undefined);
  assert.equal(field(card, "command").value, "/git/push");
  assert.equal(field(card, "ttl").value, "60");
});

test("parseBapRequestApproval_rejectsShapeless", () => {
  assert.equal(parseBapRequestApproval("{}"), null);
  assert.equal(parseBapRequestApproval('{"body":{}}'), null);
  assert.equal(
    parseBapRequestApproval(JSON.stringify({ ...REQUEST, to: "x" })),
    null,
  );
});

test("eventToBapCard_grant_linksRequest", () => {
  const card = eventToBapCard({
    kind: 4551,
    tags: [
      ["p", "cd".repeat(32)],
      ["aud", "did:key:zAgent"],
      ["cmd", "/git/merge"],
      ["res", "nostr:git/naddr1/refs/heads/main"],
      ["expiration", "4600"],
      ["req", "ee".repeat(32)],
    ],
    content: "h.p.s",
  });
  assert.equal(card.title, "Grant");
  assert.equal(card.requestEventId, "ee".repeat(32));
  assert.equal(field(card, "audience").value, "did:key:zAgent");
  assert.equal(field(card, "expires").value, "1970-01-01T01:16:40.000Z");
});

test("eventToBapCard_revocationCheckpointStopResume", () => {
  const revoke = eventToBapCard({
    kind: 4553,
    tags: [
      ["prf", "bafy1"],
      ["e", "ff".repeat(32)],
    ],
    content: "tok",
  });
  assert.equal(field(revoke, "revoked delegation").value, "bafy1");

  const cp = eventToBapCard({
    kind: 4564,
    tags: [
      ["e", "aa".repeat(32), "", "root"],
      ["agent", "did:key:zAgent"],
      ["replica", "r1"],
      ["step", "3"],
      ["prev", "bb".repeat(32)],
    ],
    content: JSON.stringify({ committed: "c1", pending: "p1", refs: {} }),
  });
  assert.equal(cp.title, "Checkpoint");
  assert.equal(field(cp, "task").value, "aa".repeat(32));
  assert.equal(field(cp, "step").value, "3");
  assert.equal(field(cp, "prev").value, "bb".repeat(32));
  assert.equal(field(cp, "committed").value, "c1");

  const stop = eventToBapCard({
    kind: 4570,
    tags: [
      ["root", "did:key:zOwner"],
      ["reason", "runaway"],
    ],
    content: "",
  });
  assert.equal(stop.title, "Emergency stop");
  assert.equal(field(stop, "scope").value, "all");
  assert.equal(field(stop, "reason").value, "runaway");

  const resume = eventToBapCard({
    kind: 4571,
    tags: [
      ["e", "dd".repeat(32)],
      ["root", "did:key:zOwner"],
      ["dbap", "inline"],
    ],
    content: JSON.stringify({ note: "fixed", dbap: { type: "x" } }),
  });
  assert.equal(resume.title, "Resume");
  assert.equal(field(resume, "lifts stop").value, "dd".repeat(32));
  assert.equal(field(resume, "device proof").value, "inline (DBAP)");
  assert.equal(field(resume, "note").value, "fixed");
});

test("eventToBapCard_otherBapKinds_genericTagCard", () => {
  const card = eventToBapCard({
    kind: 4565,
    tags: [
      ["seq", "12"],
      ["d", "x"],
    ],
    content: "",
  });
  assert.equal(card.title, "Beacon");
  assert.deepEqual(card.fields, [
    { label: "seq", value: "12" },
    { label: "d", value: "x" },
  ]);
  assert.equal(bapKindTitle(4599), "BAP kind 4599");
});

test("eventToBapCard_nonBapKind_null", () => {
  assert.equal(eventToBapCard({ kind: 9, tags: [], content: "hi" }), null);
  assert.equal(eventToBapCard({ kind: 34560, tags: [], content: "" }), null);
});
