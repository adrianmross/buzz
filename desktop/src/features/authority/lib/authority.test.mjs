import assert from "node:assert/strict";
import test from "node:test";

const values = new Map();
globalThis.window = {
  localStorage: {
    getItem: (key) => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, String(value)),
    removeItem: (key) => values.delete(key),
  },
};

const {
  DEFAULT_MEDIATOR_INVITATION_URL,
  DEFAULT_RELYING_PARTY_URL,
  KIND_BAP_ANNOUNCEMENT,
  announcementRowsFor,
  announcementToRow,
  didNostrFromPubkey,
  readAuthoritySettings,
  relyingPartyInfoUrl,
  writeAuthoritySettings,
} = await import("./authority.ts");

const ME = "ea9b4d7a7a78a3e3729e5568b14d764d4962be0e1f20f749bcf8d9dbbf9a9328";
const OTHER =
  "f1a95a79781164eaea997e277444ef4518ed0cf4473b35da6110e0241622853c";

test("didNostrFromPubkey formats a 64-hex x-only key and rejects the rest", () => {
  assert.equal(didNostrFromPubkey(ME), `did:nostr:${ME}`);
  assert.equal(didNostrFromPubkey(ME.toUpperCase()), `did:nostr:${ME}`);
  assert.equal(didNostrFromPubkey(undefined), null);
  assert.equal(didNostrFromPubkey("npub1abc"), null);
  assert.equal(didNostrFromPubkey(ME.slice(0, 63)), null);
});

test("settings default when unset and persist as a pair", () => {
  values.clear();
  assert.deepEqual(readAuthoritySettings(), {
    relyingPartyUrl: DEFAULT_RELYING_PARTY_URL,
    mediatorInvitationUrl: DEFAULT_MEDIATOR_INVITATION_URL,
  });
  assert.equal(DEFAULT_RELYING_PARTY_URL, "https://approve.red-wiz.stream");
  assert.ok(
    DEFAULT_MEDIATOR_INVITATION_URL.startsWith(
      "https://didcomm.red-wiz.stream/invite?oob=",
    ),
  );

  assert.equal(
    writeAuthoritySettings({
      relyingPartyUrl: " https://rp.example ",
      mediatorInvitationUrl: "",
    }),
    true,
  );
  // Trimmed on write; a blank value falls back to the default on read.
  assert.deepEqual(readAuthoritySettings(), {
    relyingPartyUrl: "https://rp.example",
    mediatorInvitationUrl: DEFAULT_MEDIATOR_INVITATION_URL,
  });
});

test("relyingPartyInfoUrl appends /rp once", () => {
  assert.equal(
    relyingPartyInfoUrl("https://rp.example///"),
    "https://rp.example/rp",
  );
  assert.equal(
    relyingPartyInfoUrl(" https://rp.example"),
    "https://rp.example/rp",
  );
});

function event(overrides) {
  return {
    id: "evt",
    pubkey: OTHER,
    created_at: 100,
    kind: KIND_BAP_ANNOUNCEMENT,
    tags: [],
    content: "",
    sig: "",
    ...overrides,
  };
}

test("announcementToRow reads d/resource/revision/owner and falls back to the signer", () => {
  const full = announcementToRow(
    event({
      tags: [
        ["d", "wallet"],
        ["resource", "did:web:x/wallet"],
        ["revision", "7"],
        ["owner", `did:nostr:${ME}`],
      ],
      content: "x".repeat(200),
    }),
  );
  assert.equal(full.d, "wallet");
  assert.equal(full.resource, "did:web:x/wallet");
  assert.equal(full.revision, 7);
  assert.equal(full.ownerDid, `did:nostr:${ME}`);
  assert.equal(full.updatedAt, 100);
  assert.equal(full.contentSummary.length, 120);

  // Reference-shaped replica announcement: only d/agent, no revision.
  const bare = announcementToRow(
    event({
      tags: [
        ["d", "r-vec"],
        ["agent", "did:key:zQ3sh"],
        ["revision", "-1"],
      ],
    }),
  );
  assert.equal(bare.resource, "r-vec");
  assert.equal(bare.revision, null);
  assert.equal(bare.ownerDid, "did:key:zQ3sh");

  assert.equal(announcementToRow(event({})).ownerDid, `did:nostr:${OTHER}`);
});

test("announcementRowsFor keeps only announcements naming me, deduped, newest first", () => {
  const rows = announcementRowsFor(
    [
      event({ id: "mine", pubkey: ME, created_at: 1 }),
      event({ id: "approver", tags: [["p", ME]], created_at: 3 }),
      event({ id: "approver", tags: [["p", ME]], created_at: 3 }),
      event({
        id: "owner-did",
        tags: [["owner", `did:nostr:${ME}`]],
        created_at: 2,
      }),
      event({ id: "stranger", tags: [["p", OTHER]], created_at: 9 }),
      event({ id: "wrong-kind", pubkey: ME, kind: 30550, created_at: 9 }),
    ],
    ME,
  );
  assert.deepEqual(
    rows.map((row) => row.id),
    ["approver", "owner-did", "mine"],
  );
});
