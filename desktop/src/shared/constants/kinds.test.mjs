import assert from "node:assert/strict";
import test from "node:test";

import {
  isConversationalUnreadKind,
  KIND_STREAM_MESSAGE,
  KIND_STREAM_MESSAGE_V2,
  KIND_STREAM_MESSAGE_DIFF,
  KIND_SYSTEM_MESSAGE,
  KIND_JOB_REQUEST,
  KIND_JOB_ACCEPTED,
  KIND_JOB_PROGRESS,
  KIND_JOB_RESULT,
  KIND_JOB_CANCEL,
  KIND_JOB_ERROR,
  KIND_HUDDLE_STARTED,
  KIND_HUDDLE_PARTICIPANT_JOINED,
  KIND_HUDDLE_PARTICIPANT_LEFT,
  KIND_HUDDLE_ENDED,
  BAP_TIMELINE_EVENT_KINDS,
  CHANNEL_EVENT_KINDS,
  CHANNEL_TIMELINE_CONTENT_KINDS,
  KIND_BAP_ANNOUNCEMENT,
  KIND_BAP_MANIFEST_CORE,
  KIND_BAP_REQUEST,
  KIND_BAP_DELEGATION,
  KIND_BAP_RESUME,
  isBapTimelineKind,
} from "./kinds.ts";

test("isConversationalUnreadKind_streamMessage_counts", () => {
  assert.equal(isConversationalUnreadKind(KIND_STREAM_MESSAGE), true);
});

test("isConversationalUnreadKind_streamMessageV2_counts", () => {
  // 40002 is a real message edit/v2 — must stay counted.
  assert.equal(isConversationalUnreadKind(KIND_STREAM_MESSAGE_V2), true);
});

test("isConversationalUnreadKind_streamMessageDiff_counts", () => {
  // 40008 is a real message diff — must stay counted.
  assert.equal(isConversationalUnreadKind(KIND_STREAM_MESSAGE_DIFF), true);
});

test("isConversationalUnreadKind_systemMessage_excluded", () => {
  // 40099 channel_created / member_joined rows must not inflate the pill.
  assert.equal(isConversationalUnreadKind(KIND_SYSTEM_MESSAGE), false);
});

test("isConversationalUnreadKind_allJobKinds_excluded", () => {
  for (const kind of [
    KIND_JOB_REQUEST,
    KIND_JOB_ACCEPTED,
    KIND_JOB_PROGRESS,
    KIND_JOB_RESULT,
    KIND_JOB_CANCEL,
    KIND_JOB_ERROR,
  ]) {
    assert.equal(isConversationalUnreadKind(kind), false, `kind ${kind}`);
  }
});

test("isConversationalUnreadKind_huddleLifecycle_excluded", () => {
  for (const kind of [
    KIND_HUDDLE_STARTED,
    KIND_HUDDLE_PARTICIPANT_JOINED,
    KIND_HUDDLE_PARTICIPANT_LEFT,
    KIND_HUDDLE_ENDED,
  ]) {
    assert.equal(isConversationalUnreadKind(kind), false, `kind ${kind}`);
  }
});

test("isConversationalUnreadKind_undefinedKind_countsAsConversational", () => {
  // Optimistic/pending rows whose kind has not populated must not be dropped.
  assert.equal(isConversationalUnreadKind(undefined), true);
});

test("isConversationalUnreadKind_unknownKind_countsAsConversational", () => {
  // An exclude-list, not an include-list: anything not explicitly excluded
  // (e.g. a future conversational kind) is kept.
  assert.equal(isConversationalUnreadKind(12345), true);
});

test("bapKinds_registeredAsTimelineContent_andNonConversational", () => {
  // Every channel-postable BAP kind: live subscription, history fetch, own
  // row, and excluded from unread pills. Mirror of the bap-core registry.
  assert.deepEqual(
    [...BAP_TIMELINE_EVENT_KINDS],
    [
      4550, 4551, 4552, 4553, 4564, 4565, 4566, 4567, 4568, 4569, 4570, 4571,
      4572,
    ],
  );
  for (const kind of BAP_TIMELINE_EVENT_KINDS) {
    assert.ok(CHANNEL_EVENT_KINDS.includes(kind), `live ${kind}`);
    assert.ok(CHANNEL_TIMELINE_CONTENT_KINDS.includes(kind), `history ${kind}`);
    assert.equal(isBapTimelineKind(kind), true, `card ${kind}`);
    assert.equal(isConversationalUnreadKind(kind), false, `unread ${kind}`);
  }
  assert.equal(KIND_BAP_REQUEST, 4550);
  assert.equal(KIND_BAP_DELEGATION, 4551);
  assert.equal(KIND_BAP_RESUME, 4571);
});

test("bapAnnouncement_isAddressable_notTimelineContent", () => {
  assert.equal(KIND_BAP_ANNOUNCEMENT, 34560);
  assert.equal(isBapTimelineKind(KIND_BAP_ANNOUNCEMENT), false);
  assert.equal(CHANNEL_TIMELINE_CONTENT_KINDS.includes(34560), false);
  assert.equal(isBapTimelineKind(undefined), false);
});

test("BAP manifest core is addressable, never a timeline card", () => {
  assert.equal(KIND_BAP_MANIFEST_CORE, 30550);
  assert.equal(isBapTimelineKind(KIND_BAP_MANIFEST_CORE), false);
  assert.ok(!BAP_TIMELINE_EVENT_KINDS.includes(KIND_BAP_MANIFEST_CORE));
  assert.ok(!CHANNEL_TIMELINE_CONTENT_KINDS.includes(KIND_BAP_MANIFEST_CORE));
});
