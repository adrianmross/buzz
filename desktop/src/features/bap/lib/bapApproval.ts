import {
  KIND_BAP_DELEGATION,
  KIND_BAP_REQUEST,
} from "@/shared/constants/kinds";
import { getChannelIdFromTags } from "@/features/messages/lib/threading";
import {
  type BapRequestApproval,
  parseBapRequestApproval,
} from "@/features/bap/lib/bapCard";

/**
 * Pure helpers for the approve flow — everything that does not need a key or
 * a socket. Mirrors `approveRequest()` in the bap repo's
 * apps/bap-wallet/src/cli.ts: the desktop only differs in where the
 * signature comes from (Rust identity key) and where the proof comes from
 * (the hosted RP page, via a `buzz://bap/proof` deep link).
 */

export type BapRequestEvent = {
  id: string;
  kind: number;
  pubkey: string;
  created_at: number;
  tags: string[][];
  content: string;
};

export type BapRequest = {
  eventId: string;
  channelId: string | null;
  pubkey: string;
  createdAt: number;
  /** `p` tag: the approver's Nostr pubkey (hex). */
  approverPubkey: string | null;
  request: BapRequestApproval;
};

/**
 * The approver as the request may name it: hex pubkey, did:nostr, the
 * identity did:key, or (M18) the passkey's did:key when one is enrolled.
 */
export type BapApprover = {
  pubkey: string;
  didKey: string;
  approverDid?: string;
};

export type DraftCommitment = {
  dbap_version: "1.0";
  grant_type: "ucan-delegation";
  issuer_did: string;
  audience_did: string;
  command: string;
  resource: string;
  policy: unknown[];
  not_before: number;
  expires: number;
  request_ref: string;
};

/** `DraftCommitment` plus the RP-minted `nonce` (an `ApprovalCommitment`). */
export type ProofCommitment = DraftCommitment & { nonce: string };

/** What the wallet page hands back: the verified proof and the RP verdict. */
export type BapProofPayload = {
  proof: {
    type: "DeviceBoundApprovalProof";
    dbap_version: "1.0";
    commitment: ProofCommitment;
    webauthn: Record<string, unknown>;
    credential_binding: Record<string, unknown>;
  };
  verify: { ok: true; commitment_hash: string };
};

export function parseBapRequestEvent(
  event: BapRequestEvent,
): BapRequest | null {
  if (event.kind !== KIND_BAP_REQUEST) return null;
  const request = parseBapRequestApproval(event.content);
  if (!request) return null;
  const p = event.tags.find((tag) => tag[0] === "p")?.[1];
  return {
    eventId: event.id,
    channelId: getChannelIdFromTags(event.tags),
    pubkey: event.pubkey,
    createdAt: event.created_at,
    approverPubkey: typeof p === "string" ? p.toLowerCase() : null,
    request,
  };
}

export function isRequestAddressedTo(
  req: BapRequest,
  me: BapApprover,
): boolean {
  const pubkey = me.pubkey.toLowerCase();
  return (
    req.approverPubkey === pubkey ||
    req.request.to.includes(`did:nostr:${pubkey}`) ||
    req.request.to.includes(me.didKey) ||
    (me.approverDid !== undefined && req.request.to.includes(me.approverDid))
  );
}

export const isRequestExpired = (req: BapRequest, now: number) =>
  req.request.expiresTime <= now;

/** Request event ids answered by a kind-4551 (`req` tag), per bap-core events.ts. */
export function answeredRequestIds(
  grants: readonly { kind: number; tags: string[][] }[],
): Set<string> {
  const ids = new Set<string>();
  for (const grant of grants) {
    if (grant.kind !== KIND_BAP_DELEGATION) continue;
    for (const tag of grant.tags) {
      if (tag[0] === "req" && typeof tag[1] === "string") ids.add(tag[1]);
    }
  }
  return ids;
}

/** Requests addressed to `me`, unanswered, unexpired — newest first. */
export function selectPendingRequests(
  requests: readonly BapRequestEvent[],
  grants: readonly { kind: number; tags: string[][] }[],
  me: BapApprover,
  now: number,
): BapRequest[] {
  const answered = answeredRequestIds(grants);
  return requests
    .map(parseBapRequestEvent)
    .filter(
      (req): req is BapRequest =>
        req !== null &&
        !answered.has(req.eventId) &&
        isRequestAddressedTo(req, me) &&
        !isRequestExpired(req, now),
    )
    .sort((a, b) => b.createdAt - a.createdAt);
}

/**
 * The commitment the RP turns into a challenge — exactly `approveRequest()`:
 * ttl never above the request's, policy = requested + the action digest.
 */
export function buildDraftCommitment(
  req: BapRequest,
  issuerDid: string,
  now: number,
  ttl?: number,
): DraftCommitment {
  const r = req.request;
  const granted = Math.min(ttl ?? r.requestedTtl, r.requestedTtl);
  return {
    dbap_version: "1.0",
    grant_type: "ucan-delegation",
    issuer_did: issuerDid,
    audience_did: r.from,
    command: r.command,
    resource: r.resource,
    policy: [...r.requestedPolicy, ["==", ".action_digest", r.actionDigest]],
    not_before: now,
    expires: now + granted,
    request_ref: r.id,
  };
}

const b64url = (bytes: Uint8Array) =>
  btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");

export function encodeFragmentJson(value: unknown): string {
  return b64url(new TextEncoder().encode(JSON.stringify(value)));
}

export function decodeFragmentJson(fragment: string): unknown {
  const padded = fragment.replace(/-/g, "+").replace(/_/g, "/");
  try {
    const bytes = Uint8Array.from(atob(padded), (c) => c.charCodeAt(0));
    return JSON.parse(new TextDecoder().decode(bytes)) as unknown;
  } catch {
    return null;
  }
}

/** `https://<rp>/#req=<base64url(JSON draft)>` — fragment, never query. */
export function buildRpApproveUrl(rpBase: string, draft: DraftCommitment) {
  return `${rpBase.replace(/\/+$/, "")}/#req=${encodeFragmentJson(draft)}`;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Parse the `buzz://bap/proof#<payload>` fragment. Shape only; no crypto. */
export function parseProofDeepLinkPayload(
  fragment: string,
): BapProofPayload | null {
  const v = decodeFragmentJson(fragment);
  if (!isRecord(v) || !isRecord(v.proof) || !isRecord(v.verify)) return null;
  const p = v.proof;
  const c = p.commitment;
  if (
    p.type !== "DeviceBoundApprovalProof" ||
    p.dbap_version !== "1.0" ||
    !isRecord(c) ||
    !isRecord(p.webauthn) ||
    !isRecord(p.credential_binding) ||
    v.verify.ok !== true ||
    typeof v.verify.commitment_hash !== "string"
  ) {
    return null;
  }
  for (const key of [
    "issuer_did",
    "audience_did",
    "command",
    "resource",
    "request_ref",
    "nonce",
  ]) {
    if (typeof c[key] !== "string" || !c[key]) return null;
  }
  if (
    typeof c.not_before !== "number" ||
    typeof c.expires !== "number" ||
    !Array.isArray(c.policy)
  ) {
    return null;
  }
  return v as unknown as BapProofPayload;
}

export type DelegationPayloadLike = {
  iss: string;
  aud: string;
  sub: string;
  cmd: string;
  res: string[];
  pol: unknown[];
  nonce: string;
  nbf: number;
  exp: number;
  flags: { binding: "action"; subdelegation: false };
};

/** The grant UCAN payload `approveRequest()` builds, from the verified commitment. */
export function delegationPayloadFromCommitment(
  c: ProofCommitment,
  chainRoot: string,
): DelegationPayloadLike {
  return {
    iss: c.issuer_did,
    aud: c.audience_did,
    sub: chainRoot,
    cmd: c.command,
    res: [c.resource],
    pol: c.policy,
    nonce: `grant-${c.request_ref}`,
    nbf: c.not_before,
    exp: c.expires,
    flags: { binding: "action", subdelegation: false },
  };
}

/** Kind-4551 index tags (bap-core `buildDelegationEvent`) plus the channel `h`. */
export function buildDelegationEventTags(
  payload: DelegationPayloadLike,
  opts: {
    audiencePubkey: string | undefined;
    requestEventId: string;
    channelId: string | null;
  },
): string[][] {
  const tags: string[][] = [];
  if (opts.channelId) tags.push(["h", opts.channelId]);
  if (opts.audiencePubkey) tags.push(["p", opts.audiencePubkey]);
  tags.push(["aud", payload.aud], ["cmd", payload.cmd]);
  for (const r of payload.res) tags.push(["res", r]);
  tags.push(["expiration", String(payload.exp)], ["req", opts.requestEventId]);
  return tags;
}
