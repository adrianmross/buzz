import { openUrl } from "@tauri-apps/plugin-opener";
import {
  grantWithinCommitment,
  validateCommitment,
} from "@bap/core/src/dbap.ts";
import { didKeyFromNostrPubkey, partyPubkey } from "@bap/core/src/did.ts";
import type { PolicyAtom } from "@bap/core/src/policy.ts";

import {
  type BapProofPayload,
  type BapRequest,
  buildDelegationEventTags,
  buildDraftCommitment,
  buildRpApproveUrl,
  delegationPayloadFromCommitment,
  isRequestAddressedTo,
  isRequestExpired,
} from "@/features/bap/lib/bapApproval";
import { assembleUcan } from "@/features/bap/lib/ucan";
import { relayClient } from "@/shared/api/relayClient";
import { signDigest, signRelayEvent } from "@/shared/api/tauri";
import type { RelayEvent } from "@/shared/api/types";
import { KIND_BAP_DELEGATION } from "@/shared/constants/kinds";

/**
 * The approve flow, split by the browser round trip:
 *
 *   startBapApproval   draft commitment → hosted RP wallet page (system browser)
 *   (page)             /challenge → passkey assertion → /verify → buzz://bap/proof#…
 *   completeBapApproval proof → grantWithinCommitment → UCAN (Rust-signed digest)
 *                      → kind 4551 into the request's channel
 *
 * Same algorithm as `approveRequest()` in the bap repo's wallet CLI.
 */

/** Hosted relying party; `VITE_BAP_RP_URL` points a dev build at the dev RP. */
export const BAP_RP_URL: string =
  (import.meta.env?.VITE_BAP_RP_URL as string | undefined) ??
  "https://approve.red-wiz.stream";

type PendingApproval = {
  eventId: string;
  channelId: string | null;
  chainRoot: string;
  audiencePubkey: string | undefined;
};

// ponytail: in-memory only — an app restart between "Approve" and the proof
// deep link drops the pending entry; the user clicks Approve again. Persist
// (keyed by community) if that round trip turns out to span restarts.
const pendingApprovals = new Map<string, PendingApproval>();

/** Community-scoped singleton reset (see `resetCommunityState`). */
export function resetBapApprovalState(): void {
  pendingApprovals.clear();
}

export function approverFor(pubkey: string) {
  const normalized = pubkey.toLowerCase();
  return { pubkey: normalized, didKey: didKeyFromNostrPubkey(normalized) };
}

/** Build the draft commitment and open the wallet page. Returns the URL opened. */
export async function startBapApproval(
  req: BapRequest,
  myPubkey: string,
  now = Math.floor(Date.now() / 1000),
): Promise<string> {
  const me = approverFor(myPubkey);
  if (!isRequestAddressedTo(req, me)) {
    throw new Error("This request is addressed to a different approver.");
  }
  if (isRequestExpired(req, now)) {
    throw new Error("This request has expired; expiry is denial.");
  }
  // The UCAN `iss` must be a did:key (bap-core validatePayload), so the
  // commitment issuer is the did:key of the identity pubkey — the DID the
  // wallet page's passkey enrollment is bound to.
  const draft = buildDraftCommitment(req, me.didKey, now);
  let audiencePubkey: string | undefined;
  try {
    audiencePubkey = partyPubkey(draft.audience_did);
  } catch {
    audiencePubkey = undefined;
  }
  pendingApprovals.set(draft.request_ref, {
    eventId: req.eventId,
    channelId: req.channelId,
    chainRoot: req.request.chainRoot,
    audiencePubkey,
  });
  const url = buildRpApproveUrl(BAP_RP_URL, draft);
  await openUrl(url);
  return url;
}

/** Finish an approval from the verified proof: sign the grant, publish 4551. */
export async function completeBapApproval(
  payload: BapProofPayload,
): Promise<RelayEvent> {
  const commitment = validateCommitment(payload.proof.commitment);
  const pending = pendingApprovals.get(commitment.request_ref);
  if (!pending) {
    throw new Error(
      `No pending approval for request ${commitment.request_ref}; open the request card and approve again.`,
    );
  }
  const draft = delegationPayloadFromCommitment(
    commitment as unknown as BapProofPayload["proof"]["commitment"],
    pending.chainRoot,
  );
  // DBAP §Verification step 5, before anything is signed.
  grantWithinCommitment(
    { ...draft, pol: draft.pol as PolicyAtom[] },
    commitment,
  );
  const { token } = await assembleUcan(draft, signDigest);
  const event = await signRelayEvent({
    kind: KIND_BAP_DELEGATION,
    content: token,
    tags: buildDelegationEventTags(draft, {
      audiencePubkey: pending.audiencePubkey,
      requestEventId: pending.eventId,
      channelId: pending.channelId,
    }),
  });
  await relayClient.publishEvent(
    event,
    "Timed out publishing the grant.",
    "Failed to publish the grant.",
  );
  pendingApprovals.delete(commitment.request_ref);
  return event;
}
