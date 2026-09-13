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
import {
  loadNativeEnrollment,
  nativeAuthenticatorReady,
  runNativeCeremony,
} from "@/features/bap/lib/nativeAuthenticator";
import { assembleUcan } from "@/features/bap/lib/ucan";
import { readAuthoritySettings } from "@/features/authority/lib/authority";
import { relayClient } from "@/shared/api/relayClient";
import { signDigest, signRelayEvent } from "@/shared/api/tauri";
import type { RelayEvent } from "@/shared/api/types";
import { KIND_BAP_DELEGATION } from "@/shared/constants/kinds";

/**
 * The approve flow. With a Touch ID enrolment on this Mac the whole ceremony
 * runs in-app; otherwise it is split by the browser round trip:
 *
 *   startBapApproval   draft commitment →
 *     native           /challenge → Secure Enclave assertion (Touch ID) → /verify
 *                      → completeBapApproval, no browser
 *     browser          hosted RP wallet page (system browser) →
 *     (page)           /challenge → passkey assertion → /verify → buzz://bap/proof#…
 *   completeBapApproval proof → grantWithinCommitment → UCAN (Rust-signed digest)
 *                      → kind 4551 into the request's channel
 *
 * Same algorithm as `approveRequest()` in the bap repo's wallet CLI.
 */

/** Relying party: `VITE_BAP_RP_URL` for dev builds, else the Authority setting. */
export function bapRpUrl(): string {
  return (
    (import.meta.env?.VITE_BAP_RP_URL as string | undefined) ??
    readAuthoritySettings().relyingPartyUrl
  );
}

export type BapApprovalStart =
  | { mode: "native" }
  | { mode: "browser"; url: string };

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

/**
 * Build the draft commitment, then either finish natively (Touch ID) or open
 * the wallet page. A native ceremony that fails (cancelled Touch ID, RP
 * refusal) throws rather than silently falling back to the browser.
 */
export async function startBapApproval(
  req: BapRequest,
  myPubkey: string,
  now = Math.floor(Date.now() / 1000),
): Promise<BapApprovalStart> {
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
  const rp = bapRpUrl();
  const enrollment = loadNativeEnrollment(me.didKey);
  if (enrollment && (await nativeAuthenticatorReady(enrollment))) {
    const payload = await runNativeCeremony(rp, draft, enrollment);
    await completeBapApproval(payload);
    return { mode: "native" };
  }
  const url = buildRpApproveUrl(rp, draft);
  await openUrl(url);
  return { mode: "browser", url };
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
