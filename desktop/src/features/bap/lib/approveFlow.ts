import { openUrl } from "@tauri-apps/plugin-opener";
import {
  grantWithinCommitment,
  validateCommitment,
} from "@bap/core/src/dbap.ts";
import { didKeyFromNostrPubkey, partyPubkey } from "@bap/core/src/did.ts";
import type { PolicyAtom } from "@bap/core/src/policy.ts";

import {
  type BapApprover,
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
  enrollmentSigns,
  loadNativeEnrollment,
  nativeAuthenticatorReady,
  runNativeCeremony,
} from "@/features/bap/lib/nativeAuthenticator";
import { assembleUcan, finishUcan } from "@/features/bap/lib/ucan";
import { readAuthoritySettings } from "@/features/authority/lib/authority";
import { relayClient } from "@/shared/api/relayClient";
import { signDigest, signRelayEvent } from "@/shared/api/tauri";
import type { RelayEvent } from "@/shared/api/types";
import { KIND_BAP_DELEGATION } from "@/shared/constants/kinds";

/**
 * The approve flow. With a Touch ID enrolment on this Mac the whole ceremony
 * runs in-app; otherwise it is split by the browser round trip:
 *
 *   startBapApproval   draft commitment (issuer = passkey did:key when the
 *                      enrolment carries a sign key, else the identity did:key) →
 *     native           /challenge → Secure Enclave assertion (Touch ID) →
 *     (sign-extension) passkey signs the UCAN digest (Touch ID) → /verify {proof, ucan}
 *                      → completeBapApproval publishes the passkey-signed grant
 *     native (legacy)  /challenge → assertion → /verify → completeBapApproval
 *                      signs the grant with the identity key (pre-M18 enrolment)
 *     browser          hosted RP wallet page (system browser) →
 *     (page)           /challenge → passkey assertion → /verify → buzz://bap/proof#…
 *   completeBapApproval proof → grantWithinCommitment → UCAN → kind 4551 into
 *                      the request's channel. The event's Nostr publisher is the
 *                      desktop identity; a P-256 `iss` rides on it as a carrier
 *                      key (NIP-XD §Kind 4551).
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
  | { mode: "native"; legacyEnrollment: boolean }
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

/** Me as an approver: identity key, plus the enrolled passkey DID when it signs. */
export function approverFor(pubkey: string): BapApprover {
  const normalized = pubkey.toLowerCase();
  const didKey = didKeyFromNostrPubkey(normalized);
  const enrollment = loadNativeEnrollment(didKey);
  return {
    pubkey: normalized,
    didKey,
    approverDid:
      enrollment && enrollmentSigns(enrollment)
        ? enrollment.issuer_did
        : undefined,
  };
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
  // The UCAN `iss` must be a did:key (bap-core validatePayload): the passkey's
  // P-256 did:key when this Mac's enrolment signs (M18), else the identity
  // did:key — the DID a pre-M18 enrolment or the wallet page is bound to.
  const enrollment = loadNativeEnrollment(me.didKey);
  const native =
    enrollment !== null && (await nativeAuthenticatorReady(enrollment));
  const issuerDid =
    native && enrollmentSigns(enrollment) ? enrollment.issuer_did : me.didKey;
  const draft = buildDraftCommitment(req, issuerDid, now);
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
  if (native) {
    const { payload, token } = await runNativeCeremony(
      rp,
      draft,
      enrollment,
      req.request.chainRoot,
    );
    await completeBapApproval(payload, token);
    return { mode: "native", legacyEnrollment: !enrollmentSigns(enrollment) };
  }
  const url = buildRpApproveUrl(rp, draft);
  await openUrl(url);
  return { mode: "browser", url };
}

/** `h.p.s` → `[h.p, s]`. */
function splitToken(token: string): [string, string] {
  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("grant token is not h.p.s");
  return [`${parts[0]}.${parts[1]}`, parts[2]];
}

/**
 * Finish an approval from the verified proof: publish the grant as kind 4551.
 * `token` is the passkey-signed UCAN of a sign-extension ceremony (re-verified
 * here); without it the grant is signed with the identity key (`sign_digest`).
 */
export async function completeBapApproval(
  payload: BapProofPayload,
  token?: string,
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
  const { token: content, payload: grant } = token
    ? finishUcan(...splitToken(token))
    : await assembleUcan(draft, signDigest);
  // A passkey-signed token arrives already signed: hold it to the same bar.
  grantWithinCommitment(grant, commitment);
  if (grant.nonce !== draft.nonce || grant.sub !== draft.sub) {
    throw new Error("grant token does not belong to this approval");
  }
  const event = await signRelayEvent({
    kind: KIND_BAP_DELEGATION,
    content,
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
