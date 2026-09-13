import { relayClient } from "@/shared/api/relayClient";
import { invokeTauri } from "@/shared/api/tauri";
import type { RelayEvent } from "@/shared/api/types";
import {
  KIND_BAP_ANNOUNCEMENT,
  KIND_BAP_MANIFEST_CORE,
} from "@/shared/constants/kinds";
import { relyingPartyInfoUrl } from "./lib/authority";

const MANIFEST_KINDS = [KIND_BAP_MANIFEST_CORE, KIND_BAP_ANNOUNCEMENT];

/** Pubkey hex of this machine's BAP identity, or null before creation. */
export function getMachineIdentity(): Promise<string | null> {
  return invokeTauri<string | null>("bap_machine_identity_get");
}

/** Create (or return the existing) machine identity; the secret stays in Rust. */
export function createMachineIdentity(): Promise<string> {
  return invokeTauri<string>("bap_machine_identity_create");
}

export type RelyingPartyInfo = {
  rp_id: string;
  origin: string;
  dbap?: unknown;
  /** The one binding older RPs advertise; `enrollments` lists every one verified (M18). */
  enrollment?: unknown;
  enrollments?: unknown;
};

/** `GET <rp>/rp` — throws with the HTTP status or network error message. */
export async function fetchRelyingPartyInfo(
  relyingPartyUrl: string,
): Promise<RelyingPartyInfo> {
  const response = await fetch(relyingPartyInfoUrl(relyingPartyUrl), {
    headers: { accept: "application/json" },
  });
  if (!response.ok) {
    throw new Error(`HTTP ${response.status} ${response.statusText}`.trim());
  }
  return (await response.json()) as RelyingPartyInfo;
}

/**
 * Kind-30550 manifest cores and kind-34560 announcements signed by `me` or
 * listing `me` as a `p` approver.
 * Owner/agent DID tags are not relay-indexed, so `announcementRowsFor` does
 * the final DID match client-side.
 */
export async function fetchAnnouncementsFor(me: string): Promise<RelayEvent[]> {
  const [signed, approver] = await Promise.all([
    relayClient.fetchEvents({
      kinds: MANIFEST_KINDS,
      authors: [me],
      limit: 200,
    }),
    relayClient.fetchEvents({
      kinds: MANIFEST_KINDS,
      "#p": [me],
      limit: 200,
    }),
  ]);
  return [...signed, ...approver];
}
