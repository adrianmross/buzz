import { useQuery, useQueryClient } from "@tanstack/react-query";
import * as React from "react";
import { toast } from "sonner";

import {
  approverFor,
  completeBapApproval,
} from "@/features/bap/lib/approveFlow";
import {
  type BapRequest,
  parseProofDeepLinkPayload,
  selectPendingRequests,
} from "@/features/bap/lib/bapApproval";
import { relayClient } from "@/shared/api/relayClient";
import type { FeedItem } from "@/shared/api/types";
import {
  KIND_BAP_DELEGATION,
  KIND_BAP_REQUEST,
} from "@/shared/constants/kinds";
import { listenForBapProofDeepLinks } from "@/shared/deep-link";

/**
 * Query key under the `home-feed` prefix on purpose: the live home-feed
 * signal (`useLiveHomeFeedActions`, which also watches kind 4550) refetches
 * that prefix, so a request arriving live refreshes this list too.
 */
export const bapPendingRequestsQueryKey = (pubkey: string) =>
  ["home-feed", "bap-pending", pubkey] as const;

const EMPTY: BapRequest[] = [];

/** Pending kind-4550 requests addressed to me with no kind-4551 answer. */
export function useBapPendingRequests(pubkey: string | undefined) {
  const normalized = pubkey?.trim().toLowerCase() ?? "";
  const query = useQuery({
    queryKey: bapPendingRequestsQueryKey(normalized),
    enabled: normalized.length > 0,
    staleTime: 30_000,
    queryFn: async () => {
      const me = approverFor(normalized);
      const [requests, grants] = await Promise.all([
        relayClient.fetchEvents({
          kinds: [KIND_BAP_REQUEST],
          "#p": [normalized],
          limit: 100,
        }),
        // Grants I issued; matched to requests by their `req` tag client-side
        // (multi-letter tags are not relay-indexed).
        relayClient.fetchEvents({
          kinds: [KIND_BAP_DELEGATION],
          authors: [normalized],
          limit: 200,
        }),
      ]);
      return selectPendingRequests(
        requests,
        grants,
        me,
        Math.floor(Date.now() / 1000),
      );
    },
  });
  return query.data ?? EMPTY;
}

export function bapPendingFeedItems(
  requests: readonly BapRequest[],
): FeedItem[] {
  return requests.map((req) => ({
    id: req.eventId,
    kind: KIND_BAP_REQUEST,
    pubkey: req.pubkey,
    content: `\`${req.request.command}\` on \`${req.request.resource}\``,
    createdAt: req.createdAt,
    channelId: req.channelId,
    channelName: "",
    tags: [],
    category: "needs_action",
  }));
}

/**
 * Finish approvals handed back by the wallet page via `buzz://bap/proof#…`.
 * Mounted once in the app shell next to the other deep-link hooks.
 */
export function useBapProofDeepLinks(enabled = true) {
  const queryClient = useQueryClient();
  const onProof = React.useEffectEvent(async (fragment: string) => {
    const payload = parseProofDeepLinkPayload(fragment);
    if (!payload) {
      toast.error("Ignored a malformed BAP proof link.");
      return true; // ack-and-drop, or the bad head wedges the queue
    }
    try {
      await completeBapApproval(payload);
      toast.success("Approval granted and published.");
    } catch (error) {
      toast.error(
        `Could not publish the grant: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
    void queryClient.invalidateQueries({ queryKey: ["home-feed"] });
    return true;
  });

  React.useEffect(() => {
    if (!enabled) return;
    let cancelled = false;
    const unlistenPromise = listenForBapProofDeepLinks((fragment) =>
      cancelled ? false : onProof(fragment),
    );
    return () => {
      cancelled = true;
      void unlistenPromise.then((unlisten) => unlisten());
    };
  }, [enabled]);
}
