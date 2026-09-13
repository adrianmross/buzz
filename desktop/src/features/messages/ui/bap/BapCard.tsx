import { useQueryClient } from "@tanstack/react-query";
import { ShieldCheck } from "lucide-react";
import * as React from "react";
import { toast } from "sonner";

import { useBapPendingRequests } from "@/features/bap/hooks";
import { startBapApproval } from "@/features/bap/lib/approveFlow";
import { parseBapRequestEvent } from "@/features/bap/lib/bapApproval";
import {
  type BapCard as BapCardModel,
  eventToBapCard,
} from "@/features/bap/lib/bapCard";
import type { TimelineMessage } from "@/features/messages/types";
import { useIdentityQuery } from "@/shared/api/hooks";
import { KIND_BAP_REQUEST } from "@/shared/constants/kinds";
import { cn } from "@/shared/lib/cn";
import { Button } from "@/shared/ui/button";

type BapCardProps = {
  channelId: string | null;
  className?: string;
  message: TimelineMessage;
};

/**
 * Audit card for a BAP event row: machine-verifiable fields first, free text
 * (justification, notes) visually subordinate. A kind-4550 request addressed
 * to the viewer carries the Approve button that starts the DBAP ceremony in
 * the system browser.
 */
export function BapCard({ channelId, className, message }: BapCardProps) {
  const card = React.useMemo(
    () =>
      eventToBapCard({
        kind: message.kind ?? 0,
        tags: message.tags ?? [],
        content: message.body,
      }),
    [message.kind, message.tags, message.body],
  );
  if (!card) return null;
  return (
    <div
      className={cn(
        "mt-1 max-w-2xl rounded-lg border border-border/60 bg-muted/20 px-3 py-2",
        className,
      )}
      data-testid={`bap-card-${card.kind}`}
    >
      <div className="flex items-center gap-1.5 text-sm font-semibold">
        <ShieldCheck
          aria-hidden="true"
          className="size-4 text-muted-foreground"
        />
        <span>{card.title}</span>
        <span className="text-2xs font-normal text-muted-foreground">
          kind {card.kind}
        </span>
      </div>
      <BapFields card={card} />
      {card.kind === KIND_BAP_REQUEST ? (
        <ApproveAction channelId={channelId} message={message} />
      ) : null}
    </div>
  );
}

function BapFields({ card }: { card: BapCardModel }) {
  return (
    <dl className="mt-1 grid grid-cols-[auto_1fr] gap-x-3 gap-y-0.5 text-xs">
      {card.fields.map((f) => (
        <React.Fragment key={f.label}>
          <dt className="text-muted-foreground">{f.label}</dt>
          <dd
            className={cn(
              "min-w-0 whitespace-pre-wrap break-all",
              f.untrusted
                ? "border-l-2 border-border/60 pl-2 italic text-muted-foreground"
                : "font-mono",
            )}
          >
            {f.value}
          </dd>
        </React.Fragment>
      ))}
    </dl>
  );
}

function ApproveAction({
  channelId,
  message,
}: {
  channelId: string | null;
  message: TimelineMessage;
}) {
  const identity = useIdentityQuery().data;
  const pending = useBapPendingRequests(identity?.pubkey);
  const queryClient = useQueryClient();
  const [busy, setBusy] = React.useState(false);
  const isPending = pending.some((req) => req.eventId === message.id);
  if (!isPending || !identity) return null;

  const onApprove = async () => {
    const event = {
      id: message.id,
      kind: message.kind ?? 0,
      pubkey: message.signerPubkey ?? message.pubkey ?? "",
      created_at: message.createdAt,
      tags: message.tags ?? [],
      content: message.body,
    };
    const req = parseBapRequestEvent(event);
    if (!req) return;
    setBusy(true);
    try {
      const started = await startBapApproval(
        { ...req, channelId: req.channelId ?? channelId },
        identity.pubkey,
      );
      if (started.mode === "native") {
        toast.success("Approval granted and published.");
        void queryClient.invalidateQueries({ queryKey: ["home-feed"] });
      } else {
        toast.info(
          "Approve with your passkey in the browser; the grant is published here when it returns.",
        );
      }
    } catch (error) {
      toast.error(error instanceof Error ? error.message : String(error));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="mt-2">
      <Button
        aria-label="Approve this request with a passkey"
        data-testid="bap-approve"
        disabled={busy}
        onClick={() => void onApprove()}
        size="sm"
        type="button"
      >
        Approve
      </Button>
    </div>
  );
}
