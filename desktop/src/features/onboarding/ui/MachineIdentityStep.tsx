import { Copy } from "lucide-react";
import * as React from "react";

import {
  createMachineIdentity,
  getMachineIdentity,
} from "@/features/authority/api";
import { didNostrFromPubkey } from "@/features/authority/lib/authority";
import { copyTextToClipboard } from "@/shared/lib/clipboard";
import { Button } from "@/shared/ui/button";
import { Card } from "@/shared/ui/card";
import {
  ONBOARDING_PRIMARY_CTA_CLASS,
  ONBOARDING_SECONDARY_CTA_CLASS,
} from "./OnboardingChrome";
import { OnboardingFooter } from "./OnboardingFooter";
import {
  type OnboardingTransitionDirection,
  OnboardingSlideTransition,
} from "./OnboardingSlideTransition";

/**
 * Optional onboarding step: create this machine's BAP identity (a second,
 * machine-scoped keypair kept in the OS keyring). Skippable — the same action
 * lives in Settings → Authority.
 */
export function MachineIdentityStep({
  direction,
  onNext,
}: {
  direction: OnboardingTransitionDirection;
  onNext: () => void;
}) {
  const [pubkey, setPubkey] = React.useState<string | null | undefined>();
  const [error, setError] = React.useState<string | null>(null);
  const [isCreating, setIsCreating] = React.useState(false);

  React.useEffect(() => {
    let cancelled = false;
    getMachineIdentity()
      .then((value) => {
        if (!cancelled) setPubkey(value);
      })
      .catch(() => {
        if (!cancelled) setPubkey(null);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const create = async () => {
    setIsCreating(true);
    setError(null);
    try {
      setPubkey(await createMachineIdentity());
    } catch (cause) {
      setError(
        cause instanceof Error
          ? cause.message
          : "Failed to create the machine identity",
      );
    } finally {
      setIsCreating(false);
    }
  };

  const did = didNostrFromPubkey(pubkey ?? undefined);

  return (
    <OnboardingSlideTransition
      className="flex min-h-[calc(100dvh-13.25rem)] w-full max-w-[837px] flex-col items-center text-center"
      direction={direction}
      transitionKey={`machine-identity-${direction}`}
    >
      <h1 className="text-title font-normal text-foreground">
        This machine's identity
      </h1>
      <p className="mt-5 max-w-[440px] text-sm leading-6 text-foreground/80">
        Agents running here act under a machine-scoped key that stays in this
        computer's keyring. You can create it now or later in Settings →
        Authority.
      </p>
      <div className="flex w-full flex-1 flex-col justify-center py-10">
        {did ? (
          <Card className="px-8 py-6" variant="textured">
            <div className="mx-auto flex w-full min-w-0 max-w-[832px] items-center gap-4">
              <code
                className="min-w-0 flex-1 select-text break-all text-left font-mono text-sm text-foreground"
                data-testid="machine-identity-did"
              >
                {did}
              </code>
              <Button
                aria-label="Copy machine DID"
                className="h-10 w-10 shrink-0 text-muted-foreground hover:text-foreground"
                onClick={() => copyTextToClipboard(did, "Machine DID copied")}
                size="icon"
                type="button"
                variant="ghost"
              >
                <Copy aria-hidden="true" className="h-6 w-6" />
              </Button>
            </div>
          </Card>
        ) : error ? (
          <p
            className="text-sm text-destructive"
            data-testid="machine-identity-error"
          >
            {error}
          </p>
        ) : null}
      </div>
      <OnboardingFooter>
        {did ? (
          <Button
            className={ONBOARDING_PRIMARY_CTA_CLASS}
            data-testid="onboarding-next"
            onClick={onNext}
            type="button"
          >
            Next
          </Button>
        ) : (
          <>
            <Button
              className={ONBOARDING_PRIMARY_CTA_CLASS}
              data-testid="machine-identity-create"
              disabled={pubkey === undefined || isCreating}
              onClick={() => void create()}
              type="button"
            >
              {isCreating ? "Creating…" : "Create machine identity"}
            </Button>
            <Button
              className={`${ONBOARDING_SECONDARY_CTA_CLASS} px-5`}
              data-testid="machine-identity-skip"
              disabled={isCreating}
              onClick={onNext}
              type="button"
              variant="ghost"
            >
              Skip for now
            </Button>
          </>
        )}
      </OnboardingFooter>
    </OnboardingSlideTransition>
  );
}
