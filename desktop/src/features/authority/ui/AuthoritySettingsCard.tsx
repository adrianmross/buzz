import { useQuery } from "@tanstack/react-query";
import { Copy, LoaderCircle, RefreshCw } from "lucide-react";
import * as React from "react";
import { toast } from "sonner";

import { SettingsOptionGroup } from "@/features/settings/ui/SettingsOptionGroup";
import { SettingsSectionHeader } from "@/features/settings/ui/SettingsSectionHeader";
import { copyTextToClipboard } from "@/shared/lib/clipboard";
import { Button } from "@/shared/ui/button";
import { Input } from "@/shared/ui/input";
import {
  createMachineIdentity,
  fetchAnnouncementsFor,
  fetchRelyingPartyInfo,
  getMachineIdentity,
  type RelyingPartyInfo,
} from "../api";
import {
  type AnnouncementRow,
  announcementRowsFor,
  didNostrFromPubkey,
  readAuthoritySettings,
  writeAuthoritySettings,
} from "../lib/authority";

const ROW_CLASS = "flex flex-col gap-2 px-4 py-3 text-sm";
const DID_CLASS =
  "min-w-0 flex-1 select-text break-all font-mono text-xs text-muted-foreground";

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function DidRow({
  did,
  label,
  testId,
}: {
  did: string;
  label: string;
  testId: string;
}) {
  return (
    <div className={ROW_CLASS}>
      <span className="font-medium">{label}</span>
      <div className="flex items-center gap-2">
        <code className={DID_CLASS} data-testid={testId}>
          {did}
        </code>
        <Button
          aria-label={`Copy ${label}`}
          onClick={() => copyTextToClipboard(did, `${label} copied`)}
          size="icon-xs"
          type="button"
          variant="ghost"
        >
          <Copy aria-hidden="true" />
        </Button>
      </div>
    </div>
  );
}

function MachineIdentityRow() {
  const [pubkey, setPubkey] = React.useState<string | null | undefined>();
  const [error, setError] = React.useState<string | null>(null);
  const [isCreating, setIsCreating] = React.useState(false);

  React.useEffect(() => {
    let cancelled = false;
    getMachineIdentity()
      .then((value) => {
        if (!cancelled) setPubkey(value);
      })
      .catch((cause) => {
        if (!cancelled) {
          setPubkey(null);
          setError(errorMessage(cause));
        }
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
      setError(errorMessage(cause));
    } finally {
      setIsCreating(false);
    }
  };

  const did = didNostrFromPubkey(pubkey ?? undefined);
  if (did) {
    return (
      <DidRow
        did={did}
        label="This machine's DID"
        testId="authority-machine-did"
      />
    );
  }
  return (
    <div className={ROW_CLASS}>
      <span className="font-medium">This machine's DID</span>
      <p className="text-muted-foreground">
        {pubkey === undefined
          ? "Checking…"
          : "Not created yet. The key is stored in the OS keyring and never leaves this machine."}
      </p>
      {error ? (
        <p className="text-destructive" data-testid="authority-machine-error">
          {error}
        </p>
      ) : null}
      <div>
        <Button
          data-testid="authority-machine-create"
          disabled={pubkey === undefined || isCreating}
          onClick={() => void create()}
          size="sm"
          type="button"
          variant="outline"
        >
          {isCreating ? "Creating…" : "Create machine identity"}
        </Button>
      </div>
    </div>
  );
}

function EndpointsGroup() {
  const [settings, setSettings] = React.useState(readAuthoritySettings);
  const [rpInfo, setRpInfo] = React.useState<RelyingPartyInfo | null>(null);
  const [rpError, setRpError] = React.useState<string | null>(null);
  const [isChecking, setIsChecking] = React.useState(false);

  const update = (patch: Partial<typeof settings>) => {
    const next = { ...settings, ...patch };
    setSettings(next);
    if (!writeAuthoritySettings(next)) {
      toast.error("Could not save authority settings");
    }
  };

  const check = async () => {
    setIsChecking(true);
    setRpError(null);
    setRpInfo(null);
    try {
      setRpInfo(await fetchRelyingPartyInfo(settings.relyingPartyUrl));
    } catch (cause) {
      setRpError(errorMessage(cause));
    } finally {
      setIsChecking(false);
    }
  };

  return (
    <SettingsOptionGroup
      description="Where approvals are requested and how the wallet is reached."
      title="Endpoints"
    >
      <div className={ROW_CLASS}>
        <label className="font-medium" htmlFor="authority-rp-url">
          Relying party URL
        </label>
        <div className="flex items-center gap-2">
          <Input
            data-testid="authority-rp-url"
            id="authority-rp-url"
            onChange={(event) =>
              update({ relyingPartyUrl: event.target.value })
            }
            spellCheck={false}
            value={settings.relyingPartyUrl}
          />
          <Button
            data-testid="authority-rp-check"
            disabled={isChecking || !settings.relyingPartyUrl.trim()}
            onClick={() => void check()}
            size="sm"
            type="button"
            variant="outline"
          >
            {isChecking ? "Checking…" : "Check"}
          </Button>
        </div>
        {rpInfo ? (
          <p
            className="break-all text-muted-foreground"
            data-testid="authority-rp-result"
          >
            rp_id: <code className="font-mono text-xs">{rpInfo.rp_id}</code>
            {" · "}enrollment:{" "}
            <code className="font-mono text-xs">
              {JSON.stringify(rpInfo.enrollment ?? null)}
            </code>
          </p>
        ) : null}
        {rpError ? (
          <p className="text-destructive" data-testid="authority-rp-error">
            {rpError}
          </p>
        ) : null}
      </div>
      <div className={ROW_CLASS}>
        <label className="font-medium" htmlFor="authority-mediator-url">
          Mediator invitation URL
        </label>
        <Input
          className="font-mono text-xs"
          data-testid="authority-mediator-url"
          id="authority-mediator-url"
          onChange={(event) =>
            update({ mediatorInvitationUrl: event.target.value })
          }
          spellCheck={false}
          value={settings.mediatorInvitationUrl}
        />
      </div>
    </SettingsOptionGroup>
  );
}

function formatUpdated(seconds: number): string {
  return new Date(seconds * 1000).toLocaleString();
}

function ManifestsGroup({ pubkey }: { pubkey: string }) {
  const query = useQuery<AnnouncementRow[]>({
    queryKey: ["bap-announcements", pubkey],
    queryFn: async () =>
      announcementRowsFor(await fetchAnnouncementsFor(pubkey), pubkey),
    staleTime: 60_000,
  });

  return (
    <SettingsOptionGroup
      description="Kind 30550 manifest cores and kind 34560 replica announcements on this community's relay where you are the owner or a listed approver. Untagged announcement shapes fall back to the d tag and a content summary."
      headerAction={
        <Button
          aria-label="Refresh manifests"
          disabled={query.isFetching}
          onClick={() => void query.refetch()}
          size="icon-xs"
          type="button"
          variant="ghost"
        >
          {query.isFetching ? (
            <LoaderCircle aria-hidden="true" className="animate-spin" />
          ) : (
            <RefreshCw aria-hidden="true" />
          )}
        </Button>
      }
      title="Manifests"
    >
      {query.isError ? (
        <p className="px-4 py-3 text-sm text-destructive">
          {errorMessage(query.error)}
        </p>
      ) : query.isPending ? (
        <p className="px-4 py-3 text-sm text-muted-foreground">Loading…</p>
      ) : query.data.length === 0 ? (
        <p
          className="px-4 py-3 text-sm text-muted-foreground"
          data-testid="authority-manifests-empty"
        >
          No announcements name your DID.
        </p>
      ) : (
        <ul data-testid="authority-manifests">
          {query.data.map((row) => (
            <li className={ROW_CLASS} key={row.id}>
              <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
                <span className="font-medium">{row.resource}</span>
                <span className="rounded-full bg-muted px-2 text-xs text-muted-foreground">
                  {row.kindLabel}
                </span>
                {row.revision !== null ? (
                  <span className="text-muted-foreground">
                    rev {row.revision}
                  </span>
                ) : null}
                <span className="text-xs text-muted-foreground">
                  {formatUpdated(row.updatedAt)}
                </span>
              </div>
              <code className={DID_CLASS}>{row.ownerDid}</code>
              {row.d !== row.resource ? (
                <span className="text-xs text-muted-foreground">
                  d: {row.d}
                </span>
              ) : null}
              {row.contentSummary ? (
                <span className="break-all text-xs text-muted-foreground">
                  {row.contentSummary}
                </span>
              ) : null}
            </li>
          ))}
        </ul>
      )}
    </SettingsOptionGroup>
  );
}

export function AuthoritySettingsCard({
  currentPubkey,
}: {
  currentPubkey?: string;
}) {
  const myDid = didNostrFromPubkey(currentPubkey);
  return (
    <section className="flex flex-col gap-12" data-testid="settings-authority">
      <SettingsSectionHeader
        description="Bounded Authority Protocol identities and endpoints for this machine."
        title="Authority"
      />
      <SettingsOptionGroup title="Identities">
        {myDid ? (
          <DidRow did={myDid} label="My DID" testId="authority-my-did" />
        ) : (
          <p className="px-4 py-3 text-sm text-muted-foreground">
            Sign in to see your DID.
          </p>
        )}
        <MachineIdentityRow />
      </SettingsOptionGroup>
      <EndpointsGroup />
      {currentPubkey ? <ManifestsGroup pubkey={currentPubkey} /> : null}
    </section>
  );
}
