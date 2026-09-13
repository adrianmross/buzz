import { useQuery, useQueryClient } from "@tanstack/react-query";
import * as React from "react";
import { toast } from "sonner";

import { approverFor, bapRpUrl } from "@/features/bap/lib/approveFlow";
import {
  clearNativeEnrollment,
  enrollNativeAuthenticator,
  loadNativeEnrollment,
  type NativeEnrollment,
  tauriNativeIo,
} from "@/features/bap/lib/nativeAuthenticator";
import { SettingsOptionGroup } from "@/features/settings/ui/SettingsOptionGroup";
import { Button } from "@/shared/ui/button";

const errorMessage = (error: unknown) =>
  error instanceof Error ? error.message : String(error);

/**
 * "Touch ID approvals": enrol this Mac's Secure Enclave credential with the
 * relying party so approvals run in-app instead of in the browser.
 * Mounted by the Authority settings card under the DID rows.
 */
export function NativeAuthenticatorCard({
  currentPubkey,
}: {
  currentPubkey?: string;
}) {
  const issuerDid = currentPubkey ? approverFor(currentPubkey).didKey : null;
  const queryClient = useQueryClient();
  const status = useQuery({
    queryKey: ["bap-native-authenticator"],
    queryFn: tauriNativeIo.status,
    staleTime: 30_000,
  });
  const [enrollment, setEnrollment] = React.useState<NativeEnrollment | null>(
    () => (issuerDid ? loadNativeEnrollment(issuerDid) : null),
  );
  const [busy, setBusy] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);

  const enrol = async () => {
    if (!issuerDid) return;
    setBusy(true);
    setError(null);
    try {
      setEnrollment(await enrollNativeAuthenticator(bapRpUrl(), issuerDid));
      toast.success("Touch ID enrolled for BAP approvals on this Mac.");
      void queryClient.invalidateQueries({
        queryKey: ["bap-native-authenticator"],
      });
    } catch (cause) {
      setError(errorMessage(cause));
    } finally {
      setBusy(false);
    }
  };

  const forget = () => {
    clearNativeEnrollment();
    setEnrollment(null);
  };

  const s = status.data;
  const keyMatches =
    enrollment !== null &&
    s?.enrolled === true &&
    s.credential_id === enrollment.credential_id;
  const summary = status.isPending
    ? "Checking Touch ID…"
    : !s?.available
      ? `Not available on this Mac${s?.reason ? `: ${s.reason}` : "."}`
      : keyMatches
        ? "Enrolled. Approvals run in-app with Touch ID; the browser is only used as a fallback."
        : enrollment
          ? "This Mac's credential no longer matches the saved enrolment. Enrol again."
          : "Not enrolled. Approvals open the passkey page in your browser.";

  return (
    <SettingsOptionGroup
      description="A P-256 key in this Mac's Secure Enclave, unlocked by Touch ID or your login password, acts as the DBAP authenticator."
      title="Touch ID approvals"
    >
      <div className="flex flex-col gap-2 px-4 py-3 text-sm">
        <p
          className="text-muted-foreground"
          data-testid="bap-native-authenticator-status"
        >
          {summary}
        </p>
        {enrollment ? (
          <code className="min-w-0 select-text break-all font-mono text-xs text-muted-foreground">
            credential {enrollment.credential_id}
          </code>
        ) : null}
        {error ? (
          <p
            className="text-destructive"
            data-testid="bap-native-authenticator-error"
          >
            {error}
          </p>
        ) : null}
        <div className="flex flex-wrap gap-2">
          <Button
            data-testid="bap-native-authenticator-enrol"
            disabled={busy || !issuerDid || !s?.available}
            onClick={() => void enrol()}
            size="sm"
            type="button"
            variant="outline"
          >
            {busy
              ? "Enrolling…"
              : keyMatches
                ? "Re-enrol Touch ID"
                : "Enrol Touch ID on this Mac"}
          </Button>
          {enrollment ? (
            <Button
              data-testid="bap-native-authenticator-forget"
              disabled={busy}
              onClick={forget}
              size="sm"
              type="button"
              variant="ghost"
            >
              Forget enrolment
            </Button>
          ) : null}
        </div>
      </div>
    </SettingsOptionGroup>
  );
}
