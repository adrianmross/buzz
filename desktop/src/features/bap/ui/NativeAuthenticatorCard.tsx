import { useQuery, useQueryClient } from "@tanstack/react-query";
import * as React from "react";
import { toast } from "sonner";

import { didKeyFromNostrPubkey } from "@bap/core/src/did.ts";

import { bapRpUrl } from "@/features/bap/lib/approveFlow";
import {
  clearNativeEnrollment,
  enrollNativeAuthenticator,
  enrollmentSigns,
  loadNativeEnrollment,
  type NativeEnrollment,
  tauriNativeIo,
} from "@/features/bap/lib/nativeAuthenticator";
import { DidRow } from "@/features/authority/ui/DidRow";
import { SettingsOptionGroup } from "@/features/settings/ui/SettingsOptionGroup";
import { Button } from "@/shared/ui/button";

const errorMessage = (error: unknown) =>
  error instanceof Error ? error.message : String(error);

export const LEGACY_ENROLLMENT_HINT =
  "This enrolment predates passkey signing: grants are still signed by your identity key. Re-enrol so the passkey itself is the approver.";

/**
 * "Touch ID approvals": enrol this Mac's Secure Enclave credential and
 * signing key with the relying party so approvals run in-app, signed by the
 * passkey (M18). Mounted by the Authority settings card under the DID rows.
 */
export function NativeAuthenticatorCard({
  currentPubkey,
}: {
  currentPubkey?: string;
}) {
  const ownerDid = currentPubkey
    ? didKeyFromNostrPubkey(currentPubkey.toLowerCase())
    : null;
  const queryClient = useQueryClient();
  const status = useQuery({
    queryKey: ["bap-native-authenticator"],
    queryFn: tauriNativeIo.status,
    staleTime: 30_000,
  });
  const [enrollment, setEnrollment] = React.useState<NativeEnrollment | null>(
    () => (ownerDid ? loadNativeEnrollment(ownerDid) : null),
  );
  const [busy, setBusy] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);

  const enrol = async () => {
    if (!ownerDid) return;
    setBusy(true);
    setError(null);
    try {
      setEnrollment(await enrollNativeAuthenticator(bapRpUrl(), ownerDid));
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
  const signs = enrollment !== null && enrollmentSigns(enrollment);
  const keyMatches =
    enrollment !== null &&
    s?.enrolled === true &&
    s.credential_id === enrollment.credential_id &&
    (!signs || s.sign_key === enrollment.sign_key);
  const summary = status.isPending
    ? "Checking Touch ID…"
    : !s?.available
      ? `Not available on this Mac${s?.reason ? `: ${s.reason}` : "."}`
      : keyMatches
        ? "Enrolled. Approvals run in-app with Touch ID; the browser is only used as a fallback."
        : enrollment
          ? "This Mac's keys no longer match the saved enrolment. Enrol again."
          : "Not enrolled. Approvals open the passkey page in your browser.";

  return (
    <SettingsOptionGroup
      description="Two P-256 keys in this Mac's Secure Enclave, unlocked by Touch ID or your login password: one asserts the approval ceremony, the other signs the grant and is the approver DID."
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
        {enrollment && !signs ? (
          <p
            className="text-muted-foreground"
            data-testid="bap-native-authenticator-legacy"
          >
            {LEGACY_ENROLLMENT_HINT}
          </p>
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
            disabled={busy || !ownerDid || !s?.available}
            onClick={() => void enrol()}
            size="sm"
            type="button"
            variant="outline"
          >
            {busy
              ? "Enrolling…"
              : keyMatches && signs
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
      {signs ? (
        <DidRow
          did={enrollment.issuer_did}
          hint="Grants you approve here are issued by this DID. A resource's manifest must list it as an approver — not your identity DID — for the passkey to be trusted."
          label="Approver DID (passkey)"
          testId="bap-approver-did"
        />
      ) : null}
    </SettingsOptionGroup>
  );
}
