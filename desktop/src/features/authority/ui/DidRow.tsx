import { Copy } from "lucide-react";

import { copyTextToClipboard } from "@/shared/lib/clipboard";
import { Button } from "@/shared/ui/button";

export const ROW_CLASS = "flex flex-col gap-2 px-4 py-3 text-sm";
export const DID_CLASS =
  "min-w-0 flex-1 select-text break-all font-mono text-xs text-muted-foreground";

/** One labelled DID with a copy button, as the Authority settings list them. */
export function DidRow({
  did,
  label,
  testId,
  hint,
}: {
  did: string;
  label: string;
  testId: string;
  hint?: string;
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
      {hint ? <p className="text-muted-foreground">{hint}</p> : null}
    </div>
  );
}
