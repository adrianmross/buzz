import {
  KIND_BAP_ATTESTATION,
  KIND_BAP_BEACON,
  KIND_BAP_CERTIFICATE,
  KIND_BAP_CHECKPOINT,
  KIND_BAP_CLAIM_RECEIPT,
  KIND_BAP_DELEGATION,
  KIND_BAP_EMERGENCY_STOP,
  KIND_BAP_EPOCH_ROLLUP,
  KIND_BAP_INVOCATION,
  KIND_BAP_RECEIPT,
  KIND_BAP_REQUEST,
  KIND_BAP_RESUME,
  KIND_BAP_REVOCATION,
  isBapTimelineKind,
} from "@/shared/constants/kinds";

/**
 * Pure event → card model for BAP kinds. Reads index tags (and the JSON
 * content of 4550/4564/4571) without verifying anything: the relay already
 * checked signatures, and a card that blanks on a stray field is worse for an
 * audit than one that shows what arrived. Protocol validation happens only on
 * the approve path (`approveFlow.ts`).
 */

export type BapCardEvent = {
  kind: number;
  tags: string[][];
  content: string;
};

export type BapCardField = {
  label: string;
  value: string;
  /** Free text supplied by the requester: rendered visually subordinate. */
  untrusted?: boolean;
};

/** The DIDComm `request-approval` body carried in a kind-4550 `content`. */
export type BapRequestApproval = {
  id: string;
  from: string;
  to: string[];
  expiresTime: number;
  command: string;
  resource: string;
  actionDigest: string;
  justification: string;
  requestedTtl: number;
  requestedPolicy: unknown[];
  chainRoot: string;
  risk: string;
};

export type BapCard = {
  kind: number;
  title: string;
  fields: BapCardField[];
  /** Parsed 4550 body; only present when the content is a well-formed request. */
  request?: BapRequestApproval;
  /** 4551: the request event this grant answers (`req` tag). */
  requestEventId?: string;
};

const TITLES: Record<number, string> = {
  [KIND_BAP_REQUEST]: "Approval request",
  [KIND_BAP_DELEGATION]: "Grant",
  [KIND_BAP_INVOCATION]: "Invocation",
  [KIND_BAP_REVOCATION]: "Revocation",
  [KIND_BAP_CHECKPOINT]: "Checkpoint",
  [KIND_BAP_BEACON]: "Beacon",
  [KIND_BAP_CLAIM_RECEIPT]: "Claim receipt",
  [KIND_BAP_ATTESTATION]: "Attestation",
  [KIND_BAP_RECEIPT]: "Receipt",
  [KIND_BAP_EPOCH_ROLLUP]: "Epoch rollup",
  [KIND_BAP_EMERGENCY_STOP]: "Emergency stop",
  [KIND_BAP_RESUME]: "Resume",
  [KIND_BAP_CERTIFICATE]: "Certificate",
};

export function bapKindTitle(kind: number): string {
  return TITLES[kind] ?? `BAP kind ${kind}`;
}

const tagValue = (tags: string[][], name: string) =>
  tags.find((tag) => tag[0] === name)?.[1];
const tagValues = (tags: string[][], name: string) =>
  tags
    .filter((tag) => tag[0] === name && typeof tag[1] === "string")
    .map((tag) => tag[1]);

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function parseJson(content: string): unknown {
  try {
    return JSON.parse(content) as unknown;
  } catch {
    return null;
  }
}

/** Lenient parse of a 4550 body: shape only, no bounds or policy checks. */
export function parseBapRequestApproval(
  content: string,
): BapRequestApproval | null {
  const m = parseJson(content);
  if (!isRecord(m) || !isRecord(m.body)) return null;
  const b = m.body;
  const ctx = isRecord(b.delegation_context) ? b.delegation_context : {};
  if (
    typeof m.id !== "string" ||
    typeof m.from !== "string" ||
    !Array.isArray(m.to) ||
    typeof b.command !== "string" ||
    typeof b.resource !== "string"
  ) {
    return null;
  }
  return {
    id: m.id,
    from: m.from,
    to: m.to.filter((t): t is string => typeof t === "string"),
    expiresTime: typeof m.expires_time === "number" ? m.expires_time : 0,
    command: b.command,
    resource: b.resource,
    actionDigest: typeof b.action_digest === "string" ? b.action_digest : "",
    justification: typeof b.justification === "string" ? b.justification : "",
    requestedTtl: typeof b.requested_ttl === "number" ? b.requested_ttl : 0,
    requestedPolicy: Array.isArray(b.requested_policy)
      ? b.requested_policy
      : [],
    chainRoot: typeof ctx.chain_root === "string" ? ctx.chain_root : "",
    risk: typeof b.risk === "string" ? b.risk : "",
  };
}

const isoTime = (unix: number) =>
  unix > 0 ? new Date(unix * 1000).toISOString() : "";

function field(label: string, value: string | undefined): BapCardField[] {
  return value ? [{ label, value }] : [];
}

function requestCard(event: BapCardEvent): BapCard {
  const request = parseBapRequestApproval(event.content);
  const tags = event.tags;
  if (!request) {
    return {
      kind: event.kind,
      title: bapKindTitle(event.kind),
      fields: [
        ...field("command", tagValue(tags, "cmd")),
        ...field("resource", tagValue(tags, "res")),
        ...field("ttl", tagValue(tags, "ttl")),
        ...field("reason", tagValue(tags, "reason")),
      ],
    };
  }
  return {
    kind: event.kind,
    title: bapKindTitle(event.kind),
    request,
    fields: [
      { label: "command", value: request.command },
      { label: "resource", value: request.resource },
      ...field("action digest", request.actionDigest),
      { label: "requester", value: request.from },
      ...field("approver", request.to.join(", ")),
      ...field("chain root", request.chainRoot),
      {
        label: "requested",
        value: `ttl ${request.requestedTtl}s${request.risk ? ` · risk ${request.risk}` : ""}`,
      },
      ...(request.requestedPolicy.length > 0
        ? [{ label: "policy", value: JSON.stringify(request.requestedPolicy) }]
        : []),
      ...field("expires", isoTime(request.expiresTime)),
      ...(request.justification
        ? [
            {
              label: "justification",
              value: request.justification,
              untrusted: true,
            },
          ]
        : []),
    ],
  };
}

function grantCard(event: BapCardEvent): BapCard {
  const tags = event.tags;
  const exp = Number(tagValue(tags, "expiration"));
  return {
    kind: event.kind,
    title: bapKindTitle(event.kind),
    requestEventId: tagValue(tags, "req"),
    fields: [
      ...field("audience", tagValue(tags, "aud")),
      ...field("command", tagValue(tags, "cmd")),
      ...field("resource", tagValues(tags, "res").join("\n")),
      ...field("expires", Number.isFinite(exp) ? isoTime(exp) : undefined),
      ...field("proof of", tagValue(tags, "prf")),
      ...field("answers request", tagValue(tags, "req")),
    ],
  };
}

function checkpointCard(event: BapCardEvent): BapCard {
  const tags = event.tags;
  const body = parseJson(event.content);
  const b = isRecord(body) ? body : {};
  return {
    kind: event.kind,
    title: bapKindTitle(event.kind),
    fields: [
      ...field("task", tagValue(tags, "e")),
      ...field("step", tagValue(tags, "step")),
      ...field("prev", tagValue(tags, "prev")),
      ...field("agent", tagValue(tags, "agent")),
      ...field("replica", tagValue(tags, "replica")),
      ...field(
        "committed",
        typeof b.committed === "string" ? b.committed : undefined,
      ),
      ...field(
        "pending",
        typeof b.pending === "string" ? b.pending : undefined,
      ),
    ],
  };
}

function stopCard(event: BapCardEvent): BapCard {
  const tags = event.tags;
  return {
    kind: event.kind,
    title: bapKindTitle(event.kind),
    fields: [
      ...field("root", tagValue(tags, "root")),
      { label: "scope", value: tagValue(tags, "scope") ?? "all" },
      ...field("reason", tagValue(tags, "reason")),
      ...field("guard", tagValue(tags, "guard")),
      ...field("beacon seq", tagValue(tags, "seq")),
    ],
  };
}

function resumeCard(event: BapCardEvent): BapCard {
  const tags = event.tags;
  const inline = tagValue(tags, "dbap") === "inline";
  const body = inline ? parseJson(event.content) : null;
  const note = isRecord(body)
    ? typeof body.note === "string"
      ? body.note
      : ""
    : event.content;
  return {
    kind: event.kind,
    title: bapKindTitle(event.kind),
    fields: [
      ...field("lifts stop", tagValue(tags, "e")),
      ...field("root", tagValue(tags, "root")),
      ...field("beacon seq", tagValue(tags, "seq")),
      { label: "device proof", value: inline ? "inline (DBAP)" : "none" },
      ...(note ? [{ label: "note", value: note, untrusted: true }] : []),
    ],
  };
}

function genericCard(event: BapCardEvent): BapCard {
  return {
    kind: event.kind,
    title: bapKindTitle(event.kind),
    fields: event.tags
      .filter((tag) => typeof tag[0] === "string" && typeof tag[1] === "string")
      .slice(0, 8)
      .map((tag) => ({ label: tag[0], value: tag[1] })),
  };
}

export function eventToBapCard(event: BapCardEvent): BapCard | null {
  if (!isBapTimelineKind(event.kind)) return null;
  switch (event.kind) {
    case KIND_BAP_REQUEST:
      return requestCard(event);
    case KIND_BAP_DELEGATION:
      return grantCard(event);
    case KIND_BAP_REVOCATION:
      return {
        kind: event.kind,
        title: bapKindTitle(event.kind),
        fields: [
          ...field("revoked delegation", tagValue(event.tags, "prf")),
          ...field("revoked event", tagValue(event.tags, "e")),
        ],
      };
    case KIND_BAP_CHECKPOINT:
      return checkpointCard(event);
    case KIND_BAP_EMERGENCY_STOP:
      return stopCard(event);
    case KIND_BAP_RESUME:
      return resumeCard(event);
    default:
      return genericCard(event);
  }
}
