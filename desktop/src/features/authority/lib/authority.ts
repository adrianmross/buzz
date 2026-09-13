import type { RelayEvent } from "@/shared/api/types";
import { getStorageItem, setStorageItem } from "@/shared/lib/safeStorage";

/**
 * BAP (Bounded Authority Protocol) kind 34560 — addressable announcement.
 * Defined locally until the shared kinds registry lands (another branch adds
 * the BAP kinds to `shared/constants/kinds.ts`; switch to that import on merge).
 */
export const KIND_BAP_ANNOUNCEMENT = 34560;
/** BAP kind 30550 — manifest core (NIP-XP v2), signed by its `owner_did`. */
export const KIND_BAP_MANIFEST_CORE = 30550;

const DID_NOSTR_PREFIX = "did:nostr:";
const X_ONLY_HEX = /^[0-9a-f]{64}$/;

/** `did:nostr:<64-hex x-only pubkey>`; null for anything that is not one. */
export function didNostrFromPubkey(
  pubkeyHex: string | undefined,
): string | null {
  const hex = pubkeyHex?.trim().toLowerCase() ?? "";
  return X_ONLY_HEX.test(hex) ? `${DID_NOSTR_PREFIX}${hex}` : null;
}

export const DEFAULT_RELYING_PARTY_URL = "https://approve.red-wiz.stream";
export const DEFAULT_MEDIATOR_INVITATION_URL =
  "https://didcomm.red-wiz.stream/invite?oob=eyJAdHlwZSI6Imh0dHBzOi8vZGlkY29tbS5vcmcvb3V0LW9mLWJhbmQvMS4xL2ludml0YXRpb24iLCJAaWQiOiI5MTgzNDhhNS1mZGNhLTQyNmUtODhjNy01NWVhZTc5ZTk0MGYiLCJsYWJlbCI6InJlZC13aXotbWVkaWF0b3IiLCJnb2FsX2NvZGUiOiJhcmllcy52Yy5tZWRpYXRlIiwiZ29hbCI6Ik1lZGlhdG9yIEludml0YXRpb24iLCJhY2NlcHQiOlsiZGlkY29tbS9haXAxIiwiZGlkY29tbS9haXAyO2Vudj1yZmMxOSJdLCJoYW5kc2hha2VfcHJvdG9jb2xzIjpbImh0dHBzOi8vZGlkY29tbS5vcmcvZGlkZXhjaGFuZ2UvMS4xIiwiaHR0cHM6Ly9kaWRjb21tLm9yZy9jb25uZWN0aW9ucy8xLjAiXSwic2VydmljZXMiOlt7ImlkIjoiI2lubGluZS0wIiwic2VydmljZUVuZHBvaW50IjoiaHR0cHM6Ly9kaWRjb21tLnJlZC13aXouc3RyZWFtIiwidHlwZSI6ImRpZC1jb21tdW5pY2F0aW9uIiwicmVjaXBpZW50S2V5cyI6WyJkaWQ6a2V5Ono2TWtwejVkWkhCSkVzVjJqRkE2RDh6MWZjd3FDRzVGM2VyRkR3aWI2Z2VUa2FuMSJdLCJyb3V0aW5nS2V5cyI6W119LHsiaWQiOiIjaW5saW5lLTEiLCJzZXJ2aWNlRW5kcG9pbnQiOiJ3c3M6Ly9kaWRjb21tLnJlZC13aXouc3RyZWFtIiwidHlwZSI6ImRpZC1jb21tdW5pY2F0aW9uIiwicmVjaXBpZW50S2V5cyI6WyJkaWQ6a2V5Ono2TWtwejVkWkhCSkVzVjJqRkE2RDh6MWZjd3FDRzVGM2VyRkR3aWI2Z2VUa2FuMSJdLCJyb3V0aW5nS2V5cyI6W119XX0";

export const AUTHORITY_RP_URL_STORAGE_KEY = "buzz.authority.relyingPartyUrl";
export const AUTHORITY_MEDIATOR_URL_STORAGE_KEY =
  "buzz.authority.mediatorInvitationUrl";

export type AuthoritySettings = {
  relyingPartyUrl: string;
  mediatorInvitationUrl: string;
};

/** Persisted values, falling back to the defaults for blank/missing entries. */
export function readAuthoritySettings(): AuthoritySettings {
  return {
    relyingPartyUrl:
      getStorageItem(AUTHORITY_RP_URL_STORAGE_KEY)?.trim() ||
      DEFAULT_RELYING_PARTY_URL,
    mediatorInvitationUrl:
      getStorageItem(AUTHORITY_MEDIATOR_URL_STORAGE_KEY)?.trim() ||
      DEFAULT_MEDIATOR_INVITATION_URL,
  };
}

/** Persist both values in one call; returns false when either write failed. */
export function writeAuthoritySettings(settings: AuthoritySettings): boolean {
  const rpOk = setStorageItem(
    AUTHORITY_RP_URL_STORAGE_KEY,
    settings.relyingPartyUrl.trim(),
  );
  const mediatorOk = setStorageItem(
    AUTHORITY_MEDIATOR_URL_STORAGE_KEY,
    settings.mediatorInvitationUrl.trim(),
  );
  return rpOk && mediatorOk;
}

/** `<rp>/rp` — trailing slashes on the configured origin are tolerated. */
export function relyingPartyInfoUrl(relyingPartyUrl: string): string {
  return `${relyingPartyUrl.trim().replace(/\/+$/, "")}/rp`;
}

export type AnnouncementRowKind = "manifest" | "replica announcement";

/** Row model for one kind-30550 manifest core or kind-34560 announcement. */
export type AnnouncementRow = {
  id: string;
  kindLabel: AnnouncementRowKind;
  /** `d` tag (the announcement's addressable name). */
  d: string;
  /** Manifest: content `resource`; announcement: `resource` tag; else `d`. */
  resource: string;
  /** `revision` tag; null when the announcement carries none. */
  revision: number | null;
  /** Manifest: content `owner_did`; announcement: `owner`/`agent` tag; else the signer as did:nostr. */
  ownerDid: string;
  updatedAt: number;
  /** Announcements only: first 120 chars of the content for unmodelled shapes. */
  contentSummary: string;
};

function firstTag(event: RelayEvent, name: string): string | undefined {
  return event.tags.find((tag) => tag[0] === name)?.[1];
}

function manifestCoreFields(content: string): {
  owner_did?: string;
  resource?: string;
} {
  try {
    const parsed: unknown = JSON.parse(content);
    if (parsed && typeof parsed === "object") {
      const { owner_did, resource } = parsed as Record<string, unknown>;
      return {
        owner_did: typeof owner_did === "string" ? owner_did : undefined,
        resource: typeof resource === "string" ? resource : undefined,
      };
    }
  } catch {
    // Not JCS/JSON — fall back to tags below.
  }
  return {};
}

export function announcementToRow(event: RelayEvent): AnnouncementRow {
  const d = firstTag(event, "d") ?? "";
  const revisionRaw = firstTag(event, "revision");
  const revision = revisionRaw === undefined ? Number.NaN : Number(revisionRaw);
  const isManifest = event.kind === KIND_BAP_MANIFEST_CORE;
  const core = isManifest ? manifestCoreFields(event.content) : {};
  return {
    id: event.id,
    kindLabel: isManifest ? "manifest" : "replica announcement",
    d,
    resource: core.resource ?? firstTag(event, "resource") ?? d,
    revision: Number.isInteger(revision) && revision >= 0 ? revision : null,
    ownerDid:
      core.owner_did ??
      firstTag(event, "owner") ??
      firstTag(event, "agent") ??
      didNostrFromPubkey(event.pubkey) ??
      event.pubkey,
    updatedAt: event.created_at,
    contentSummary: isManifest ? "" : event.content.slice(0, 120),
  };
}

/**
 * Dedupe by id, keep only manifest cores and announcements naming
 * `pubkey`/`did` as signer (a core is always signed by its owner), `owner`,
 * `agent`, or a `p` approver, newest first.
 */
export function announcementRowsFor(
  events: readonly RelayEvent[],
  pubkeyHex: string,
): AnnouncementRow[] {
  const did = didNostrFromPubkey(pubkeyHex);
  const seen = new Set<string>();
  const rows: AnnouncementRow[] = [];
  for (const event of events) {
    if (
      (event.kind !== KIND_BAP_ANNOUNCEMENT &&
        event.kind !== KIND_BAP_MANIFEST_CORE) ||
      seen.has(event.id)
    )
      continue;
    const named =
      event.pubkey === pubkeyHex ||
      event.tags.some(
        (tag) =>
          (tag[0] === "owner" || tag[0] === "agent" || tag[0] === "p") &&
          (tag[1] === pubkeyHex || (did !== null && tag[1] === did)),
      );
    if (!named) continue;
    seen.add(event.id);
    rows.push(announcementToRow(event));
  }
  return rows.sort((a, b) => b.updatedAt - a.updatedAt);
}
