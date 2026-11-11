import type {
  AnalysisOperation,
  CapabilityDescriptor,
} from "../application/AnalysisProvider.js";
import type { ProviderRejectionCode } from "../contracts/providerSelection.js";
import { REGEX_MATCHING_LIMITATION } from "../process/RegexMatcher.js";
import { PARANOIA_PROVIDER_ID } from "./ParanoiaRelease.js";

/** Static identity; the observed release is reported in each analysis profile. */
export const PARANOIA_PROVIDER_IDENTITY = Object.freeze({
  id: PARANOIA_PROVIDER_ID,
  name: "Paranoia",
  version: null,
});

/** Analyst outcomes `paranoia query` answers. */
export const PARANOIA_OPERATIONS = Object.freeze([
  "list_documents",
  "list_procedures",
  "search_procedures",
  "list_strings",
  "search_strings",
  "procedure_address",
  "address_name",
  "procedure_pseudo_code",
  "procedure_assembly",
  "procedure_callers",
  "procedure_callees",
  "xrefs",
] as const satisfies readonly Exclude<AnalysisOperation, "health">[]);
export type ParanoiaOperation = (typeof PARANOIA_OPERATIONS)[number];

export const isParanoiaOperation = (
  operation: AnalysisOperation,
): operation is ParanoiaOperation =>
  (PARANOIA_OPERATIONS as readonly string[]).includes(operation);

const PROVENANCE =
  "Paranoia static analysis: addresses and bytes are its observations, functions and their extents its derivations from entry points, symbols, unwind tables and recursive descent, and pseudocode its reconstruction, never original source.";
const ENTRY_LIMITATION =
  "Function entries come from Paranoia's own discovery; code reached only through unresolved indirect jumps can remain outside any function.";
const RELATIONSHIP_LIMITATION =
  "Paranoia reports direct call instructions between discovered functions and calls into import slots. Calls through registers or tables it could not resolve are absent; an empty list is not proof that nothing calls the function.";
const STRING_LIMITATION =
  "Paranoia's strings are printable ASCII and UTF-16LE runs in the file's sections. Strings in other encodings, or built at run time, are absent; an empty search is not proof of absence.";
const XREF_LIMITATION =
  "References are code-to-code (call, jump) and code-to-data references Paranoia's analysis resolved. Data-to-data references and unresolved indirect references are absent.";
const TEXT_LIMITATION =
  "Pseudocode and assembly are exact Paranoia text, not comparable as equal or different with another provider's text. Pseudocode exists for x86, x86-64 and (experimentally) AArch64; other architectures answer null.";

/** The limitations that apply to one operation's answer, and only those. */
export const paranoiaLimitations = (
  operation: ParanoiaOperation,
): readonly string[] => {
  switch (operation) {
    case "list_documents":
      return [];
    case "list_strings":
      return [PROVENANCE, STRING_LIMITATION];
    case "search_strings":
      return [PROVENANCE, STRING_LIMITATION, REGEX_MATCHING_LIMITATION];
    case "list_procedures":
    case "procedure_address":
    case "address_name":
      return [PROVENANCE, ENTRY_LIMITATION];
    case "search_procedures":
      return [PROVENANCE, ENTRY_LIMITATION, REGEX_MATCHING_LIMITATION];
    case "procedure_callers":
    case "procedure_callees":
      return [PROVENANCE, RELATIONSHIP_LIMITATION];
    case "xrefs":
      return [PROVENANCE, XREF_LIMITATION];
    case "procedure_pseudo_code":
    case "procedure_assembly":
      return [PROVENANCE, TEXT_LIMITATION];
  }
};

/** Paranoia reads the target and writes nothing; each answer is one supervised process. */
export const paranoiaCapabilities = (
  availability:
    | { readonly available: true }
    | {
        readonly available: false;
        readonly reason: string;
        readonly code: ProviderRejectionCode;
      },
): readonly CapabilityDescriptor[] =>
  PARANOIA_OPERATIONS.map((operation) => ({
    provider: PARANOIA_PROVIDER_IDENTITY,
    operation,
    ...(availability.available
      ? ({ available: true, reason: null } as const)
      : ({
          available: false,
          reason: availability.reason,
          availabilityCode: availability.code,
        } as const)),
    // Answers are a pure function of the target bytes and the executable the profile names.
    cachePolicy: "snapshot",
    effects: {
      mutatesArtifact: false,
      launchesProcess: true,
      mayShowUi: false,
      mayAccessNetwork: false,
      mayWriteFilesystem: false,
      changesPermissions: false,
      requiresRoot: false,
    },
    limitations: paranoiaLimitations(operation),
  }));
