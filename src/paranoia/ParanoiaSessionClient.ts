import { stat } from "node:fs/promises";

import {
  createAnalysisExecution,
  type AnalysisClient,
  type AnalysisExecution,
  type AnalysisOperation,
  type ExecutionOptions,
} from "../application/AnalysisProvider.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisCapabilityUnavailableError,
  AnalysisInputError,
  AnalysisOutputError,
} from "../domain/analysisErrorCore.js";
import type { AnalysisProfileCommitment } from "../domain/analysisProfile.js";
import {
  analysisSearchPredicate,
  analysisSearchQuerySchema,
} from "../domain/analysisSearch.js";
import type { BinaryTarget } from "../domain/binaryTargetTypes.js";
import type { EvidenceLocation } from "../domain/evidence.js";
import { analysisInputErrorFromIssues } from "../domain/inputIssueProjection.js";
import type { JsonValue } from "../domain/jsonValue.js";
import { ProviderAdapterError } from "../domain/providerAdapterError.js";
import { ProviderCleanupError } from "../domain/providerCleanupError.js";
import { err, ok, type Result } from "../domain/result.js";
import { matchRegexValues } from "../process/RegexMatcher.js";
import {
  isParanoiaOperation,
  paranoiaLimitations,
  PARANOIA_PROVIDER_IDENTITY,
  type ParanoiaOperation,
} from "./ParanoiaCapabilities.js";
import {
  runParanoiaQuery,
  type ParanoiaAnswer,
  type ParanoiaProcessLauncher,
  type RetainedParanoiaRun,
} from "./ParanoiaCommand.js";
import type { ParanoiaConfiguration } from "./ParanoiaConfiguration.js";
import {
  buildInventoryIndex,
  compareAddresses,
  functionSchema,
  inventorySchema,
  normalizeParanoiaAddress,
  xrefsSchema,
  type AddressedValue,
  type InventoryIndex,
} from "./ParanoiaInventory.js";
import { PARANOIA_PROVIDER_ID } from "./ParanoiaRelease.js";

export { normalizeParanoiaAddress } from "./ParanoiaInventory.js";

/** One answer before provenance is attached. */
interface Answer {
  readonly result: unknown;
  readonly locations: readonly EvidenceLocation[];
}
type AnswerResult = Result<Answer, AnalysisError>;

export interface ParanoiaSessionDependencies {
  readonly configuration: ParanoiaConfiguration;
  /** `dev:ino:size:mtime` of the executable when the profile was resolved; a change needs a reopen. */
  readonly executableIdentity: string | undefined;
  readonly launcher?: ParanoiaProcessLauncher | undefined;
}

/** File identity that changes when the executable is replaced or rebuilt. */
export const executableIdentity = async (path: string): Promise<string> => {
  const s = await stat(path, { bigint: true });
  return [s.dev, s.ino, s.size, s.mtimeNs].join(":");
};

const unavailable = (operation: string, reason: string) =>
  new AnalysisCapabilityUnavailableError(
    PARANOIA_PROVIDER_ID,
    operation,
    reason,
    { userMessage: reason },
  );

const badAddress = (operation: string, field: string, message: string) =>
  new AnalysisInputError(operation, { userMessage: message }, [
    { path: [field], reason: "invalid_value" },
  ]);

const at = (address: string): EvidenceLocation => ({
  kind: "address",
  address,
});

/**
 * One target analysed by Paranoia. Each answer is a separate supervised
 * `paranoia query` run that only reads the target; the inventory is fetched once
 * and validated, and every answer is checked against the target's SHA-256.
 */
export class ParanoiaSessionClient implements AnalysisClient {
  readonly #target: BinaryTarget;
  readonly #profile: AnalysisProfileCommitment | undefined;
  readonly #deps: ParanoiaSessionDependencies;
  readonly #session = new AbortController();
  readonly #active = new Set<Promise<unknown>>();
  #retained: RetainedParanoiaRun[] = [];
  #index: Promise<Result<InventoryIndex, AnalysisError>> | undefined;
  #closing = false;
  #closed = false;

  constructor(
    target: BinaryTarget,
    profile: AnalysisProfileCommitment | undefined,
    deps: ParanoiaSessionDependencies,
  ) {
    this.#target = target;
    this.#profile = profile;
    this.#deps = deps;
  }

  execute(
    operation: AnalysisOperation,
    parameters: Readonly<Record<string, JsonValue>>,
    options: ExecutionOptions = {},
  ): Promise<Result<AnalysisExecution, AnalysisError>> {
    if (this.#closing)
      return Promise.resolve(
        err(unavailable(operation, "This Paranoia session is closed.")),
      );
    const signal =
      options.signal === undefined
        ? this.#session.signal
        : AbortSignal.any([this.#session.signal, options.signal]);
    const work = this.#execute(operation, parameters, signal);
    this.#active.add(work);
    const release = () => this.#active.delete(work);
    void work.then(release, release);
    return work;
  }

  async #execute(
    operation: AnalysisOperation,
    parameters: Readonly<Record<string, JsonValue>>,
    signal: AbortSignal,
  ): Promise<Result<AnalysisExecution, AnalysisError>> {
    if (signal.aborted)
      return err(
        new AnalysisCancelledError(operation, { cause: signal.reason }),
      );
    if (operation === "health")
      return ok(
        this.#execution([], {
          result: {
            ready: true,
            paranoia: { command: this.#deps.configuration.command },
          },
          locations: [],
        }),
      );
    if (!isParanoiaOperation(operation))
      return err(
        unavailable(
          operation,
          "Paranoia answers procedure and string queries, pseudocode, assembly, callers, callees and references; this operation needs another provider.",
        ),
      );
    const admitted = await this.#admit(operation, parameters);
    if (!admitted.ok) return admitted;
    const answer = await this.#answer(operation, parameters, signal);
    if (!answer.ok) return answer;
    if (signal.aborted)
      return err(
        new AnalysisCancelledError(operation, { cause: signal.reason }),
      );
    return ok(this.#execution(paranoiaLimitations(operation), answer.value));
  }

  /** The one-document rule and the executable the profile named. */
  async #admit(
    operation: string,
    parameters: Readonly<Record<string, JsonValue>>,
  ): Promise<Result<null, AnalysisError>> {
    const document = parameters["document"];
    if (document !== undefined && document !== this.#target.path)
      return err(
        new AnalysisInputError(
          operation,
          {
            userMessage:
              "A Paranoia session analyses one program; omit document or pass the selected target path.",
          },
          [
            {
              path: ["document"],
              reason: "invalid_value",
              expected: this.#target.path,
            },
          ],
        ),
      );
    const expected = this.#deps.executableIdentity;
    if (expected === undefined) return ok(null);
    const { command } = this.#deps.configuration;
    try {
      if ((await executableIdentity(command)) === expected) return ok(null);
    } catch (cause: unknown) {
      return err(
        new ProviderAdapterError(PARANOIA_PROVIDER_ID, operation, {
          cause,
          userMessage: `Cannot inspect ${command}: ${cause instanceof Error ? cause.message : String(cause)}`,
        }),
      );
    }
    return err(
      new ProviderAdapterError(PARANOIA_PROVIDER_ID, operation, {
        userMessage: `${command} changed after this target was opened; reopen the target so REA records the current Paranoia executable.`,
      }),
    );
  }

  #execution(
    limitations: readonly string[],
    answer: Answer,
  ): AnalysisExecution {
    return createAnalysisExecution(
      answer.result,
      {
        ...PARANOIA_PROVIDER_IDENTITY,
        version: this.#profile?.provider.version ?? null,
      },
      {
        limitations,
        locations: [
          { kind: "artifact-path", path: this.#target.path },
          ...answer.locations,
        ],
        ...(this.#profile === undefined
          ? {}
          : { analysisProfile: this.#profile }),
      },
    );
  }

  #query(
    operation: string,
    args: readonly string[],
    signal: AbortSignal,
  ): Promise<Result<ParanoiaAnswer, AnalysisError>> {
    return runParanoiaQuery({
      configuration: this.#deps.configuration,
      target: this.#target.path,
      sha256: this.#target.sha256,
      arguments: args,
      operation,
      signal,
      retain: (run) => this.#retained.push(run),
      launcher: this.#deps.launcher,
    });
  }

  async #fetchIndex(
    operation: string,
  ): Promise<Result<InventoryIndex, AnalysisError>> {
    const answer = await this.#query(
      operation,
      ["inventory"],
      this.#session.signal,
    );
    if (!answer.ok) return answer;
    const inventory = inventorySchema.safeParse(answer.value.result);
    if (!inventory.success)
      return err(
        new AnalysisOutputError(
          operation,
          "paranoia query inventory answered in an unexpected shape.",
          {
            cause: inventory.error,
          },
        ),
      );
    return ok(buildInventoryIndex(inventory.data));
  }

  /** The inventory, fetched once per session. A failed fetch is forgotten, so a retry runs again. */
  #ensureIndex(
    operation: string,
    signal: AbortSignal,
  ): Promise<Result<InventoryIndex, AnalysisError>> {
    const pending = (this.#index ??= this.#fetchIndex(operation));
    void pending.then((r) => {
      if (!r.ok && this.#index === pending) this.#index = undefined;
    });
    return new Promise((resolve) => {
      const abort = () =>
        resolve(
          err(new AnalysisCancelledError(operation, { cause: signal.reason })),
        );
      if (signal.aborted) {
        abort();
        return;
      }
      signal.addEventListener("abort", abort, { once: true });
      void pending.then((r) => {
        signal.removeEventListener("abort", abort);
        resolve(r);
      });
    });
  }

  async #answer(
    operation: ParanoiaOperation,
    parameters: Readonly<Record<string, JsonValue>>,
    signal: AbortSignal,
  ): Promise<AnswerResult> {
    if (operation === "list_documents")
      return ok({ result: [this.#target.path], locations: [] });
    const index = await this.#ensureIndex(operation, signal);
    if (!index.ok) return index;
    switch (operation) {
      case "list_procedures":
        return ok({ result: index.value.procedures, locations: [] });
      case "search_procedures":
        return this.#search(
          operation,
          parameters,
          index.value.procedures,
          signal,
        );
      case "search_strings":
        return this.#search(operation, parameters, index.value.strings, signal);
      case "list_strings":
        return this.#listStrings(operation, parameters, index.value);
      case "address_name":
        return this.#addressName(operation, parameters, index.value);
      case "xrefs":
        return this.#xrefs(operation, parameters, signal);
      default:
        return this.#procedureAnswer(
          operation,
          parameters,
          index.value,
          signal,
        );
    }
  }

  async #search(
    operation: string,
    parameters: Readonly<Record<string, JsonValue>>,
    rows: readonly AddressedValue[],
    signal: AbortSignal,
  ): Promise<AnswerResult> {
    const query = analysisSearchQuerySchema.safeParse(parameters);
    if (!query.success)
      return err(
        analysisInputErrorFromIssues(operation, query.error.issues, parameters),
      );
    if (query.data.mode === "literal") {
      const matches = analysisSearchPredicate(query.data);
      return ok({
        result: rows.filter((r) => matches(r.value)),
        locations: [],
      });
    }
    const matched = await matchRegexValues({
      operation,
      pattern: query.data.pattern,
      caseSensitive: query.data.case_sensitive,
      values: rows.map((r) => r.value),
      signal,
    });
    if (!matched.ok) return matched;
    return ok({
      result: matched.value.flatMap((i) => rows[i] ?? []),
      locations: [],
    });
  }

  #listStrings(
    operation: string,
    parameters: Readonly<Record<string, JsonValue>>,
    index: InventoryIndex,
  ): AnswerResult {
    if (parameters["address"] === undefined)
      return ok({ result: index.strings, locations: [] });
    const selected = normalizeParanoiaAddress(parameters["address"]);
    if (selected === undefined)
      return err(
        badAddress(
          operation,
          "address",
          "address must be a 0x hexadecimal address.",
        ),
      );
    return ok({
      result: index.strings.filter((s) => s.address === selected),
      locations: [at(selected)],
    });
  }

  #addressName(
    operation: string,
    parameters: Readonly<Record<string, JsonValue>>,
    index: InventoryIndex,
  ): AnswerResult {
    const selected = normalizeParanoiaAddress(parameters["address"]);
    if (selected === undefined)
      return err(
        badAddress(
          operation,
          "address",
          "address must be a 0x hexadecimal address.",
        ),
      );
    return ok({
      result: index.byAddress.get(selected) ?? null,
      locations: [at(selected)],
    });
  }

  async #xrefs(
    operation: string,
    parameters: Readonly<Record<string, JsonValue>>,
    signal: AbortSignal,
  ): Promise<AnswerResult> {
    const selected = normalizeParanoiaAddress(parameters["address"]);
    if (selected === undefined)
      return err(
        badAddress(
          operation,
          "address",
          "Pass address as a 0x hexadecimal address.",
        ),
      );
    const answer = await this.#query(operation, ["xrefs", selected], signal);
    if (!answer.ok) return answer;
    const refs = xrefsSchema.safeParse(answer.value.result);
    if (!refs.success)
      return err(
        new AnalysisOutputError(
          operation,
          "paranoia query xrefs answered in an unexpected shape.",
          { cause: refs.error },
        ),
      );
    const from = [
      ...new Set((refs.data?.references ?? []).map((r) => r.from)),
    ].sort(compareAddresses);
    return ok({ result: from, locations: [at(selected)] });
  }

  /** A procedure selector: an entry address, an interior address, or a unique name. */
  async #procedure(
    operation: string,
    selector: JsonValue | undefined,
    index: InventoryIndex,
    signal: AbortSignal,
  ): Promise<Result<string, AnalysisError>> {
    if (typeof selector !== "string" || selector === "")
      return err(
        new AnalysisInputError(
          operation,
          { userMessage: "Pass procedure as a name or a 0x address." },
          [{ path: ["procedure"], reason: "missing_argument" }],
        ),
      );
    const selected = normalizeParanoiaAddress(selector);
    if (selected === undefined) {
      const found = index.byName.get(selector);
      if (typeof found === "string" && index.functionStarts.has(found))
        return ok(found);
      return err(
        badAddress(
          operation,
          "procedure",
          found === null
            ? `More than one function is named ${selector}; pass its address.`
            : `No function is named ${selector}.`,
        ),
      );
    }
    if (index.functionStarts.has(selected)) return ok(selected);
    // An interior address: Paranoia resolves the containing function.
    const answer = await this.#query(operation, ["function", selected], signal);
    if (!answer.ok) return answer;
    const f = functionSchema.safeParse(answer.value.result);
    if (f.success && f.data !== null) return ok(f.data.address);
    return err(
      badAddress(operation, "procedure", `No function contains ${selected}.`),
    );
  }

  async #procedureAnswer(
    operation:
      | "procedure_address"
      | "procedure_callers"
      | "procedure_callees"
      | "procedure_pseudo_code"
      | "procedure_assembly",
    parameters: Readonly<Record<string, JsonValue>>,
    index: InventoryIndex,
    signal: AbortSignal,
  ): Promise<AnswerResult> {
    const procedure = await this.#procedure(
      operation,
      parameters["procedure"],
      index,
      signal,
    );
    if (!procedure.ok) return procedure;
    const locations = [at(procedure.value)];
    if (operation === "procedure_address")
      return ok({ result: procedure.value, locations });
    if (operation === "procedure_callees")
      return ok({
        result: index.callees.get(procedure.value) ?? [],
        locations,
      });
    if (operation === "procedure_callers")
      return ok({
        result: index.callers.get(procedure.value) ?? [],
        locations,
      });
    const answer = await this.#query(
      operation,
      ["function", procedure.value],
      signal,
    );
    if (!answer.ok) return answer;
    const f = functionSchema.safeParse(answer.value.result);
    if (!f.success || f.data === null)
      return err(
        new AnalysisOutputError(
          operation,
          `paranoia query function ${procedure.value} gave no function.`,
          f.success ? {} : { cause: f.error },
        ),
      );
    if (operation === "procedure_pseudo_code")
      return ok({ result: f.data.pseudocode, locations });
    if (f.data.assembly === null)
      return err(
        unavailable(
          operation,
          `Paranoia has no disassembly for ${procedure.value}.`,
        ),
      );
    return ok({ result: f.data.assembly, locations });
  }

  /** Stop admitting work, wait for running queries, and prove every retained process stopped. */
  async close(): Promise<Result<null, AnalysisError>> {
    if (this.#closed) return ok(null);
    if (!this.#closing) {
      this.#closing = true;
      this.#session.abort();
    }
    while (this.#active.size > 0) await Promise.allSettled(this.#active);
    await this.#index;
    const remaining: RetainedParanoiaRun[] = [];
    for (const run of this.#retained) {
      const stopped = await run.owner?.stop().catch(() => undefined);
      if (stopped === undefined || stopped.status === "incomplete")
        remaining.push(run);
    }
    this.#retained = remaining;
    if (remaining.length > 0)
      return err(
        new ProviderCleanupError(
          PARANOIA_PROVIDER_ID,
          remaining.flatMap((r) => r.error.cleanupResources),
          {
            reason:
              "A paranoia query process could not be proven stopped; closing again retries.",
          },
          { operation: "close_binary" },
        ).bindCleanupDependencies(remaining.map((r) => r.error)),
      );
    this.#closed = true;
    return ok(null);
  }
}
