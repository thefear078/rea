import { randomUUID } from "node:crypto";

import { z } from "zod";

import type { AnalysisError } from "../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisOutputError,
  AnalysisResourceConstraintError,
  AnalysisTimeoutError,
} from "../domain/analysisErrorCore.js";
import { ProviderAdapterError } from "../domain/providerAdapterError.js";
import { ProviderCleanupError } from "../domain/providerCleanupError.js";
import { err, ok, type Result } from "../domain/result.js";
import {
  OwnedCommandFailure,
  runOwnedCommand,
} from "../process/OwnedCommand.js";
import type {
  OwnedProviderProcessSpawnOptions,
  ProviderProcessSupervisor,
  SpawnedOwnedProviderProcess,
} from "../process/ProviderProcess.js";
import {
  PARANOIA_OUTPUT_BYTES,
  type ParanoiaConfiguration,
} from "./ParanoiaConfiguration.js";
import {
  PARANOIA_PROVIDER_ID,
  PARANOIA_QUERY_FORMAT,
} from "./ParanoiaRelease.js";

/** Test seam for the owned process launcher; production uses the default. */
export type ParanoiaProcessLauncher = (
  options: OwnedProviderProcessSpawnOptions,
) => Promise<SpawnedOwnedProviderProcess>;

/** The envelope every `paranoia query` answer shares. */
const answerSchema = z.object({
  format: z.literal(PARANOIA_QUERY_FORMAT),
  file: z.object({
    sha256: z.string().regex(/^[0-9a-f]{64}$/u),
    name: z.string(),
    format: z.string(),
    arch: z.string(),
    bits: z.number().int(),
    entry: z.string(),
  }),
  result: z.unknown(),
});

export type ParanoiaAnswer = z.infer<typeof answerSchema>;

/** A run whose process tree could not be proven stopped; its owner retries the stop. */
export interface RetainedParanoiaRun {
  readonly error: ProviderCleanupError;
  readonly owner: ProviderProcessSupervisor | undefined;
}

export interface ParanoiaQueryRequest {
  readonly configuration: ParanoiaConfiguration;
  /** Absolute path of the target, read by Paranoia, never written. */
  readonly target: string;
  /** SHA-256 the answer must report, so every answer is about the selected bytes. */
  readonly sha256: string;
  readonly arguments: readonly string[];
  readonly operation: string;
  readonly signal: AbortSignal;
  readonly retain: (run: RetainedParanoiaRun) => void;
  readonly launcher?: ParanoiaProcessLauncher | undefined;
}

const message = (cause: unknown): string =>
  cause instanceof Error ? cause.message : String(cause);

/** Run one `paranoia query TARGET …` under an owned process group and parse its single answer. */
export const runParanoiaQuery = async (
  request: ParanoiaQueryRequest,
): Promise<Result<ParanoiaAnswer, AnalysisError>> => {
  const { configuration, operation } = request;
  const subcommand = request.arguments[0] ?? "";
  let stdout: string;
  try {
    const snapshot = await runOwnedCommand(
      {
        command: configuration.command,
        arguments: ["query", request.target, ...request.arguments],
        runId: `rea-paranoia-${randomUUID()}`,
      },
      {
        timeoutMs: configuration.timeoutMs,
        diagnosticBytes: PARANOIA_OUTPUT_BYTES,
      },
      {
        signal: request.signal,
        ...(request.launcher === undefined
          ? {}
          : { launcher: request.launcher }),
      },
    );
    if (snapshot.exitCode !== 0)
      return err(
        new ProviderAdapterError(PARANOIA_PROVIDER_ID, operation, {
          userMessage: `paranoia query ${subcommand} failed with exit code ${String(snapshot.exitCode)}: ${snapshot.stderr.text.trim().split("\n").at(-1) ?? ""}`,
        }),
      );
    if (
      snapshot.stdout.invalidUtf8 === true ||
      snapshot.outputIncomplete === true
    )
      return err(
        new AnalysisOutputError(
          operation,
          `paranoia query ${subcommand} wrote incomplete or invalid UTF-8 output.`,
        ),
      );
    stdout = snapshot.stdout.text;
  } catch (cause: unknown) {
    return err(failure(cause, request, subcommand));
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(stdout);
  } catch (cause: unknown) {
    return err(
      new AnalysisOutputError(
        operation,
        `paranoia query ${subcommand} did not print JSON: ${message(cause)}`,
        { cause },
      ),
    );
  }
  const answer = answerSchema.safeParse(parsed);
  if (!answer.success)
    return err(
      new AnalysisOutputError(
        operation,
        `paranoia query ${subcommand} answered in an unexpected shape; this provider reads ${PARANOIA_QUERY_FORMAT}. Use a Paranoia release that prints it.`,
        { cause: answer.error },
      ),
    );
  if (answer.data.file.sha256 !== request.sha256)
    return err(
      new ProviderAdapterError(PARANOIA_PROVIDER_ID, operation, {
        userMessage: `${request.target} changed after it was opened: Paranoia analysed bytes with SHA-256 ${answer.data.file.sha256}, the target is ${request.sha256}. Reopen the target.`,
        diagnostics: {
          expected_sha256: request.sha256,
          observed_sha256: answer.data.file.sha256,
        },
      }),
    );
  return ok(answer.data);
};

/** Map an owned-command failure to its typed error, keeping an unproven stop owned. */
const failure = (
  cause: unknown,
  request: ParanoiaQueryRequest,
  subcommand: string,
): AnalysisError => {
  const { operation, configuration } = request;
  if (!(cause instanceof OwnedCommandFailure))
    return new ProviderAdapterError(PARANOIA_PROVIDER_ID, operation, {
      cause,
      userMessage: `Cannot run ${configuration.command}: ${message(cause)}`,
    });
  let primary: AnalysisError;
  if (cause.reason === "cancelled")
    primary = new AnalysisCancelledError(operation, {
      cause: cause.cancellation?.reason,
    });
  else if (cause.reason === "timeout")
    primary = new AnalysisTimeoutError(operation, configuration.timeoutMs, {
      cause,
      userMessage: `paranoia query ${subcommand} did not finish within REA_PARANOIA_TIMEOUT_MS (${String(configuration.timeoutMs)} ms).`,
      remediationAction:
        "Raise REA_PARANOIA_TIMEOUT_MS in the environment that starts REA, then restart REA.",
    });
  else if (cause.reason === "output-limit")
    primary = new AnalysisResourceConstraintError(
      operation,
      "memory",
      `paranoia query ${subcommand} wrote more than ${String(PARANOIA_OUTPUT_BYTES)} bytes.`,
      { output_limit_bytes: PARANOIA_OUTPUT_BYTES },
      {
        cause,
        remediationAction:
          "The same request on this target fails the same way; use another provider for it.",
      },
    );
  else
    primary = new ProviderAdapterError(PARANOIA_PROVIDER_ID, operation, {
      cause,
      userMessage: `paranoia query ${subcommand} failed: ${cause.snapshot?.stderr.text.trim().split("\n").at(-1) || cause.message}`,
    });
  if (cause.cleanupFailure === null) return primary;
  const error = new ProviderCleanupError(
    PARANOIA_PROVIDER_ID,
    [...cause.resources],
    { reason: cause.cleanupFailure },
    { cause, operation, cleanupPrimary: primary },
  );
  request.retain({ error, owner: cause.cleanupOwner });
  return error;
};
