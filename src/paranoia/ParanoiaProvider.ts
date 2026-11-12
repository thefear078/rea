import { accessSync, constants, statSync } from "node:fs";
import { randomUUID } from "node:crypto";

import type {
  AnalysisClient,
  AnalysisProfileResolution,
  AnalysisProfileResolutionOptions,
  AnalysisProviderCandidate,
  ProviderAvailability,
  ProviderTargetSupport,
} from "../application/AnalysisProvider.js";
import {
  AnalysisCancelledError,
  AnalysisCapabilityUnavailableError,
} from "../domain/analysisErrorCore.js";
import {
  createAnalysisProfile,
  type AnalysisProfileCommitment,
} from "../domain/analysisProfile.js";
import type { BinaryTarget } from "../domain/binaryTargetTypes.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import { err, ok, type Result } from "../domain/result.js";
import { hashStableFile } from "../filesystem/StableFileHash.js";
import {
  OwnedCommandFailure,
  runOwnedCommand,
} from "../process/OwnedCommand.js";
import { snapshotEnvironment } from "../process/snapshotEnvironment.js";
import {
  paranoiaCapabilities,
  PARANOIA_PROVIDER_IDENTITY,
} from "./ParanoiaCapabilities.js";
import type { ParanoiaProcessLauncher } from "./ParanoiaCommand.js";
import { readParanoiaConfiguration } from "./ParanoiaConfiguration.js";
import {
  PARANOIA_COMMAND_REMEDIATION,
  PARANOIA_PROVIDER_ID,
  PARANOIA_QUERY_FORMAT,
} from "./ParanoiaRelease.js";
import {
  executableIdentity,
  ParanoiaSessionClient,
} from "./ParanoiaSessionClient.js";

/** Formats and architectures Paranoia disassembles. Pseudocode is narrower; see the limitations. */
const FORMATS: ReadonlySet<string> = new Set(["pe", "elf", "mach-o"]);
const ARCHITECTURES: ReadonlySet<string> = new Set([
  "x86",
  "x86_64",
  "arm64",
  "arm",
  "riscv",
  "mips",
  "powerpc",
]);

const unavailable = (operation: string, reason: string) =>
  new AnalysisCapabilityUnavailableError(
    PARANOIA_PROVIDER_ID,
    operation,
    reason,
    { userMessage: reason },
  );

const cancelled = (cause: unknown) =>
  new AnalysisCancelledError("paranoia:profile", { cause });

const describe = (cause: unknown): string =>
  cause instanceof Error ? cause.message : String(cause);

/** `paranoia --version` prints `paranoia <semver>`. */
export const probeVersion = async (
  command: string,
  signal: AbortSignal | undefined,
  launcher: ParanoiaProcessLauncher | undefined,
): Promise<Result<string, AnalysisError>> => {
  try {
    const snapshot = await runOwnedCommand(
      {
        command,
        arguments: ["--version"],
        runId: `rea-paranoia-version-${randomUUID()}`,
      },
      { timeoutMs: 30_000, diagnosticBytes: 64 * 1024 },
      {
        ...(signal === undefined ? {} : { signal }),
        ...(launcher === undefined ? {} : { launcher }),
      },
    );
    const match = /^paranoia (\d+\.\d+\.\d+\S*)\s*$/u.exec(
      snapshot.stdout.text.trim(),
    );
    if (snapshot.exitCode === 0 && match?.[1] !== undefined)
      return ok(match[1]);
    return err(
      unavailable(
        "open_binary",
        `${command} --version did not print \`paranoia <version>\`; is REA_PARANOIA_COMMAND the paranoia CLI?`,
      ),
    );
  } catch (cause: unknown) {
    if (cause instanceof OwnedCommandFailure && cause.reason === "cancelled")
      return err(cancelled(cause.cancellation?.reason));
    return err(
      unavailable(
        "open_binary",
        `Cannot run ${command} --version: ${describe(cause)}`,
      ),
    );
  }
};

/** SHA-256 of the executable and the file identity that later runs compare against. */
export const hashExecutable = async (
  command: string,
  options: AnalysisProfileResolutionOptions | undefined,
): Promise<Result<{ sha256: string; identity: string }, AnalysisError>> => {
  const signal = options?.signal;
  const owner = options?.fileCloseResources;
  try {
    const identity = await executableIdentity(command);
    const hashing = () =>
      hashStableFile(command, {
        ...(signal === undefined ? {} : { signal }),
        retainFailedClose: (handle) => owner?.retain(handle, command),
      });
    const { sha256 } =
      owner === undefined ? await hashing() : await owner.run(hashing);
    return ok({ sha256, identity });
  } catch (cause: unknown) {
    if (signal?.aborted === true) return err(cancelled(signal.reason));
    return err(
      unavailable("open_binary", `Cannot hash ${command}: ${describe(cause)}`),
    );
  }
};

/**
 * Bring-your-own Paranoia (https://github.com/Altumptic/paranoia), driven through
 * `paranoia query`. Static and read-only: every answer is one supervised run that
 * reads the target and writes nothing. Discovery reads configuration only; the
 * version probe runs when a target is opened.
 */
export class ParanoiaProvider implements AnalysisProviderCandidate {
  readonly #environment: Readonly<NodeJS.ProcessEnv>;
  readonly #launcher: ParanoiaProcessLauncher | undefined;
  /** Executable identity recorded with each profile digest, checked before every run. */
  readonly #identities = new Map<string, string>();

  constructor(
    environment: Readonly<NodeJS.ProcessEnv>,
    options: { readonly launcher?: ParanoiaProcessLauncher } = {},
  ) {
    this.#environment = snapshotEnvironment(environment);
    this.#launcher = options.launcher;
  }

  identity() {
    return PARANOIA_PROVIDER_IDENTITY;
  }

  capabilities() {
    const availability = this.inspectAvailability();
    return paranoiaCapabilities(
      availability.status === "available"
        ? { available: true }
        : {
            available: false,
            reason: availability.reason,
            code: availability.code,
          },
    );
  }

  inspectAvailability(): ProviderAvailability {
    const configuration = readParanoiaConfiguration(this.#environment);
    if (!configuration.ok)
      return {
        status: "unavailable",
        code: configuration.error.code,
        reason: configuration.error.reason,
        diagnostics: {
          configured: this.#environment["REA_PARANOIA_COMMAND"] !== undefined,
          version_probed: false,
        },
      };
    const { command } = configuration.value;
    try {
      accessSync(command, constants.X_OK);
      if (!statSync(command).isFile()) throw new Error("not a regular file");
    } catch (cause: unknown) {
      return {
        status: "unavailable",
        code: "executable_missing",
        reason: `Cannot execute REA_PARANOIA_COMMAND ${command}: ${cause instanceof Error ? cause.message : String(cause)}. ${PARANOIA_COMMAND_REMEDIATION}`,
        diagnostics: { configured: true, command, version_probed: false },
      };
    }
    return {
      status: "available",
      code: null,
      reason: null,
      diagnostics: {
        configured: true,
        command,
        timeout_ms: configuration.value.timeoutMs,
        version_probed: false,
      },
    };
  }

  inspectTargetSupport(target: BinaryTarget): ProviderTargetSupport {
    const diagnostics = {
      target_kind: target.kind,
      target_format: target.format,
    };
    if (target.kind !== "executable")
      return {
        status: "unsupported",
        code: "target_kind_unsupported",
        reason:
          "Paranoia analyses executable images, not databases or archives.",
        diagnostics,
      };
    if (!FORMATS.has(target.format))
      return {
        status: "unsupported",
        code: "target_format_unsupported",
        reason:
          target.format === "mach-o-universal"
            ? "Open one slice of the universal Mach-O; REA's Paranoia provider does not pick a slice yet."
            : `Paranoia loads PE, ELF and thin Mach-O images; ${target.format} is not supported.`,
        diagnostics,
      };
    if (!ARCHITECTURES.has(target.architecture))
      return {
        status: "unsupported",
        code: "architecture_unsupported",
        reason: `Paranoia disassembles x86, x86-64, AArch64, ARM, RISC-V, MIPS and PowerPC; ${target.architecture} is not supported.`,
        diagnostics: { ...diagnostics, architecture: target.architecture },
      };
    return { status: "supported", code: null, reason: null, diagnostics };
  }

  /** Probe `paranoia --version` and hash the executable, so every answer names the build that produced it. */
  async resolveAnalysisProfile(
    _target: BinaryTarget,
    options?: AnalysisProfileResolutionOptions,
  ): Promise<Result<AnalysisProfileResolution, AnalysisError>> {
    if (options?.signal?.aborted === true)
      return err(cancelled(options.signal.reason));
    const configuration = readParanoiaConfiguration(this.#environment);
    if (!configuration.ok)
      return err(unavailable("open_binary", configuration.error.reason));
    const { command } = configuration.value;
    const version = await probeVersion(
      command,
      options?.signal,
      this.#launcher,
    );
    if (!version.ok) return version;
    const hashed = await hashExecutable(command, options);
    if (!hashed.ok) return hashed;
    const profile = createAnalysisProfile(
      { ...PARANOIA_PROVIDER_IDENTITY, version: version.value },
      {
        paranoia_version: version.value,
        paranoia_sha256: hashed.value.sha256,
        query_format: PARANOIA_QUERY_FORMAT,
        cache_policy: "snapshot",
      },
    );
    this.#identities.set(profile.digest, hashed.value.identity);
    return ok({ profile });
  }

  createClient(
    target: BinaryTarget,
    profile?: AnalysisProfileCommitment,
  ): AnalysisClient {
    const configuration = readParanoiaConfiguration(this.#environment);
    if (!configuration.ok)
      return {
        execute: async (operation) =>
          err(unavailable(operation, configuration.error.reason)),
        close: async () => ok(null),
      };
    return new ParanoiaSessionClient(target, profile, {
      configuration: configuration.value,
      executableIdentity:
        profile === undefined
          ? undefined
          : this.#identities.get(profile.digest),
      launcher: this.#launcher,
    });
  }
}
