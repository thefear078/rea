import { isAbsolute } from "node:path";

import type { ProviderRejectionCode } from "../contracts/providerSelection.js";
import { err, ok, type Result } from "../domain/result.js";
import { PARANOIA_COMMAND_REMEDIATION } from "./ParanoiaRelease.js";

/** Deadline for one `paranoia query` run: analysis plus one answer. */
const DEFAULT_TIMEOUT_MS = 120_000;
const MAX_TIMEOUT_MS = 60 * 60 * 1000;

/** Bytes of one answer REA buffers. An inventory costs ~150 bytes per function and string. */
export const PARANOIA_OUTPUT_BYTES = 256 * 1024 * 1024;

export interface ParanoiaConfiguration {
  readonly command: string;
  readonly timeoutMs: number;
}

export interface ParanoiaConfigurationError {
  readonly code: Extract<ProviderRejectionCode, "not_configured">;
  readonly reason: string;
}

/** Read the bring-your-own executable and its deadline from the environment REA started with. */
export const readParanoiaConfiguration = (
  environment: Readonly<NodeJS.ProcessEnv>,
): Result<ParanoiaConfiguration, ParanoiaConfigurationError> => {
  const command = environment["REA_PARANOIA_COMMAND"];
  if (command === undefined || command.trim() === "")
    return err({
      code: "not_configured",
      reason: `REA_PARANOIA_COMMAND is not set. ${PARANOIA_COMMAND_REMEDIATION}`,
    });
  if (!isAbsolute(command))
    return err({
      code: "not_configured",
      reason: `REA_PARANOIA_COMMAND must be an absolute path, not ${command}. ${PARANOIA_COMMAND_REMEDIATION}`,
    });
  const rawTimeout = environment["REA_PARANOIA_TIMEOUT_MS"];
  let timeoutMs = DEFAULT_TIMEOUT_MS;
  if (rawTimeout !== undefined && rawTimeout.trim() !== "") {
    const parsed = Number(rawTimeout);
    if (!Number.isSafeInteger(parsed) || parsed < 1 || parsed > MAX_TIMEOUT_MS)
      return err({
        code: "not_configured",
        reason: `REA_PARANOIA_TIMEOUT_MS must be a whole number of milliseconds between 1 and ${String(MAX_TIMEOUT_MS)}, not ${rawTimeout}.`,
      });
    timeoutMs = parsed;
  }
  return ok({ command, timeoutMs });
};
