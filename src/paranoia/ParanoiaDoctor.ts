import type { FileCloseResourceOwner } from "../application/AnalysisProvider.js";
import type {
  DoctorProviderCheck,
  DoctorProviderInspection,
} from "../application/Doctor.js";
import { readParanoiaConfiguration } from "./ParanoiaConfiguration.js";
import {
  hashExecutable,
  ParanoiaProvider,
  probeVersion,
} from "./ParanoiaProvider.js";
import {
  PARANOIA_COMMAND_REMEDIATION,
  PARANOIA_PROVIDER_ID,
  PARANOIA_QUERY_FORMAT,
} from "./ParanoiaRelease.js";

/** Settings a registration may carry; only those the caller set explicitly. */
const REGISTRATION_SETTINGS = [
  "REA_PARANOIA_COMMAND",
  "REA_PARANOIA_TIMEOUT_MS",
] as const;

const failed = (
  configured: boolean,
  code: string,
  detail: string,
): DoctorProviderInspection => ({
  id: PARANOIA_PROVIDER_ID,
  configured,
  available: false,
  providerVersion: null,
  registrationEnvironment: {},
  checks: [
    {
      name: "installation",
      ok: false,
      code,
      detail,
      remediation: PARANOIA_COMMAND_REMEDIATION,
      classification: configured ? "config_drift" : "missing_analysis_engine",
    } satisfies DoctorProviderCheck,
  ],
});

/**
 * Project Paranoia readiness into the doctor contract. Runs `paranoia --version`
 * and hashes the executable; reads nothing else and writes nothing.
 */
export const inspectParanoiaProvider = async (
  environment: Readonly<NodeJS.ProcessEnv>,
  options: {
    readonly fileCloseResources: FileCloseResourceOwner;
    readonly signal?: AbortSignal | undefined;
  },
): Promise<DoctorProviderInspection> => {
  const configured = (environment["REA_PARANOIA_COMMAND"] ?? "") !== "";
  const availability = new ParanoiaProvider(environment).inspectAvailability();
  if (availability.status === "unavailable")
    return failed(configured, availability.code, availability.reason);
  const configuration = readParanoiaConfiguration(environment);
  if (!configuration.ok)
    return failed(
      configured,
      configuration.error.code,
      configuration.error.reason,
    );
  const { command, timeoutMs } = configuration.value;
  const version = await probeVersion(command, options.signal, undefined);
  if (!version.ok)
    return failed(configured, "version_unresolved", version.error.message);
  const hashed = await hashExecutable(command, {
    fileCloseResources: options.fileCloseResources,
    ...(options.signal === undefined ? {} : { signal: options.signal }),
  });
  if (!hashed.ok)
    return failed(configured, "executable_missing", hashed.error.message);
  return {
    id: PARANOIA_PROVIDER_ID,
    configured,
    available: true,
    providerVersion: version.value,
    registrationEnvironment: Object.fromEntries(
      REGISTRATION_SETTINGS.flatMap((name) => {
        const setting = environment[name];
        return setting === undefined ? [] : [[name, setting]];
      }),
    ),
    checks: [
      {
        name: "installation",
        ok: true,
        code: null,
        detail: `${command} reports Paranoia ${version.value} (sha256 ${hashed.value.sha256}); answers are read in ${PARANOIA_QUERY_FORMAT}, each run within ${String(timeoutMs)} ms.`,
        remediation: null,
        classification: "config_drift",
        details: {
          executable: command,
          version: version.value,
          sha256: hashed.value.sha256,
          query_format: PARANOIA_QUERY_FORMAT,
          timeout_ms: timeoutMs,
        },
      },
    ],
  };
};
