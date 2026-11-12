import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { basename } from "node:path";

import { describe, expect, it } from "vitest";

import { ArtifactResourceScope } from "../../../../src/artifacts/ArtifactResourceScope.js";
import type {
  AnalysisClient,
  FileCloseResourceOwner,
} from "../../../../src/application/AnalysisProvider.js";
import type { BinaryTarget } from "../../../../src/domain/binaryTargetTypes.js";
import type { JsonValue } from "../../../../src/domain/jsonValue.js";
import { readParanoiaConfiguration } from "../../../../src/paranoia/ParanoiaConfiguration.js";
import { inspectParanoiaProvider } from "../../../../src/paranoia/ParanoiaDoctor.js";
import { ParanoiaProvider } from "../../../../src/paranoia/ParanoiaProvider.js";
import { normalizeParanoiaAddress } from "../../../../src/paranoia/ParanoiaSessionClient.js";

const withFileCloseOwner = async <T>(
  operation: (owner: FileCloseResourceOwner) => Promise<T>,
): Promise<T> => {
  const scope = new ArtifactResourceScope();
  const owner: FileCloseResourceOwner = {
    retain: (handle, resource) =>
      scope.retain({
        kind: "lease",
        resource,
        lease: { release: () => handle.close() },
      }),
    run: (work) => scope.run(work),
  };
  try {
    return await operation(owner);
  } finally {
    await scope.close();
  }
};

const executable = (
  path: string,
  sha256: string,
  format: "pe" | "elf" | "mach-o" = "pe",
): BinaryTarget => {
  const common = {
    path,
    sha256,
    kind: "executable",
    architecture: "x86_64",
    availableArchitectures: ["x86_64"],
  } as const;
  return format === "pe"
    ? { ...common, format, executableRole: "application", managed: false }
    : { ...common, format };
};

describe("Paranoia provider without a process", () => {
  it("reads its configuration fail-closed", () => {
    expect(readParanoiaConfiguration({})).toMatchObject({
      ok: false,
      error: { code: "not_configured" },
    });
    expect(
      readParanoiaConfiguration({ REA_PARANOIA_COMMAND: "paranoia" }),
    ).toMatchObject({ ok: false });
    const absolute =
      process.platform === "win32"
        ? "C:\\tools\\paranoia.exe"
        : "/opt/paranoia";
    expect(
      readParanoiaConfiguration({
        REA_PARANOIA_COMMAND: absolute,
        REA_PARANOIA_TIMEOUT_MS: "0",
      }),
    ).toMatchObject({ ok: false });
    expect(
      readParanoiaConfiguration({
        REA_PARANOIA_COMMAND: absolute,
        REA_PARANOIA_TIMEOUT_MS: "5000",
      }),
    ).toEqual({
      ok: true,
      value: { command: absolute, timeoutMs: 5000 },
    });
  });

  it("reports itself unavailable, with every capability, when not configured", () => {
    const provider = new ParanoiaProvider({});
    expect(provider.inspectAvailability()).toMatchObject({
      status: "unavailable",
      code: "not_configured",
    });
    const capabilities = provider.capabilities();
    expect(capabilities.map((c) => c.operation)).toContain(
      "procedure_pseudo_code",
    );
    expect(
      capabilities.every(
        (c) =>
          !c.available &&
          !c.effects.mutatesArtifact &&
          !c.effects.mayAccessNetwork,
      ),
    ).toBe(true);
  });

  it("admits PE, ELF and thin Mach-O executables only", () => {
    const provider = new ParanoiaProvider({});
    expect(
      provider.inspectTargetSupport(executable("/x", "0".repeat(64), "pe"))
        .status,
    ).toBe("supported");
    expect(
      provider.inspectTargetSupport(executable("/x", "0".repeat(64), "elf"))
        .status,
    ).toBe("supported");
    expect(
      provider.inspectTargetSupport({
        ...executable("/x", "0".repeat(64)),
        format: "mach-o-universal",
      } as unknown as BinaryTarget),
    ).toMatchObject({
      status: "unsupported",
      code: "target_format_unsupported",
    });
  });

  it("normalises addresses the way Paranoia prints them", () => {
    expect(normalizeParanoiaAddress("0x0000401000")).toBe("0x401000");
    expect(normalizeParanoiaAddress("0X401ABC")).toBe("0x401abc");
    expect(normalizeParanoiaAddress("401000")).toBeUndefined();
    expect(normalizeParanoiaAddress(4198400)).toBeUndefined();
  });
});

// A real paranoia binary and a target: REA_PARANOIA_COMMAND=/abs/paranoia REA_PARANOIA_TEST_TARGET=/abs/file.
const command = process.env["REA_PARANOIA_COMMAND"];
const targetPath = process.env["REA_PARANOIA_TEST_TARGET"];

const live = command !== undefined && targetPath !== undefined;

const liveTarget = (): BinaryTarget => {
  const bytes = readFileSync(targetPath ?? "");
  const sha256 = createHash("sha256").update(bytes).digest("hex");
  const format: "pe" | "elf" | "mach-o" =
    bytes.subarray(0, 2).toString("latin1") === "MZ"
      ? "pe"
      : bytes[0] === 0x7f
        ? "elf"
        : "mach-o";
  return executable(targetPath ?? "", sha256, format);
};

const open = async (
  t: BinaryTarget,
): Promise<{ client: AnalysisClient; version: string | null }> => {
  const provider = new ParanoiaProvider({
    REA_PARANOIA_COMMAND: command ?? "",
  });
  expect(provider.inspectAvailability().status).toBe("available");
  const profile = await withFileCloseOwner((fileCloseResources) =>
    provider.resolveAnalysisProfile(t, { fileCloseResources }),
  );
  if (!profile.ok || profile.value.profile === null)
    throw new Error(`profile: ${JSON.stringify(profile)}`);
  return {
    client: provider.createClient(t, profile.value.profile),
    version: profile.value.profile.provider.version,
  };
};

const run = async (
  client: AnalysisClient,
  operation: string,
  parameters: Record<string, JsonValue> = {},
) => {
  const r = await client.execute(operation as never, parameters);
  if (!r.ok) throw new Error(`${operation}: ${r.error.message}`);
  return r.value;
};

describe.skipIf(!live)("Paranoia provider against a real paranoia", () => {
  const target = live ? liveTarget() : executable("", "");

  it("answers every operation it advertises, with provenance", async () => {
    const { client, version } = await open(target);
    try {
      expect(version).toMatch(/^\d+\.\d+\.\d+/u);
      const docs = await run(client, "list_documents");
      expect(docs.result).toEqual([targetPath]);

      const procedures = (await run(client, "list_procedures")).result as {
        address: string;
        value: string;
      }[];
      expect(procedures.length).toBeGreaterThan(10);
      expect(
        procedures.every(
          (p) => normalizeParanoiaAddress(p.address) === p.address,
        ),
      ).toBe(true);

      // The procedure with most callees exercises calls, pseudocode and assembly together.
      let busiest = procedures[0]!;
      let most = -1;
      for (const p of procedures.slice(0, 400)) {
        const callees = (
          await run(client, "procedure_callees", { procedure: p.address })
        ).result as string[];
        if (callees.length > most) [busiest, most] = [p, callees.length];
      }
      expect(most).toBeGreaterThan(0);
      const callees = (
        await run(client, "procedure_callees", { procedure: busiest.value })
      ).result as string[];
      const callee = callees.find((c) =>
        procedures.some((p) => p.address === c),
      );
      if (callee !== undefined) {
        const callers = (
          await run(client, "procedure_callers", { procedure: callee })
        ).result as string[];
        expect(callers).toContain(busiest.address);
        const xrefs = (await run(client, "xrefs", { address: callee }))
          .result as string[];
        expect(xrefs.length).toBeGreaterThan(0);
      }

      expect(
        (await run(client, "procedure_address", { procedure: busiest.value }))
          .result,
      ).toBe(busiest.address);
      expect(
        (await run(client, "address_name", { address: busiest.address }))
          .result,
      ).toBe(busiest.value);
      const assembly = await run(client, "procedure_assembly", {
        procedure: busiest.address,
      });
      expect(assembly.result).toContain(busiest.address);
      expect(assembly.provider).toMatchObject({ id: "paranoia", version });
      expect(assembly.limitations.length).toBeGreaterThan(0);
      expect(assembly.locations).toContainEqual({
        kind: "address",
        address: busiest.address,
      });
      const pseudo = await run(client, "procedure_pseudo_code", {
        procedure: busiest.address,
      });
      expect(pseudo.result === null || typeof pseudo.result === "string").toBe(
        true,
      );

      const found = (
        await run(client, "search_procedures", {
          pattern: busiest.value,
          mode: "literal",
          case_sensitive: true,
        })
      ).result;
      expect(found).toContainEqual({
        address: busiest.address,
        value: busiest.value,
      });
      const strings = (await run(client, "list_strings")).result as {
        address: string;
        value: string;
      }[];
      expect(strings.length).toBeGreaterThan(0);
      const regex = (
        await run(client, "search_strings", {
          pattern: "^[A-Za-z]{4}",
          mode: "regex",
          case_sensitive: false,
        })
      ).result as unknown[];
      expect(regex.length).toBeGreaterThan(0);

      const unknown = await client.execute("procedure_pseudo_code", {
        procedure: "no_such_function_here",
      });
      expect(unknown.ok).toBe(false);
      const other = await client.execute("list_segments", {});
      expect(other).toMatchObject({ ok: false });
    } finally {
      expect(await client.close()).toEqual({ ok: true, value: null });
    }
  }, 300_000);
});

describe.skipIf(!live)("Paranoia provider sessions", () => {
  const target = live ? liveTarget() : executable("", "");

  it("refuses answers about other bytes than the selected target", async () => {
    const { client } = await open({ ...target, sha256: "f".repeat(64) });
    try {
      const r = await client.execute("list_procedures", {});
      expect(r.ok).toBe(false);
      if (!r.ok)
        expect(
          r.error.message +
            String((r.error as { userMessage?: string }).userMessage),
        ).toMatch(/changed after it was opened/u);
    } finally {
      await client.close();
    }
  }, 120_000);

  it("a closed session answers nothing", async () => {
    const { client } = await open(target);
    await client.close();
    const r = await client.execute("list_procedures", {});
    expect(r.ok).toBe(false);
    void basename;
  }, 120_000);
});

describe("Paranoia doctor", () => {
  it("reports a missing configuration as a missing engine", async () => {
    const inspection = await withFileCloseOwner((fileCloseResources) =>
      inspectParanoiaProvider({}, { fileCloseResources }),
    );
    expect(inspection).toMatchObject({
      id: "paranoia",
      configured: false,
      available: false,
      checks: [
        {
          name: "installation",
          ok: false,
          classification: "missing_analysis_engine",
        },
      ],
    });
  });

  it.skipIf(!live)(
    "reports the real executable's version and hash",
    async () => {
      const inspection = await withFileCloseOwner((fileCloseResources) =>
        inspectParanoiaProvider(
          { REA_PARANOIA_COMMAND: command ?? "" },
          { fileCloseResources },
        ),
      );
      expect(inspection.available).toBe(true);
      expect(inspection.providerVersion).toMatch(/^\d+\.\d+\.\d+/u);
      expect(inspection.checks[0]?.details?.["sha256"]).toMatch(
        /^[0-9a-f]{64}$/u,
      );
      expect(inspection.registrationEnvironment).toEqual({
        REA_PARANOIA_COMMAND: command,
      });
    },
    60_000,
  );
});
