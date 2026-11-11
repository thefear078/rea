import { z } from "zod";

/** Paranoia prints addresses as `0x` and lowercase hex without leading zeros. */
const address = z.string().regex(/^0x(0|[1-9a-f][0-9a-f]{0,15})$/u);

/** `paranoia query TARGET inventory` result. */
export const inventorySchema = z.object({
  functions: z.array(
    z.object({
      address,
      name: z.string(),
      size: z.number().int().nonnegative(),
      thunk: z.boolean(),
    }),
  ),
  imports: z.array(
    z.object({ address, name: z.string(), library: z.string() }),
  ),
  strings: z.array(
    z.object({
      address: address.nullable(),
      value: z.string(),
      encoding: z.string(),
    }),
  ),
  calls: z.array(z.tuple([address, address])),
});
export type Inventory = z.infer<typeof inventorySchema>;

/** `paranoia query TARGET function SEL` result; null when no function is there. */
export const functionSchema = z
  .object({
    address,
    name: z.string(),
    pseudocode: z.string().nullable(),
    assembly: z.string().nullable(),
  })
  .nullable();

/** `paranoia query TARGET xrefs SEL` result; null when the selector names nothing. */
export const xrefsSchema = z
  .object({
    address,
    references: z.array(
      z.object({ from: address, kind: z.enum(["call", "jump", "data"]) }),
    ),
  })
  .nullable();

export interface AddressedValue {
  readonly address: string;
  readonly value: string;
}

/** Facts derived once from one validated inventory. */
export interface InventoryIndex {
  readonly inventory: Inventory;
  /** Function and import names by address. */
  readonly byAddress: ReadonlyMap<string, string>;
  /** Address by name; null when two different addresses share the name. */
  readonly byName: ReadonlyMap<string, string | null>;
  readonly functionStarts: ReadonlySet<string>;
  readonly callees: ReadonlyMap<string, readonly string[]>;
  readonly callers: ReadonlyMap<string, readonly string[]>;
  readonly procedures: readonly AddressedValue[];
  /** Mapped strings only: a string without an address can't be selected or referenced. */
  readonly strings: readonly AddressedValue[];
}

export const compareAddresses = (a: string, b: string): number =>
  a.length - b.length || (a < b ? -1 : a > b ? 1 : 0);

/** `0x…` in any case and with leading zeros, as Paranoia prints it. */
export const normalizeParanoiaAddress = (
  value: unknown,
): string | undefined => {
  if (typeof value !== "string") return undefined;
  const match = /^0x0*([0-9a-f]{1,16})$/iu.exec(value);
  return match?.[1] === undefined
    ? undefined
    : `0x${BigInt(`0x${match[1]}`).toString(16)}`;
};

const nameIndex = (inventory: Inventory) => {
  const byAddress = new Map<string, string>();
  const byName = new Map<string, string | null>();
  const record = (name: string, at: string) =>
    byName.set(name, byName.has(name) && byName.get(name) !== at ? null : at);
  for (const f of inventory.functions) {
    byAddress.set(f.address, f.name);
    record(f.name, f.address);
  }
  for (const i of inventory.imports) {
    if (!byAddress.has(i.address)) byAddress.set(i.address, i.name);
    record(i.name, i.address);
  }
  return { byAddress, byName };
};

const callIndex = (inventory: Inventory) => {
  const callees = new Map<string, string[]>();
  const callers = new Map<string, string[]>();
  const add = (map: Map<string, string[]>, key: string, value: string) => {
    const list = map.get(key);
    if (list === undefined) map.set(key, [value]);
    else list.push(value);
  };
  for (const [from, to] of inventory.calls) {
    add(callees, from, to);
    add(callers, to, from);
  }
  for (const list of callees.values()) list.sort(compareAddresses);
  for (const list of callers.values()) list.sort(compareAddresses);
  return { callees, callers };
};

export const buildInventoryIndex = (inventory: Inventory): InventoryIndex => ({
  inventory,
  ...nameIndex(inventory),
  ...callIndex(inventory),
  functionStarts: new Set(inventory.functions.map((f) => f.address)),
  procedures: inventory.functions.map((f) => ({
    address: f.address,
    value: f.name,
  })),
  strings: inventory.strings.flatMap((s) =>
    s.address === null ? [] : [{ address: s.address, value: s.value }],
  ),
});
