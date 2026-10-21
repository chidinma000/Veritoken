import { describe, it, expect } from "vitest";
import { nativeToScVal, Contract, type rpc } from "@stellar/stellar-sdk";
import { parseEvent, parseEvents, filterByName, type ParsedEvent } from "./eventParser.js";

const CONTRACT_ID = "CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA";
const ALICE = "GBQG2SJ7MXUH34SI3MJ2I256I5UMGM2QSQZM77YFX5S6JOHXUQJEPC3A";
const BOB = "GAQWW5UBJVPNKMM5NLAIBEL6QK24ODXABL7YAXBN6KNMH3OYNM5JXT35";

function rawEvent(topics: unknown[], value: unknown, overrides: Record<string, unknown> = {}) {
  return {
    id: "0000000001-0000000000",
    type: "contract",
    ledger: 12345,
    ledgerClosedAt: "2026-01-01T00:00:00Z",
    pagingToken: "12345-0",
    inSuccessfulContractCall: true,
    txHash: "abc123",
    contractId: new Contract(CONTRACT_ID),
    topic: topics.map((t) => nativeToScVal(t as never)),
    value: nativeToScVal(value as never),
    ...overrides,
  } as any;
}

describe("parseEvent — known event schema", () => {
  it("decodes transfer: addresses from topics, amount/timestamp from data", () => {
    const e = parseEvent(rawEvent(["transfer", ALICE, BOB], [nativeToScVal(500n, { type: "i128" }), nativeToScVal(999n, { type: "u64" })]));
    expect(e.name).toBe("transfer");
    if (e.known && e.name === "transfer") {
      expect(e.data.from).toBe(ALICE);
      expect(e.data.to).toBe(BOB);
      expect(e.data.amount).toBe(500n);
      expect(e.data.timestamp).toBe(999n);
    }
  });

  it("decodes mint: recipient from topic, amount/timestamp from data", () => {
    const e = parseEvent(rawEvent(["mint", ALICE], [nativeToScVal(100n, { type: "i128" }), nativeToScVal(1n, { type: "u64" })]));
    expect(e.name).toBe("mint");
    if (e.known && e.name === "mint") {
      expect(e.data.to).toBe(ALICE);
      expect(e.data.amount).toBe(100n);
    }
  });

  it("decodes burn", () => {
    const e = parseEvent(rawEvent(["burn", ALICE], [nativeToScVal(20n, { type: "i128" }), nativeToScVal(2n, { type: "u64" })]));
    expect(e.name).toBe("burn");
    if (e.known && e.name === "burn") {
      expect(e.data.from).toBe(ALICE);
      expect(e.data.amount).toBe(20n);
    }
  });

  it("decodes approve", () => {
    const e = parseEvent(rawEvent(["approve", ALICE, BOB], [nativeToScVal(30n, { type: "i128" }), nativeToScVal(500, { type: "u32" })]));
    expect(e.name).toBe("approve");
    if (e.known && e.name === "approve") {
      expect(e.data.from).toBe(ALICE);
      expect(e.data.spender).toBe(BOB);
      expect(e.data.expirationLedger).toBe(500);
    }
  });

  it("decodes freeze with no data payload", () => {
    const e = parseEvent(rawEvent(["freeze", ALICE], undefined));
    expect(e.name).toBe("freeze");
    if (e.known && (e.name === "freeze" || e.name === "unfreeze")) {
      expect(e.data.addr).toBe(ALICE);
    }
  });

  it("decodes adm_set (admin transfer)", () => {
    const e = parseEvent(rawEvent(["adm_set"], [ALICE, BOB]));
    expect(e.name).toBe("adm_set");
    if (e.known && e.name === "adm_set") {
      expect(e.data.oldAdmin).toBe(ALICE);
      expect(e.data.newAdmin).toBe(BOB);
    }
  });

  it("decodes adm_prp (proposed admin + nonce)", () => {
    const e = parseEvent(rawEvent(["adm_prp"], [nativeToScVal(ALICE, { type: "address" }), nativeToScVal(7n, { type: "u64" })]));
    expect(e.name).toBe("adm_prp");
    if (e.known && e.name === "adm_prp") {
      expect(e.data.newAdmin).toBe(ALICE);
      expect(e.data.nonce).toBe(7n);
    }
  });

  it("decodes role_set / role_rev", () => {
    const assigned = parseEvent(rawEvent(["role_set"], [nativeToScVal("verifier", { type: "symbol" }), nativeToScVal(ALICE, { type: "address" }), nativeToScVal(1n, { type: "u64" })]));
    expect(assigned.name).toBe("role_set");
    if (assigned.known && assigned.name === "role_set") {
      expect(assigned.data.role).toBe("verifier");
      expect(assigned.data.holder).toBe(ALICE);
    }

    const revoked = parseEvent(rawEvent(["role_rev"], [nativeToScVal("verifier", { type: "symbol" }), nativeToScVal(2n, { type: "u64" })]));
    expect(revoked.name).toBe("role_rev");
    if (revoked.known && revoked.name === "role_rev") expect(revoked.data.role).toBe("verifier");
  });

  it("decodes kyc_stale", () => {
    const e = parseEvent(rawEvent(["kyc_stale", ALICE], [nativeToScVal(true, { type: "bool" }), nativeToScVal(1234n, { type: "u64" })]));
    expect(e.name).toBe("kyc_stale");
    if (e.known && e.name === "kyc_stale") {
      expect(e.data.addr).toBe(ALICE);
      expect(e.data.isActive).toBe(true);
      expect(e.data.expiry).toBe(1234n);
    }
  });

  it("carries through envelope metadata (id, ledger, txHash, contractId)", () => {
    const e = parseEvent(rawEvent(["mint", ALICE], [nativeToScVal(1n, { type: "i128" }), nativeToScVal(1n, { type: "u64" })]));
    expect(e.id).toBe("0000000001-0000000000");
    expect(e.ledger).toBe(12345);
    expect(e.txHash).toBe("abc123");
    expect(e.contractId).toBe(CONTRACT_ID);
  });

  it("decodes rcv_exe (recovery executed): oldAdmin (index 0) and newAdmin (index 1)", () => {
    const e = parseEvent(rawEvent(["rcv_exe"], [ALICE, BOB]));
    expect(e.name).toBe("rcv_exe");
    if (e.known && e.name === "rcv_exe") {
      expect(e.data.oldAdmin).toBe(ALICE);
      expect(e.data.newAdmin).toBe(BOB);
    }
  });

  it("decodes migrated: fromVersion (index 0) and toVersion (index 1), no nonce field", () => {
    const e = parseEvent(rawEvent(
      ["migrated"],
      [nativeToScVal(1, { type: "u32" }), nativeToScVal(2, { type: "u32" })],
    ));
    expect(e.name).toBe("migrated");
    if (e.known && e.name === "migrated") {
      expect(e.data.fromVersion).toBe(1);
      expect(e.data.toVersion).toBe(2);
      // The old, incorrect `nonce` field must not be present
      expect("nonce" in e.data).toBe(false);
      // The old, incorrect `newVersion` field must not be present
      expect("newVersion" in e.data).toBe(false);
    }
  });
});

describe("parseEvent — unknown events", () => {
  it("falls back to the raw decoded value and a string name", () => {
    const e = parseEvent(rawEvent(["some_future_event", ALICE], nativeToScVal("payload", { type: "string" })));
    expect(e.name).toBe("some_future_event");
    expect(e.data).toBe("payload");
  });

  it("returns a typed, non-null result for an unrecognised topic (#645)", () => {
    const e = parseEvent(rawEvent(["unknown_topic"], nativeToScVal(42, { type: "u32" })));
    // Must never be null/undefined for a non-empty topics array.
    expect(e).not.toBeNull();
    expect(e!.known).toBe(false);
    expect(e!.name).toBe("unknown_topic");
    // Raw data is preserved for the caller to interpret.
    expect(e!.data).toBe(42);
  });
});

describe("parseEvent — empty topics", () => {
  it("returns null for an event with an empty topics array (#623)", () => {
    const result = parseEvent(rawEvent([], undefined));
    expect(result).toBeNull();
  });

  it("does not throw on an empty topics array (#623)", () => {
    expect(() => parseEvent(rawEvent([], undefined))).not.toThrow();
  });
});

describe("asTuple — error path", () => {
  it("throws when an event with a data-bearing decoder receives null data", () => {
    // adm_prp expects a (Address, u64) tuple; passing null data must throw.
    expect(() =>
      parseEvent(rawEvent(["adm_prp"], null)),
    ).toThrow("event data is missing");
  });

  it("throws when an event with a data-bearing decoder receives undefined data", () => {
    expect(() =>
      parseEvent(rawEvent(["adm_set"], undefined)),
    ).toThrow("event data is missing");
  });
});

describe("parseEvents / filterByName", () => {
  it("parses a batch and filters by name with a narrowed type", () => {
    const events = parseEvents([
      rawEvent(["transfer", ALICE, BOB], [nativeToScVal(1n, { type: "i128" }), nativeToScVal(1n, { type: "u64" })]),
      rawEvent(["mint", ALICE], [nativeToScVal(2n, { type: "i128" }), nativeToScVal(2n, { type: "u64" })]),
      rawEvent(["transfer", BOB, ALICE], [nativeToScVal(3n, { type: "i128" }), nativeToScVal(3n, { type: "u64" })]),
    ]);
    const transfers = filterByName(events, "transfer");
    expect(transfers).toHaveLength(2);
    expect(transfers.every((t) => t.data.amount > 0n)).toBe(true);
  });
});

describe("parseEvents — unknown topic in a mixed page (#979)", () => {
  // Documented behaviour: an unrecognised topic is *preserved* as an
  // UnknownParsedEvent (known: false, raw data), never skipped or dropped.
  const page = () => [
    rawEvent(["transfer", ALICE, BOB], [nativeToScVal(10n, { type: "i128" }), nativeToScVal(1n, { type: "u64" })], { id: "1-0", pagingToken: "1-0" }),
    rawEvent(["zz_future", ALICE], [nativeToScVal(7n, { type: "u64" }), nativeToScVal("extra", { type: "string" })], { id: "2-0", pagingToken: "2-0" }),
    rawEvent(["mint", BOB], [nativeToScVal(20n, { type: "i128" }), nativeToScVal(2n, { type: "u64" })], { id: "3-0", pagingToken: "3-0" }),
  ];

  it("preserves the unknown event in place with its raw topics and data", () => {
    const events = parseEvents(page());
    expect(events.map((e) => e.id)).toEqual(["1-0", "2-0", "3-0"]);

    const unknown = events[1];
    expect(unknown.known).toBe(false);
    expect(unknown.name).toBe("zz_future");
    expect(unknown.topics).toEqual([ALICE]);
    expect(unknown.data).toEqual([7n, "extra"]);
    expect(unknown.pagingToken).toBe("2-0");
  });

  it("still fully decodes the neighbouring known events", () => {
    const [transfer, , mint] = parseEvents(page());

    expect(transfer.known).toBe(true);
    if (transfer.known && transfer.name === "transfer") {
      expect(transfer.data).toEqual({ from: ALICE, to: BOB, amount: 10n, timestamp: 1n });
    } else {
      throw new Error("expected a known transfer event");
    }

    expect(mint.known).toBe(true);
    if (mint.known && mint.name === "mint") {
      expect(mint.data).toEqual({ to: BOB, amount: 20n, timestamp: 2n });
    } else {
      throw new Error("expected a known mint event");
    }
  });

  it("is excluded from filterByName results for known names", () => {
    const events = parseEvents(page());
    expect(filterByName(events, "transfer").map((e) => e.id)).toEqual(["1-0"]);
    expect(filterByName(events, "mint").map((e) => e.id)).toEqual(["3-0"]);
  });
});

describe("parseEvents — empty event page (#978)", () => {
  // Same shape `rpc.Server.getEvents` resolves with when a cursor has no new events.
  const emptyPage = (): rpc.Api.GetEventsResponse => ({ latestLedger: 20_000, events: [] });

  it("returns an empty array without throwing", () => {
    const response = emptyPage();
    expect(() => parseEvents(response.events)).not.toThrow();
    const parsed = parseEvents(response.events);
    expect(parsed).toEqual([]);
    expect(filterByName(parsed, "transfer")).toEqual([]);
  });

  it("emits no paging token, so a poller's cursor is not advanced", () => {
    const previousCursor = "12345-0";
    const response = emptyPage();
    const parsed = parseEvents(response.events);

    // Pollers resume from the last parsed event's pagingToken; with no events
    // there is nothing to advance to, so the existing cursor must be reused.
    const nextCursor = parsed.length > 0 ? parsed[parsed.length - 1].pagingToken : previousCursor;
    expect(nextCursor).toBe(previousCursor);
    // The RPC page itself is left untouched — no synthetic events are injected.
    expect(response).toEqual({ latestLedger: 20_000, events: [] });
  });
});

// Type-level check: ParsedEvent should be assignable from parseEvent's return.
const _typeCheck: ParsedEvent = parseEvent(rawEvent(["mint", ALICE], [nativeToScVal(1n, { type: "i128" }), nativeToScVal(1n, { type: "u64" })]));
void _typeCheck;
