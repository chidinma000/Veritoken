/**
 * Tests for TxPipeline, SequenceCache, and the TxError hierarchy.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import {
  Account,
  Contract,
  Networks,
  nativeToScVal,
  rpc,
  TransactionBuilder,
  type Transaction,
} from "@stellar/stellar-sdk";
import {
  TxPipeline, SequenceCache,
  SequenceError, SimulationError, SigningError,
  SubmissionError, ConfirmError, TimeoutError, TransientError,
  isTransientError, wrapCallError,
  type PipelineOptions,
} from "./pipeline.js";
import { encodeAddress, encodeI128 } from "./codec.js";

const PASSPHRASE  = Networks.TESTNET;
const CONTRACT_ID = "CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA";
const ALICE = "GBQG2SJ7MXUH34SI3MJ2I256I5UMGM2QSQZM77YFX5S6JOHXUQJEPC3A";
const BOB   = "GAQWW5UBJVPNKMM5NLAIBEL6QK24ODXABL7YAXBN6KNMH3OYNM5JXT35";
const SIM_SRC = ALICE;

const VALID_XDR = (() => {
  const acct = new Account(ALICE, "0");
  const contract = new Contract(CONTRACT_ID);
  return new TransactionBuilder(acct, { fee: "100", networkPassphrase: PASSPHRASE })
    .addOperation(contract.call("t", encodeAddress(ALICE)))
    .setTimeout(30).build().toXDR();
})();

const mockAssemble: typeof rpc.assembleTransaction = () =>
  ({
    build: () => ({ toXDR: () => VALID_XDR }),
  }) as unknown as ReturnType<typeof rpc.assembleTransaction>;
const noSleep = (_ms: number): Promise<void> => Promise.resolve();
const sign = vi.fn(async (x: string) => x);
beforeEach(() => {
  vi.clearAllMocks();
});

interface ServerOptions {
  sequence?: string;
  simError?: boolean | string;
  sendStatus?: string;
  getTxStatus?: string;
}

type MockServer = rpc.Server & {
  getAccount: ReturnType<typeof vi.fn>;
  simulateTransaction: ReturnType<typeof vi.fn>;
  sendTransaction: ReturnType<typeof vi.fn>;
  getTransaction: ReturnType<typeof vi.fn>;
};

function makeSrv(opts: ServerOptions = {}): MockServer {
  const { sequence = "10", simError = false, sendStatus = "PENDING", getTxStatus = "SUCCESS" } = opts;
  const simResp = simError
    ? { error: typeof simError === "string" ? simError : "Error(Contract, #6)", _e: true }
    : { result: { retval: nativeToScVal(42n, { type: "i128" }) }, minResourceFee: "200", latestLedger: 1000 };
  return {
    getAccount: vi.fn().mockResolvedValue({ sequence }),
    simulateTransaction: vi.fn().mockResolvedValue(simResp),
    sendTransaction: vi.fn().mockResolvedValue({ status: sendStatus, hash: "txhash_abc", errorResult: sendStatus === "ERROR" ? { msg: "bad" } : undefined }),
    getTransaction: vi.fn().mockResolvedValue({ status: getTxStatus, resultXdr: "r", resultMetaXdr: null }),
  } as unknown as MockServer;
}

function makePipeline(srv: unknown, overrides: PipelineOptions = {}) {
  return new TxPipeline(srv as rpc.Server, PASSPHRASE, {
    assemble: mockAssemble,
    sleep: noSleep,
    maxRetries: 2,
    initialBackoffMs: 0,
    confirmTimeoutMs: 10_000,
    pollIntervalMs: 0,
    ...overrides,
  });
}

describe("isTransientError", () => {
  it("recognises timeout", () => expect(isTransientError(new Error("Request timeout"))).toBe(true));
  it("recognises ECONNRESET", () => expect(isTransientError(new Error("ECONNRESET"))).toBe(true));
  it("recognises 503", () => expect(isTransientError(new Error("HTTP 503"))).toBe(true));
  it("recognises 429", () => expect(isTransientError(new Error("429 Too Many Requests"))).toBe(true));
  it("recognises ENOTFOUND (DNS failure)", () => expect(isTransientError(new Error("getaddrinfo ENOTFOUND rpc.testnet.stellar.org"))).toBe(true));
  it("recognises socket hang up", () => expect(isTransientError(new Error("socket hang up"))).toBe(true));
  it("does not flag contract errors", () => expect(isTransientError(new Error("Error(Contract, #6)"))).toBe(false));
});

describe("SimulationError — NoReturnValue classification", () => {
  it('exact lowercase "no return value" produces the short message', () => {
    const e = new SimulationError("balance", "no return value");
    expect(e.message).toBe("No return value from balance");
  });

  it('mixed-case "No return value" is still classified as NoReturnValue', () => {
    const e = new SimulationError("balance", "No return value");
    expect(e.message).toBe("No return value from balance");
  });

  it('"no return value from contract" substring match produces the short message', () => {
    const e = new SimulationError("transfer", "no return value from contract");
    expect(e.message).toBe("No return value from transfer");
  });

  it("an unrelated detail string produces the generic message", () => {
    const e = new SimulationError("transfer", "Error(Contract, #6)");
    expect(e.message).toBe("Simulation error calling transfer: Error(Contract, #6)");
  });
});

describe("SequenceCache", () => {
  it("fetches from RPC on first use", async () => {
    const srv = makeSrv({ sequence: "42" });
    const c = new SequenceCache();
    expect(await c.next(srv, ALICE)).toBe("42");
    expect(srv.getAccount).toHaveBeenCalledOnce();
  });
  it("returns cached value without re-fetching", async () => {
    const srv = makeSrv({ sequence: "42" });
    const c = new SequenceCache();
    await c.next(srv, ALICE);
    await c.next(srv, ALICE);
    expect(srv.getAccount).toHaveBeenCalledOnce();
  });
  it("advance() increments without re-fetch", async () => {
    const srv = makeSrv({ sequence: "10" });
    const c = new SequenceCache();
    await c.next(srv, ALICE);
    c.advance(ALICE);
    expect(await c.next(srv, ALICE)).toBe("11");
    expect(srv.getAccount).toHaveBeenCalledOnce();
  });
  it("advance() is a no-op when the account is absent", () => {
    const c = new SequenceCache();
    expect(() => c.advance(ALICE)).not.toThrow();
    expect(c.peek(ALICE)).toBeUndefined();
  });
  it("invalidate() forces re-fetch", async () => {
    const srv = makeSrv({ sequence: "10" });
    const c = new SequenceCache();
    await c.next(srv, ALICE);
    c.invalidate(ALICE);
    await c.next(srv, ALICE);
    expect(srv.getAccount).toHaveBeenCalledTimes(2);
  });
  it("peek() returns undefined before fetch", () => {
    expect(new SequenceCache().peek(ALICE)).toBeUndefined();
  });
  it("peek() returns cached value after fetch", async () => {
    const srv = makeSrv({ sequence: "7" });
    const c = new SequenceCache();
    await c.next(srv, ALICE);
    expect(c.peek(ALICE)).toBe("7");
  });
  it("throws SequenceError when getAccount fails", async () => {
    const srv = { getAccount: vi.fn().mockRejectedValue(new Error("rpc down")) };
    await expect(
      new SequenceCache().next(srv as unknown as rpc.Server, ALICE),
    ).rejects.toBeInstanceOf(SequenceError);
  });
  it("evicts the oldest entry once the 1000-account cap is exceeded", async () => {
    const srv = makeSrv({ sequence: "1" });
    const c = new SequenceCache();
    const accounts = Array.from({ length: 1001 }, (_, i) => `account_${i}`);
    for (const a of accounts) await c.next(srv, a);

    const present = accounts.filter((a) => c.peek(a) !== undefined);
    expect(present.length).toBe(1000);
    // The first-inserted account is the one evicted; the newest survives.
    expect(c.peek("account_0")).toBeUndefined();
    expect(c.peek("account_1000")).toBe("1");
  });
});

describe("TxPipeline.buildTx", () => {
  it("produces round-trippable XDR", () => {
    const p = makePipeline(makeSrv());
    expect(() => TransactionBuilder.fromXDR(
      p.buildTx(CONTRACT_ID, "transfer", [encodeAddress(ALICE), encodeAddress(BOB), encodeI128(1n)], ALICE, "0"),
      PASSPHRASE)).not.toThrow();
  });
  it("advances sequence by 1", () => {
    const p = makePipeline(makeSrv());
    expect(
      (
        TransactionBuilder.fromXDR(
          p.buildTx(CONTRACT_ID, "name", [], ALICE, "5"),
          PASSPHRASE,
        ) as Transaction
      ).sequence,
    ).toBe("6");
  });
});

describe("TxPipeline.read", () => {
  it("returns decoded value on success", async () => {
    const { value } = await makePipeline(makeSrv()).read(CONTRACT_ID, "balance", [encodeAddress(ALICE)], SIM_SRC);
    expect(value).toBe(42n);
  });
  it("throws SimulationError on contract error response", async () => {
    const orig = rpc.Api.isSimulationError;
    (rpc.Api as any).isSimulationError = (r: any) => Boolean(r._e);
    await expect(makePipeline(makeSrv({ simError: true })).read(CONTRACT_ID, "balance", [], SIM_SRC)).rejects.toBeInstanceOf(SimulationError);
    (rpc.Api as any).isSimulationError = orig;
  });
  it("throws SimulationError when no retval", async () => {
    const srv = { simulateTransaction: vi.fn().mockResolvedValue({ result: undefined, latestLedger: 1000 }) };
    await expect(makePipeline(srv).read(CONTRACT_ID, "name", [], SIM_SRC)).rejects.toBeInstanceOf(SimulationError);
  });
  it("retries transient errors", async () => {
    let n = 0;
    const srv = { simulateTransaction: vi.fn().mockImplementation(() => {
      if (++n < 3) throw new Error("timeout");
      return Promise.resolve({ result: { retval: nativeToScVal(1n, { type: "i128" }) }, latestLedger: 1000 });
    })};
    const { value } = await makePipeline(srv, { maxRetries: 3 }).read(CONTRACT_ID, "balance", [], SIM_SRC);
    expect(value).toBe(1n);
    expect(n).toBe(3);
  });
  it("throws TransientError after max retries", async () => {
    const srv = { simulateTransaction: vi.fn().mockRejectedValue(new Error("ECONNRESET")) };
    await expect(makePipeline(srv, { maxRetries: 2 }).read(CONTRACT_ID, "balance", [], SIM_SRC)).rejects.toBeInstanceOf(TransientError);
  });
});

describe("TxPipeline.write — success", () => {
  it("returns txHash, SUCCESS status, retries=0 on first attempt", async () => {
    const r = await makePipeline(makeSrv()).write(CONTRACT_ID, "transfer", [encodeAddress(ALICE), encodeAddress(BOB), encodeI128(1n)], ALICE, sign);
    expect(r.txHash).toBe("txhash_abc");
    expect(r.response.status).toBe("SUCCESS");
    expect(r.retries).toBe(0);
  });
  it("calls sign exactly once with non-empty string", async () => {
    await makePipeline(makeSrv()).write(CONTRACT_ID, "mint", [encodeAddress(ALICE), encodeI128(1n)], ALICE, sign);
    expect(sign).toHaveBeenCalledOnce();
    expect(sign.mock.calls[0][0].length).toBeGreaterThan(0);
  });
  it("advances sequence cache after success; second write skips getAccount", async () => {
    const srv = makeSrv({ sequence: "5" });
    const p = makePipeline(srv);
    await p.write(CONTRACT_ID, "t", [encodeAddress(ALICE), encodeAddress(BOB), encodeI128(1n)], ALICE, sign);
    expect(p.sequenceCache.peek(ALICE)).toBe("6");
    await p.write(CONTRACT_ID, "t", [encodeAddress(ALICE), encodeAddress(BOB), encodeI128(1n)], ALICE, sign);
    expect(srv.getAccount).toHaveBeenCalledOnce();
  });
  it("does NOT re-submit after confirmed SUCCESS", async () => {
    const srv = makeSrv();
    await makePipeline(srv).write(CONTRACT_ID, "settle", [], ALICE, sign);
    expect(srv.sendTransaction).toHaveBeenCalledOnce();
  });
});

describe("TxPipeline.write — confirmation polling", () => {
  it("polls until NOT_FOUND resolves to SUCCESS", async () => {
    const srv = makeSrv();
    let n = 0;
    srv.getTransaction = vi.fn().mockImplementation(() =>
      Promise.resolve(++n < 4 ? { status: "NOT_FOUND" } : { status: "SUCCESS", resultXdr: "ok", resultMetaXdr: null }));
    const r = await makePipeline(srv).write(CONTRACT_ID, "settle", [], ALICE, sign);
    expect(r.response.status).toBe("SUCCESS");
    expect(n).toBe(4);
  });
  it("throws ConfirmError when final status is FAILED", async () => {
    const err = await makePipeline(makeSrv({ getTxStatus: "FAILED" }))
      .write(CONTRACT_ID, "t", [encodeAddress(ALICE), encodeAddress(BOB), encodeI128(1n)], ALICE, sign)
      .catch((e) => e);
    expect(err).toBeInstanceOf(ConfirmError);
    expect(err.txHash).toBe("txhash_abc");
    expect(err.finalStatus).toBe("FAILED");
  });
  it("throws TimeoutError when confirmTimeoutMs is exceeded", async () => {
    const srv = makeSrv();
    srv.getTransaction = vi.fn().mockResolvedValue({ status: "NOT_FOUND" });
    let elapsed = 0;
    const fakeSleep = (ms: number) => { elapsed += ms; return Promise.resolve(); };
    const p = makePipeline(srv, { confirmTimeoutMs: 100, pollIntervalMs: 60, sleep: fakeSleep });
    await expect(p.write(CONTRACT_ID, "t", [encodeAddress(ALICE), encodeAddress(BOB), encodeI128(1n)], ALICE, sign)).rejects.toBeInstanceOf(TimeoutError);
  });
});

describe("TxPipeline.write — error handling", () => {
  it("throws SimulationError for contract errors without retrying", async () => {
    const orig = rpc.Api.isSimulationError;
    (rpc.Api as any).isSimulationError = (r: any) => Boolean(r._e);
    const srv = makeSrv({ simError: true });
    await expect(makePipeline(srv, { maxRetries: 3 }).write(CONTRACT_ID, "t", [], ALICE, sign)).rejects.toBeInstanceOf(SimulationError);
    expect(srv.simulateTransaction).toHaveBeenCalledOnce();
    (rpc.Api as any).isSimulationError = orig;
  });
  it("throws SubmissionError when sendTransaction returns ERROR", async () => {
    await expect(makePipeline(makeSrv({ sendStatus: "ERROR" }))
      .write(CONTRACT_ID, "t", [encodeAddress(ALICE), encodeAddress(BOB), encodeI128(1n)], ALICE, sign))
      .rejects.toBeInstanceOf(SubmissionError);
  });
  it("throws SigningError when sign callback throws", async () => {
    const badSign = vi.fn().mockRejectedValue(new Error("cancelled"));
    await expect(makePipeline(makeSrv()).write(CONTRACT_ID, "t", [], ALICE, badSign)).rejects.toBeInstanceOf(SigningError);
  });
  it("throws SigningError when sign callback returns empty string", async () => {
    const emptySign = vi.fn().mockResolvedValue("");
    await expect(makePipeline(makeSrv()).write(CONTRACT_ID, "t", [], ALICE, emptySign)).rejects.toBeInstanceOf(SigningError);
  });
  it("invalidates sequence cache on transient simulation failure", async () => {
    let calls = 0;
    const srv = {
      getAccount: vi.fn().mockResolvedValue({ sequence: "5" }),
      simulateTransaction: vi.fn().mockImplementation(() => {
        if (++calls === 1) throw new Error("ECONNRESET");
        return Promise.resolve({ result: { retval: nativeToScVal(1n, { type: "i128" }) }, latestLedger: 1000 });
      }),
      sendTransaction: vi.fn().mockResolvedValue({ status: "PENDING", hash: "h" }),
      getTransaction: vi.fn().mockResolvedValue({ status: "SUCCESS", resultXdr: "r", resultMetaXdr: null }),
    };
    await makePipeline(srv, { maxRetries: 2 }).write(CONTRACT_ID, "t", [encodeAddress(ALICE), encodeAddress(BOB), encodeI128(1n)], ALICE, sign);
    expect(srv.getAccount).toHaveBeenCalledTimes(2);
  });
  it("retries transient submit errors and reports correct retry count", async () => {
    let submitN = 0;
    const srv = {
      getAccount: vi.fn().mockResolvedValue({ sequence: "0" }),
      simulateTransaction: vi.fn().mockResolvedValue({ result: { retval: nativeToScVal(1n, { type: "i128" }) }, latestLedger: 1000 }),
      sendTransaction: vi.fn().mockImplementation(() => { if (++submitN < 3) throw new Error("timeout"); return Promise.resolve({ status: "PENDING", hash: "h2" }); }),
      getTransaction: vi.fn().mockResolvedValue({ status: "SUCCESS", resultXdr: "r", resultMetaXdr: null }),
    };
    const r = await makePipeline(srv, { maxRetries: 3 }).write(CONTRACT_ID, "mint", [encodeAddress(ALICE), encodeI128(10n)], ALICE, sign);
    expect(r.retries).toBe(2);
    expect(submitN).toBe(3);
  });
  it("throws TransientError after all retries exhausted", async () => {
    const srv = { getAccount: vi.fn().mockResolvedValue({ sequence: "0" }), simulateTransaction: vi.fn().mockRejectedValue(new Error("ETIMEDOUT")) };
    const err = await makePipeline(srv, { maxRetries: 2 }).write(CONTRACT_ID, "t", [], ALICE, sign).catch((e) => e);
    expect(err).toBeInstanceOf(TransientError);
    expect(err.message).toContain("ETIMEDOUT");
  });
  it("throws SequenceError when getAccount fails", async () => {
    const srv = { getAccount: vi.fn().mockRejectedValue(new Error("not found")) };
    await expect(makePipeline(srv).write(CONTRACT_ID, "t", [], ALICE, sign)).rejects.toBeInstanceOf(SequenceError);
  });
});

describe("TxPipeline.write — failing-call identification (#642)", () => {
  it("wraps a non-transient simulation transport error with the method and contract id", async () => {
    const srv = makeSrv();
    srv.simulateTransaction = vi.fn().mockRejectedValue(new Error("boom unexpected"));
    const err = await makePipeline(srv)
      .write(CONTRACT_ID, "transfer", [], ALICE, sign)
      .catch((e) => e);
    expect(err).toBeInstanceOf(Error);
    expect(err.message).toContain("transfer");
    expect(err.message).toContain(CONTRACT_ID);
    expect(err.message).toContain("boom unexpected");
    expect((err as { cause?: Error }).cause).toBeInstanceOf(Error);
    expect((err as { cause?: Error }).cause?.message).toBe("boom unexpected");
  });

  it("names the method in the SubmissionError when the network rejects the send", async () => {
    const err = await makePipeline(makeSrv({ sendStatus: "ERROR" }))
      .write(CONTRACT_ID, "mint", [], ALICE, sign)
      .catch((e) => e);
    expect(err).toBeInstanceOf(SubmissionError);
    expect(err.message).toContain("mint");
  });

  it("surfaces a submission-stage transport failure with its method, contract, stage, and cause (#977)", async () => {
    const srv = makeSrv();
    const cause = new Error("upstream rejected payload");
    srv.sendTransaction = vi.fn().mockRejectedValue(cause);

    const err = await makePipeline(srv)
      .write(CONTRACT_ID, "burn", [encodeAddress(ALICE), encodeI128(5n)], ALICE, sign)
      .then(() => { throw new Error("expected write to reject"); }, (e) => e);

    // Not swallowed or retried as a success: the send was attempted exactly once
    // and nothing after it (confirmation polling) ran.
    expect(srv.sendTransaction).toHaveBeenCalledOnce();
    expect(srv.getTransaction).not.toHaveBeenCalled();

    // The failed stage and call are identifiable, and the original error is kept.
    expect(err).toBeInstanceOf(Error);
    expect(err.message).toBe(
      `Contract call burn on ${CONTRACT_ID} failed during submission: upstream rejected payload`,
    );
    expect((err as { cause?: unknown }).cause).toBe(cause);
  });

  it("leaves typed TxError subclasses unwrapped", () => {
    const original = new SimulationError("foo", "bad");
    expect(wrapCallError(original, "foo", CONTRACT_ID, "simulation")).toBe(original);
  });
});
