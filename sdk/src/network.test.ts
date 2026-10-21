import { describe, it, expect, afterEach } from "vitest";
import { Networks, rpc } from "@stellar/stellar-sdk";
import {
  resolveNetworkConfig,
  createServer,
  isValidNetwork,
  InvalidNetworkConfigError,
  KNOWN_NETWORKS,
  RPC_URLS,
  NETWORK_PASSPHRASES,
} from "./network.js";

const ENV_KEYS = [
  "VERITOKEN_NETWORK",
  "STELLAR_NETWORK",
  "VITE_STELLAR_NETWORK",
  "VERITOKEN_RPC_URL",
  "SOROBAN_RPC_URL",
  "VITE_SOROBAN_RPC_URL",
  "VERITOKEN_NETWORK_PASSPHRASE",
  "STELLAR_NETWORK_PASSPHRASE",
  "VITE_STELLAR_NETWORK_PASSPHRASE",
  "VERITOKEN_RPC_ALLOW_HTTP",
];

function clearEnv() {
  for (const key of ENV_KEYS) delete process.env[key];
}

afterEach(() => {
  clearEnv();
});

describe("isValidNetwork", () => {
  it("accepts every known network", () => {
    for (const n of KNOWN_NETWORKS) expect(isValidNetwork(n)).toBe(true);
  });

  it("rejects unknown network names", () => {
    expect(isValidNetwork("devnet")).toBe(false);
    expect(isValidNetwork("")).toBe(false);
  });
});

describe("resolveNetworkConfig", () => {
  it("defaults to testnet with built-in RPC URL and passphrase", () => {
    const config = resolveNetworkConfig();
    expect(config).toEqual({
      network: "testnet",
      rpcUrl: RPC_URLS.testnet,
      networkPassphrase: NETWORK_PASSPHRASES.testnet,
      allowHttp: false,
    });
  });

  it("switches networks via an explicit override", () => {
    const config = resolveNetworkConfig({ network: "mainnet" });
    expect(config.network).toBe("mainnet");
    expect(config.rpcUrl).toBe(RPC_URLS.mainnet);
    expect(config.networkPassphrase).toBe(Networks.PUBLIC);
  });

  it("resolves futurenet defaults", () => {
    const config = resolveNetworkConfig({ network: "futurenet" });
    expect(config.rpcUrl).toBe(RPC_URLS.futurenet);
    expect(config.networkPassphrase).toBe(Networks.FUTURENET);
  });

  it("allows plain HTTP by default for standalone", () => {
    const config = resolveNetworkConfig({ network: "standalone" });
    expect(config.allowHttp).toBe(true);
    expect(config.rpcUrl.startsWith("http://")).toBe(true);
  });

  it("reads the network from an environment variable when no override is given", () => {
    process.env.STELLAR_NETWORK = "mainnet";
    const config = resolveNetworkConfig();
    expect(config.network).toBe("mainnet");
  });

  it("prefers an explicit override over an environment variable", () => {
    process.env.STELLAR_NETWORK = "mainnet";
    const config = resolveNetworkConfig({ network: "testnet" });
    expect(config.network).toBe("testnet");
  });

  it("respects env var priority order (VERITOKEN_NETWORK beats STELLAR_NETWORK)", () => {
    process.env.STELLAR_NETWORK = "mainnet";
    process.env.VERITOKEN_NETWORK = "futurenet";
    const config = resolveNetworkConfig();
    expect(config.network).toBe("futurenet");
  });

  it("reads a custom RPC URL from an environment variable", () => {
    process.env.SOROBAN_RPC_URL = "https://custom-rpc.example.com";
    const config = resolveNetworkConfig({ network: "testnet" });
    expect(config.rpcUrl).toBe("https://custom-rpc.example.com");
  });

  it("an explicit rpcUrl override wins over the environment variable", () => {
    process.env.SOROBAN_RPC_URL = "https://from-env.example.com";
    const config = resolveNetworkConfig({ network: "testnet", rpcUrl: "https://from-override.example.com" });
    expect(config.rpcUrl).toBe("https://from-override.example.com");
  });

  it("applies explicit > environment > default precedence for every field (#975)", () => {
    // Conflicting values in every environment layer.
    process.env.VERITOKEN_NETWORK = "futurenet";
    process.env.STELLAR_NETWORK = "standalone";
    process.env.VERITOKEN_RPC_URL = "https://rpc.from-env.example.com";
    process.env.SOROBAN_RPC_URL = "https://rpc.from-lower-priority-env.example.com";
    process.env.VERITOKEN_NETWORK_PASSPHRASE = "Env Passphrase ; 2026";
    process.env.VERITOKEN_RPC_ALLOW_HTTP = "true";

    // Explicit options beat every environment variable.
    expect(
      resolveNetworkConfig({
        network: "mainnet",
        rpcUrl: "https://rpc.explicit.example.com",
        networkPassphrase: "Explicit Passphrase ; 2026",
        allowHttp: false,
      }),
    ).toEqual({
      network: "mainnet",
      rpcUrl: "https://rpc.explicit.example.com",
      networkPassphrase: "Explicit Passphrase ; 2026",
      allowHttp: false,
    });

    // With no explicit options, the highest-priority environment variable wins over defaults.
    expect(resolveNetworkConfig()).toEqual({
      network: "futurenet",
      rpcUrl: "https://rpc.from-env.example.com",
      networkPassphrase: "Env Passphrase ; 2026",
      allowHttp: true,
    });

    // Fields that are neither explicit nor in the environment fall back to built-in defaults.
    clearEnv();
    expect(resolveNetworkConfig({ network: "mainnet" })).toEqual({
      network: "mainnet",
      rpcUrl: RPC_URLS.mainnet,
      networkPassphrase: NETWORK_PASSPHRASES.mainnet,
      allowHttp: false,
    });
  });

  it("reads allowHttp from an environment variable", () => {
    process.env.VERITOKEN_RPC_ALLOW_HTTP = "true";
    const config = resolveNetworkConfig({ network: "testnet" });
    expect(config.allowHttp).toBe(true);
  });

  it("throws InvalidNetworkConfigError for an unknown network name", () => {
    expect(() => resolveNetworkConfig({ network: "devnet" as never })).toThrow(InvalidNetworkConfigError);
  });

  it("throws InvalidNetworkConfigError for an unknown network name read from the environment", () => {
    process.env.STELLAR_NETWORK = "not-a-real-network";
    expect(() => resolveNetworkConfig()).toThrow(/Unknown network/);
  });

  it("throws InvalidNetworkConfigError for an empty rpcUrl override", () => {
    expect(() => resolveNetworkConfig({ rpcUrl: "   " })).toThrow(InvalidNetworkConfigError);
  });

  it("throws InvalidNetworkConfigError for an empty networkPassphrase override", () => {
    expect(() => resolveNetworkConfig({ networkPassphrase: "" })).toThrow(InvalidNetworkConfigError);
  });

  it("rejects a plain-HTTP RPC URL on a network that doesn't allow it", () => {
    expect(() =>
      resolveNetworkConfig({ network: "testnet", rpcUrl: "http://insecure.example.com" }),
    ).toThrow(/plain HTTP/);
  });

  it("accepts a plain-HTTP RPC URL when allowHttp is explicitly set", () => {
    const config = resolveNetworkConfig({
      network: "testnet",
      rpcUrl: "http://localhost:8000/soroban/rpc",
      allowHttp: true,
    });
    expect(config.allowHttp).toBe(true);
  });

  it("supports a fully custom network via explicit overrides", () => {
    const config = resolveNetworkConfig({
      network: "standalone",
      rpcUrl: "http://localhost:9000/rpc",
      networkPassphrase: "My Custom Network ; 2026",
    });
    expect(config).toEqual({
      network: "standalone",
      rpcUrl: "http://localhost:9000/rpc",
      networkPassphrase: "My Custom Network ; 2026",
      allowHttp: true,
    });
  });

  // ── Custom (unknown-named) networks — #451 ─────────────────────────────────

  it("accepts a genuinely unknown network name when rpcUrl and networkPassphrase are both explicit", () => {
    const config = resolveNetworkConfig({
      network: "my-private-devnet",
      rpcUrl: "https://rpc.my-devnet.internal",
      networkPassphrase: "My Private Devnet ; 2026",
    });
    expect(config).toEqual({
      network: "my-private-devnet",
      rpcUrl: "https://rpc.my-devnet.internal",
      networkPassphrase: "My Private Devnet ; 2026",
      allowHttp: false,
    });
  });

  it("still rejects an unknown network name missing rpcUrl", () => {
    expect(() =>
      resolveNetworkConfig({ network: "my-private-devnet", networkPassphrase: "Custom ; 2026" }),
    ).toThrow(/Unknown network/);
  });

  it("still rejects an unknown network name missing networkPassphrase", () => {
    expect(() =>
      resolveNetworkConfig({ network: "my-private-devnet", rpcUrl: "https://rpc.example.com" }),
    ).toThrow(/Unknown network/);
  });

  it("defaults allowHttp to false for a custom network even though standalone defaults to true", () => {
    const config = resolveNetworkConfig({
      network: "my-private-devnet",
      rpcUrl: "https://rpc.my-devnet.internal",
      networkPassphrase: "Custom ; 2026",
    });
    expect(config.allowHttp).toBe(false);
  });

  it("still rejects plaintext HTTP on a custom network unless allowHttp is explicit", () => {
    expect(() =>
      resolveNetworkConfig({
        network: "my-private-devnet",
        rpcUrl: "http://rpc.my-devnet.internal",
        networkPassphrase: "Custom ; 2026",
      }),
    ).toThrow(/plain HTTP/);
  });

  it("allows plaintext HTTP on a custom network when allowHttp is explicitly true", () => {
    const config = resolveNetworkConfig({
      network: "my-private-devnet",
      rpcUrl: "http://rpc.my-devnet.internal",
      networkPassphrase: "Custom ; 2026",
      allowHttp: true,
    });
    expect(config.rpcUrl).toBe("http://rpc.my-devnet.internal");
  });

  it("resolves a custom network's rpcUrl/networkPassphrase from environment variables", () => {
    process.env.VERITOKEN_RPC_URL = "https://rpc.from-env.internal";
    process.env.VERITOKEN_NETWORK_PASSPHRASE = "From Env ; 2026";
    const config = resolveNetworkConfig({ network: "my-private-devnet" });
    expect(config.rpcUrl).toBe("https://rpc.from-env.internal");
    expect(config.networkPassphrase).toBe("From Env ; 2026");
  });
});

describe("createServer", () => {
  it("builds a server from a bare network name", () => {
    const server = createServer("testnet");
    expect(server).toBeInstanceOf(rpc.Server);
  });

  it("builds a server from a full NetworkConfig", () => {
    const server = createServer(resolveNetworkConfig({ network: "mainnet" }));
    expect(server).toBeInstanceOf(rpc.Server);
  });

  it("builds a server from partial overrides, applying defaults for the rest", () => {
    const server = createServer({ network: "futurenet" });
    expect(server).toBeInstanceOf(rpc.Server);
  });

  it("propagates validation errors from resolveNetworkConfig", () => {
    expect(() => createServer({ network: "bogus" as never })).toThrow(InvalidNetworkConfigError);
  });
});
