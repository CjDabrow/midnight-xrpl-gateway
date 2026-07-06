// The Midnight browser-provider connection layer. Adapted from the canonical bboard-ui
// (BrowserDeployedBoardManager, Apache-2.0) — the spike-confirmed pattern (docs/SPIKE_BROWSER_PROVING.md):
// the WALLET (1AM or Lace) supplies the prover + indexer URIs; the proving keys are fetched as static
// assets. Multi-wallet: scans window.midnight.* for any v4 connector and lets the caller pick one.
// NOTE: witnesses go to the wallet's prover (HOSTED with 1AM, LOCAL with Lace + local proof server) —
// see docs/PRIVACY_BOUNDARY.md. A proverOverride forces a local proof server even with a hosted wallet.
import { fromHex, toHex } from "@midnight-ntwrk/midnight-js-utils";
import { setNetworkId } from "@midnight-ntwrk/midnight-js-network-id";
import { ConnectedAPI, type InitialAPI } from "@midnight-ntwrk/dapp-connector-api";
import { FetchZkConfigProvider } from "@midnight-ntwrk/midnight-js-fetch-zk-config-provider";
import { httpClientProofProvider } from "@midnight-ntwrk/midnight-js-http-client-proof-provider";
import { indexerPublicDataProvider } from "@midnight-ntwrk/midnight-js-indexer-public-data-provider";
import {
  Binding,
  FinalizedTransaction,
  Proof,
  SignatureEnabled,
  Transaction,
  type TransactionId,
} from "@midnight-ntwrk/ledger-v8";
import type { UnboundTransaction } from "@midnight-ntwrk/midnight-js-types";
import semver from "semver";
import { levelPrivateStateProvider } from "@midnight-ntwrk/midnight-js-level-private-state-provider";
import { zkConfigPath, type GatewayCircuitKeys, type GatewayProviders, GatewayPrivateStateId } from "./contract.ts";
import { withTimeout, TIMEOUTS } from "../lib/timeout.ts";

const COMPATIBLE_CONNECTOR_API_VERSION = "4.x"; // 1AM ships DApp Connector v4 (window.midnight typed by the connector pkg)

export interface WalletInfo {
  /** the window.midnight key (e.g. "mnLace" / 1AM's key) — pass back to connectMidnight to choose it */
  readonly key: string;
  readonly name: string;
  readonly apiVersion: string;
}

/** All injected, v4-compatible Midnight wallets (1AM, Lace, …). Empty if none installed yet. */
export function listWallets(): WalletInfo[] {
  if (!window.midnight) return [];
  return Object.entries(window.midnight)
    .filter(([, w]) => !!w && typeof w === "object" && "apiVersion" in w && semver.satisfies((w as InitialAPI).apiVersion, COMPATIBLE_CONNECTOR_API_VERSION))
    .map(([key, w]) => ({ key, name: (w as InitialAPI).name ?? key, apiVersion: (w as InitialAPI).apiVersion }));
}

/** "local" if the prover runs on the user's machine (witnesses stay local), else "hosted". */
export function classifyProver(proverServerUri: string): "local" | "hosted" {
  return /\/\/(localhost|127\.0\.0\.1|\[::1\])(:|\/|$)/.test(proverServerUri) ? "local" : "hosted";
}

/** Poll briefly for the chosen wallet (or the first compatible one) and connect. */
async function connectToWallet(networkId: string, walletKey?: string): Promise<ConnectedAPI> {
  const pick = (): InitialAPI | undefined => {
    if (!window.midnight) return undefined;
    if (walletKey) {
      const w = window.midnight[walletKey] as InitialAPI | undefined;
      return w && semver.satisfies(w.apiVersion, COMPATIBLE_CONNECTOR_API_VERSION) ? w : undefined;
    }
    return Object.values(window.midnight).find((w) => semver.satisfies(w.apiVersion, COMPATIBLE_CONNECTOR_API_VERSION));
  };
  const deadline = 5000;
  const start = performance.now();
  for (;;) {
    const initial = pick();
    // Bound the connect: opening the wallet popup can hang forever if the user dismisses or ignores
    // it. Without this, `status` stays "connecting" and every button stays disabled with no recovery.
    if (initial) return withTimeout(initial.connect(networkId), TIMEOUTS.walletConnect, "Wallet connection");
    if (performance.now() - start > deadline) {
      const walletName = walletKey ? ` (${walletKey})` : "";
      throw new Error(`No Midnight wallet found${walletName}. Make sure you have 1AM or Lace installed and enabled as a browser extension, then refresh the page.`);
    }
    await new Promise((r) => setTimeout(r, 150));
  }
}

export interface MidnightConnection {
  readonly providers: GatewayProviders;
  readonly connectedAPI: ConnectedAPI;
  /** the prover the connected wallet reported + whether it's local (witnesses stay) or hosted. */
  readonly prover: { uri: string; kind: "local" | "hosted" };
}

/**
 * Connect the chosen wallet (1AM/Lace via `walletKey`) and assemble the browser provider set.
 * `proverOverride` forces a specific proof server (e.g. `http://localhost:6300`) for full proving
 * locality even with a hosted-prover wallet like 1AM — otherwise the wallet's reported prover is used.
 */
export async function connectMidnight(networkId: string, walletKey?: string, proverOverride?: string): Promise<MidnightConnection> {
  setNetworkId(networkId as never); // MUST run before any wallet/contract op (matches the Node harness)
  const connectedAPI = await connectToWallet(networkId, walletKey);
  // These reads are quick once the wallet is connected, but a wedged wallet can still hang them —
  // bound both so a stuck read surfaces as an error instead of a frozen "connecting" state.
  const config = await withTimeout(connectedAPI.getConfiguration(), TIMEOUTS.walletOp, "Reading wallet configuration");
  const shieldedAddresses = await withTimeout(connectedAPI.getShieldedAddresses(), TIMEOUTS.walletOp, "Reading wallet addresses");
  const keyMaterialProvider = new FetchZkConfigProvider<GatewayCircuitKeys>(zkConfigPath, fetch.bind(window));
  // The wallet may not report a prover URI (and no local override was set). Fail with a clear message
  // instead of a non-null assertion that would mislabel the prover and then fail cryptically at prove time.
  const proverUri = proverOverride ?? config.proverServerUri;
  if (!proverUri) {
    throw new Error("The connected wallet did not report a prover server URI. Set VITE_PROVER_URI (e.g. http://localhost:6300) to use a local proof server.");
  }

  const providers: GatewayProviders = {
    // level provider (IndexedDB in the browser) — its codec produces the runtime-correct shape for
    // Vector<16, Bytes<32>> witnesses (the in-memory one stored raw and broke proveEligibility). Same
    // provider the Node harness used. (example-kitties uses level in the browser too.)
    privateStateProvider: levelPrivateStateProvider<typeof GatewayPrivateStateId>({
      privateStateStoreName: "mxrpl-gateway-private-state",
      accountId: shieldedAddresses.shieldedCoinPublicKey,
      // At-rest key MUST be STABLE across sessions — the provider persists + reuses a signing key, so a
      // changing password fails to decrypt it (OperationError). A per-session random key is therefore NOT
      // viable here. Keyed off the (public) coin key; the at-rest exposure is an accepted limitation for
      // this testnet/synthetic-data demo — production needs a real user-secret-derived key. See
      // docs/KNOWN_LIMITATIONS.md. (Codex Medium finding — re-evaluated.)
      privateStoragePasswordProvider: () => btoa(shieldedAddresses.shieldedCoinPublicKey) + "!",
    }),
    zkConfigProvider: keyMaterialProvider,
    proofProvider: httpClientProofProvider(proverUri, keyMaterialProvider),
    publicDataProvider: indexerPublicDataProvider(config.indexerUri, config.indexerWsUri),
    walletProvider: {
      getCoinPublicKey: () => shieldedAddresses.shieldedCoinPublicKey,
      getEncryptionPublicKey: () => shieldedAddresses.shieldedEncryptionPublicKey,
      balanceTx: async (tx: UnboundTransaction): Promise<FinalizedTransaction> => {
        const serialized = toHex(tx.serialize());
        const received = await connectedAPI.balanceUnsealedTransaction(serialized);
        return Transaction.deserialize<SignatureEnabled, Proof, Binding>("signature", "proof", "binding", fromHex(received.tx));
      },
    },
    midnightProvider: {
      submitTx: async (tx: FinalizedTransaction): Promise<TransactionId> => {
        await connectedAPI.submitTransaction(toHex(tx.serialize()));
        return tx.identifiers()[0];
      },
    },
  };
  return { providers, connectedAPI, prover: { uri: proverUri, kind: classifyProver(proverUri) } };
}
