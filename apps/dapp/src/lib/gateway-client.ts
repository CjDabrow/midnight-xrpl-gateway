// Typed client for the gateway HTTP service (POST /issue-credential). The dApp calls this AFTER the
// on-chain proof lands + the user signs the XRPL challenge.
import type { CredentialIssueRequest, IssueRecord } from "@mxrpl/gateway";
import { TIMEOUTS, TimeoutError } from "./timeout.ts";

export class GatewayServiceError extends Error {
  readonly status: number;
  readonly code: string;
  constructor(status: number, code: string, message?: string) {
    super(message ?? code);
    this.name = "GatewayServiceError";
    this.status = status;
    this.code = code;
  }
}

/**
 * fetch bounded by `TIMEOUTS.gatewayFetch`. `AbortSignal.timeout` rejects with a DOMException whose
 * message is generic/empty; since the UI surfaces `error.message`, we map that abort to a labeled
 * TimeoutError so a gateway timeout reads the same as the wallet/XRPL ones (from withTimeout).
 */
async function gatewayFetch(url: string, init: RequestInit = {}): Promise<Response> {
  try {
    return await fetch(url, { ...init, signal: AbortSignal.timeout(TIMEOUTS.gatewayFetch) });
  } catch (e) {
    if (e instanceof DOMException && e.name === "TimeoutError") {
      throw new TimeoutError(`Gateway did not respond within ${TIMEOUTS.gatewayFetch / 1000}s. The service may be offline or your connection is slow. Please check your internet and try again.`);
    }
    throw e;
  }
}

/** Request issuance of one XRPL credential from the gateway service. */
export async function requestCredential(serviceUrl: string, request: CredentialIssueRequest): Promise<IssueRecord> {
  const res = await gatewayFetch(`${serviceUrl.replace(/\/$/, "")}/issue-credential`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(request),
  });
  const body: unknown = await res.json().catch(() => ({}));
  if (!res.ok) {
    const b = body as { error?: string; message?: string };
    const statusLabel = res.status === 429 ? "rate limited (too many requests)" : `error ${res.status}`;
    throw new GatewayServiceError(res.status, b.error ?? "error", b.message ?? `Credential issuance failed (${statusLabel}): ${b.error ?? "unknown error"}`);
  }
  return body as IssueRecord;
}

export async function gatewayHealthy(serviceUrl: string): Promise<boolean> {
  try {
    const res = await gatewayFetch(`${serviceUrl.replace(/\/$/, "")}/health`);
    return res.ok;
  } catch {
    return false;
  }
}

export interface GatewayInfo {
  ok: boolean;
  contract: string;
  issuer: string; // the XRPL issuer account — needed for CredentialAccept + the gated payment
}

export async function getGatewayInfo(serviceUrl: string): Promise<GatewayInfo> {
  const res = await gatewayFetch(`${serviceUrl.replace(/\/$/, "")}/health`);
  if (!res.ok) throw new Error(`Gateway health check failed with status ${res.status}. Check that the gateway service URL is correct and the service is running.`);
  const body: unknown = await res.json().catch(() => null);
  if (!body || typeof body !== "object") throw new Error("Gateway health check did not return valid JSON. The gateway service may be misconfigured or returning an error page.");
  return body as GatewayInfo;
}
