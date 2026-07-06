// Build the proveEligibility witness inputs from a demo credential bundle + the user's XRPL account.
// The credential must be the one sealed into the deployed contract's Merkle root (see .demo-deploy.json).
import {
  fromHex,
  toHex,
  jurisdictionToUint,
  xrplAddressToBytes32,
  randomBytes32,
  requestCommitment,
} from "@mxrpl/private-credential-core";
import { createGatewayPrivateState } from "../midnight/contract.ts";

export interface DemoCredential {
  holderSecretHex: string;
  credentialIdHex: string;
  issuerRandomnessHex: string;
  birthYear: number;
  jurisdiction: string;
  schemaVersion: number;
  validUntil: number;
  merkleSiblingsHex: string[];
  merkleGoesLeft: boolean[];
}

export interface ProveRequest {
  witnessInputs: Parameters<typeof createGatewayPrivateState>[0];
  requestCommitmentHex: string;
  requestNonceHex: string;
}

const HEX32 = /^[0-9a-fA-F]{64}$/; // exactly 32 bytes
function assertHex32(v: unknown, name: string): void {
  if (typeof v !== "string" || !HEX32.test(v)) {
    const got = typeof v === "string" ? `"${v}" (${v.length} chars)` : typeof v;
    throw new Error(`${name} must be 64 hex characters. Got ${got}.`);
  }
}

/** Parse a pasted credential JSON; tolerates either the bare credential or the full .demo-deploy.json. */
export function parseCredential(json: string): DemoCredential {
  let obj: Record<string, unknown>;
  try {
    obj = JSON.parse(json) as Record<string, unknown>;
  } catch (e) {
    throw new Error(`Credential JSON is invalid. ${e instanceof Error ? e.message : "Check for extra commas or quotes."}`);
  }
  const c = (obj.credential ?? obj) as DemoCredential;
  if (!c.holderSecretHex || !Array.isArray(c.merkleSiblingsHex)) {
    throw new Error("This does not look like a credential bundle. Make sure you pasted the full credential JSON, not just a partial object.");
  }
  // Exactly 16 siblings + 16 flags, both REAL arrays — a truncated/malformed paste otherwise falls
  // through to a cryptic deep-circuit error ("expected Vector<16, Bytes<32>>").
  if (c.merkleSiblingsHex.length !== 16 || !Array.isArray(c.merkleGoesLeft) || c.merkleGoesLeft.length !== 16) {
    const siblingCount = c.merkleSiblingsHex.length;
    const leftCount = Array.isArray(c.merkleGoesLeft) ? c.merkleGoesLeft.length : 0;
    throw new Error(
      `Credential is incomplete or malformed. Expected 16 merkle siblings and 16 left/right flags, but got ${siblingCount} siblings and ${leftCount} flags. ` +
        `Make sure you did not truncate the credential when pasting.`,
    );
  }
  // Byte fields must be exactly 32-byte hex — otherwise fromHex yields wrong-width bytes that only fail
  // later in the circuit. Validate at the boundary instead.
  assertHex32(c.holderSecretHex, "holderSecretHex");
  assertHex32(c.credentialIdHex, "credentialIdHex");
  assertHex32(c.issuerRandomnessHex, "issuerRandomnessHex");
  c.merkleSiblingsHex.forEach((s, i) => assertHex32(s, `merkleSiblingsHex[${i}]`));
  if (!c.merkleGoesLeft.every((b) => typeof b === "boolean")) {
    throw new Error("merkleGoesLeft must be an array of true/false values, not other types");
  }
  return c;
}

export function buildProveRequest(cred: DemoCredential, xrplAccount: string, policyEpoch = 1): ProveRequest {
  const xrplAccountId = xrplAddressToBytes32(xrplAccount);
  const requestNonce = randomBytes32();
  const witnessInputs = {
    holderSecret: fromHex(cred.holderSecretHex),
    credentialId: fromHex(cred.credentialIdHex),
    issuerRandomness: fromHex(cred.issuerRandomnessHex),
    schemaVersion: BigInt(cred.schemaVersion),
    birthYear: BigInt(cred.birthYear),
    jurisdiction: jurisdictionToUint(cred.jurisdiction),
    validUntil: BigInt(cred.validUntil),
    merkleSiblings: cred.merkleSiblingsHex.map(fromHex),
    merkleGoesLeft: cred.merkleGoesLeft,
    xrplAccountId,
    requestNonce,
  } as Parameters<typeof createGatewayPrivateState>[0];
  return {
    witnessInputs,
    requestCommitmentHex: toHex(requestCommitment({ xrplAccountId32: xrplAccountId, requestNonce, policyEpoch })),
    requestNonceHex: toHex(requestNonce),
  };
}
