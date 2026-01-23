/**
 * Lux Consensus Bridge
 *
 * TypeScript types and interfaces for integrating ZAP with Lux's Quasar consensus.
 * This module provides the client-side interface for communicating with the
 * Lux node's ZAP consensus bridge.
 */

import { Did, didUri } from './identity.js';
import type { Query, Response, ConsensusResult } from './agent_consensus.js';

/**
 * Quasar signature types matching Lux consensus/quasar/types.go
 */
export enum SignatureType {
  BLS = 0,
  Ringtail = 1,
  Quasar = 2, // Hybrid BLS + Ringtail
  MLDSA = 3,
}

/**
 * Post-quantum signature types
 */
export enum PQSignatureType {
  MLDSA65 = 0,
  Ringtail = 1,
  Hybrid = 2,
}

/**
 * Bridge configuration options
 */
export interface BridgeConfig {
  /** Fraction of votes needed for consensus (default: 0.5) */
  consensusThreshold: number;
  /** Minimum responses before checking consensus (default: 1) */
  minResponses: number;
  /** Minimum votes before checking consensus (default: 3) */
  minVotes: number;
  /** Enable post-quantum signatures (default: true) */
  enablePQCrypto: boolean;
}

/**
 * Default bridge configuration
 */
export const DEFAULT_BRIDGE_CONFIG: BridgeConfig = {
  consensusThreshold: 0.5,
  minResponses: 1,
  minVotes: 3,
  enablePQCrypto: true,
};

/**
 * Bridge statistics
 */
export interface BridgeStats {
  registeredValidators: number;
  activeQueries: number;
  finalizedQueries: number;
  quasarInitialized: boolean;
  ringtailStats?: RingtailStats;
}

/**
 * Ringtail coordinator statistics
 */
export interface RingtailStats {
  numParties: number;
  threshold: number;
  initialized: boolean;
}

/**
 * Validator information
 */
export interface ValidatorInfo {
  nodeId: string;
  did: Did;
  weight: bigint;
  stake: bigint;
  active: boolean;
}

/**
 * Finality proof for a query
 */
export interface FinalityProof {
  queryId: string;
  responseId: string;
  votes: number;
  totalVoters: number;
  confidence: number;
  timestamp: number;
  signature: Uint8Array; // Quasar hybrid signature
}

/**
 * Quasar signature (hybrid BLS + Ringtail)
 */
export interface QuasarSignature {
  type: SignatureType;
  signature: Uint8Array;
  signers: string[]; // NodeIDs of signers
}

/**
 * Ringtail signature (post-quantum threshold)
 */
export interface RingtailSignature {
  signature: Uint8Array;
  signers: string[];
}

/**
 * BLS signature (classical aggregate)
 */
export interface BLSSignature {
  signature: Uint8Array;
  signers: string[];
}

// RPC response types
interface RPCResponse<T> {
  jsonrpc: string;
  id: number;
  result?: T;
  error?: {
    code: number;
    message: string;
  };
}

interface QueryIdResult {
  queryId: string;
}

interface ResponseIdResult {
  responseId: string;
}

interface FinalizedResult {
  finalized: boolean;
}

interface ConsensusResultRPC {
  response: Response | null;
  votes: number;
  totalVoters: number;
  confidence: number;
}

interface FinalityProofRPC {
  proof: {
    queryId: string;
    responseId: string;
    votes: number;
    totalVoters: number;
    confidence: number;
    timestamp: number;
    signature: string;
  } | null;
}

interface SignatureResult {
  signature: string;
  signers: string[];
}

interface VerifyResult {
  valid: boolean;
}

/**
 * Lux consensus bridge client
 *
 * Provides methods for interacting with the Lux node's ZAP consensus bridge
 * via JSON-RPC or gRPC.
 */
export class LuxConsensusBridge {
  private endpoint: string;
  private _config: BridgeConfig;

  constructor(endpoint: string, config: Partial<BridgeConfig> = {}) {
    this.endpoint = endpoint;
    this._config = { ...DEFAULT_BRIDGE_CONFIG, ...config };
  }

  /** Get the current configuration */
  get config(): BridgeConfig {
    return this._config;
  }

  /**
   * Register a validator's DID with the bridge
   */
  async registerValidator(nodeId: string, did: Did): Promise<void> {
    await this.rpc<void>('zap_registerValidator', {
      nodeId,
      did: didUri(did),
    });
  }

  /**
   * Submit a query for agentic consensus
   */
  async submitQuery(query: Query): Promise<string> {
    const result = await this.rpc<QueryIdResult>('zap_submitQuery', {
      id: query.id,
      content: query.content,
      submitter: didUri(query.submitter),
      timestamp: query.timestamp,
    });
    return result.queryId;
  }

  /**
   * Submit a response to a query
   */
  async submitResponse(response: Response): Promise<string> {
    const result = await this.rpc<ResponseIdResult>('zap_submitResponse', {
      id: response.id,
      queryId: response.queryId,
      content: response.content,
      responder: didUri(response.responder),
      timestamp: response.timestamp,
    });
    return result.responseId;
  }

  /**
   * Cast a vote for a response
   */
  async vote(queryId: string, responseId: string, voter: Did): Promise<void> {
    await this.rpc<void>('zap_vote', {
      queryId,
      responseId,
      voter: didUri(voter),
    });
  }

  /**
   * Check if a query has reached consensus
   */
  async isFinalized(queryId: string): Promise<boolean> {
    const result = await this.rpc<FinalizedResult>('zap_isFinalized', { queryId });
    return result.finalized;
  }

  /**
   * Get the consensus result for a query
   */
  async getResult(queryId: string): Promise<ConsensusResult | null> {
    const result = await this.rpc<ConsensusResultRPC>('zap_getResult', { queryId });
    if (!result.response) {
      return null;
    }
    return {
      response: result.response,
      votes: result.votes,
      totalVoters: result.totalVoters,
      confidence: result.confidence,
    };
  }

  /**
   * Get finality proof for a finalized query
   */
  async getFinalityProof(queryId: string): Promise<FinalityProof | null> {
    const result = await this.rpc<FinalityProofRPC>('zap_getFinalityProof', { queryId });
    if (!result.proof) {
      return null;
    }
    return {
      queryId: result.proof.queryId,
      responseId: result.proof.responseId,
      votes: result.proof.votes,
      totalVoters: result.proof.totalVoters,
      confidence: result.proof.confidence,
      timestamp: result.proof.timestamp,
      signature: hexToBytes(result.proof.signature),
    };
  }

  /**
   * Get bridge statistics
   */
  async stats(): Promise<BridgeStats> {
    return await this.rpc<BridgeStats>('zap_stats', {});
  }

  /**
   * Sign a message using Quasar hybrid signatures
   */
  async signWithQuasar(message: Uint8Array): Promise<QuasarSignature> {
    const result = await this.rpc<SignatureResult>('zap_signQuasar', {
      message: bytesToHex(message),
    });
    return {
      type: SignatureType.Quasar,
      signature: hexToBytes(result.signature),
      signers: result.signers,
    };
  }

  /**
   * Verify a Quasar signature
   */
  async verifyQuasar(message: Uint8Array, signature: QuasarSignature): Promise<boolean> {
    const result = await this.rpc<VerifyResult>('zap_verifyQuasar', {
      message: bytesToHex(message),
      signature: bytesToHex(signature.signature),
    });
    return result.valid;
  }

  private async rpc<T>(method: string, params: Record<string, unknown>): Promise<T> {
    const response = await fetch(this.endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: Date.now(),
        method,
        params,
      }),
    });

    if (!response.ok) {
      throw new Error(`RPC request failed: ${response.status} ${response.statusText}`);
    }

    const json = (await response.json()) as RPCResponse<T>;
    if (json.error) {
      throw new Error(`RPC error: ${json.error.message}`);
    }

    return json.result as T;
  }
}

// Helper functions
function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}

/**
 * Create a bridge client connected to a Lux node
 */
export function createBridge(endpoint: string, config?: Partial<BridgeConfig>): LuxConsensusBridge {
  return new LuxConsensusBridge(endpoint, config);
}
