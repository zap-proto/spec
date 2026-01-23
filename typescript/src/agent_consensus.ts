/**
 * Agentic consensus for response voting.
 *
 * Agents vote on responses to queries. No trust needed - majority wins.
 * As long as majority are honest, you get correct results.
 */

import { Did } from './identity.js';

/** Query ID (32-byte hash as hex string) */
export type QueryId = string;

/** Response ID (32-byte hash as hex string) */
export type ResponseId = string;

/** A query submitted to the agent network */
export interface Query {
  id: QueryId;
  content: string;
  submitter: Did;
  timestamp: number;
}

/** A response to a query */
export interface Response {
  id: ResponseId;
  queryId: QueryId;
  content: string;
  responder: Did;
  timestamp: number;
}

/** Result of consensus voting */
export interface ConsensusResult {
  response: Response;
  votes: number;
  totalVoters: number;
  confidence: number;
}

/** Internal state for a query */
interface QueryState {
  query: Query;
  responses: Map<ResponseId, Response>;
  votes: Map<ResponseId, Did[]>;
  finalized: ResponseId | null;
}

/**
 * Create a query with auto-generated ID.
 */
export async function createQuery(content: string, submitter: Did): Promise<Query> {
  const timestamp = Math.floor(Date.now() / 1000);
  const encoder = new TextEncoder();
  const data = new Uint8Array([
    ...encoder.encode(content),
    ...encoder.encode(didUri(submitter)),
    ...numberToBytes(timestamp),
  ]);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const id = bufferToHex(hashBuffer);

  return { id, content, submitter, timestamp };
}

/**
 * Create a response with auto-generated ID.
 */
export async function createResponse(
  queryId: QueryId,
  content: string,
  responder: Did,
): Promise<Response> {
  const timestamp = Math.floor(Date.now() / 1000);
  const encoder = new TextEncoder();
  const data = new Uint8Array([
    ...hexToBytes(queryId),
    ...encoder.encode(content),
    ...encoder.encode(didUri(responder)),
    ...numberToBytes(timestamp),
  ]);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const id = bufferToHex(hashBuffer);

  return { id, queryId, content, responder, timestamp };
}

/**
 * Agentic consensus for response voting.
 *
 * Agents submit responses and vote. Majority wins.
 */
export class AgentConsensusVoting {
  private queries = new Map<QueryId, QueryState>();
  private threshold: number;
  private minResponses: number;
  private minVotes: number;

  /**
   * Create a new consensus instance.
   *
   * @param threshold - Fraction of votes needed (0.5 = majority)
   * @param minResponses - Minimum responses before checking consensus
   * @param minVotes - Minimum votes before checking consensus
   */
  constructor(
    threshold: number = 0.5,
    minResponses: number = 1,
    minVotes: number = 1,
  ) {
    this.threshold = Math.max(0, Math.min(1, threshold));
    this.minResponses = minResponses;
    this.minVotes = minVotes;
  }

  /** Submit a new query */
  async submitQuery(query: Query): Promise<QueryId> {
    this.queries.set(query.id, {
      query,
      responses: new Map(),
      votes: new Map(),
      finalized: null,
    });
    return query.id;
  }

  /** Submit a response to a query */
  async submitResponse(response: Response): Promise<ResponseId> {
    const state = this.queries.get(response.queryId);
    if (!state) {
      throw new Error('Query not found');
    }
    if (state.finalized !== null) {
      throw new Error('Query already finalized');
    }

    state.responses.set(response.id, response);
    state.votes.set(response.id, []);
    return response.id;
  }

  /**
   * Vote for a response.
   *
   * Each agent can only vote once per query (across all responses).
   */
  async vote(queryId: QueryId, responseId: ResponseId, voter: Did): Promise<void> {
    const state = this.queries.get(queryId);
    if (!state) {
      throw new Error('Query not found');
    }
    if (state.finalized !== null) {
      throw new Error('Query already finalized');
    }
    if (!state.responses.has(responseId)) {
      throw new Error('Response not found');
    }

    // Check if voter already voted
    const voterUri = didUri(voter);
    for (const voters of state.votes.values()) {
      if (voters.some((v) => didUri(v) === voterUri)) {
        throw new Error('Already voted on this query');
      }
    }

    state.votes.get(responseId)!.push(voter);
    this.checkConsensus(state);
  }

  private checkConsensus(state: QueryState): void {
    if (state.finalized !== null) {
      return;
    }

    if (state.responses.size < this.minResponses) {
      return;
    }

    let totalVotes = 0;
    for (const voters of state.votes.values()) {
      totalVotes += voters.length;
    }

    if (totalVotes < this.minVotes) {
      return;
    }

    // Find response with most votes that meets threshold
    let best: { id: ResponseId; count: number } | null = null;
    for (const [responseId, voters] of state.votes) {
      const voteCount = voters.length;
      const confidence = totalVotes > 0 ? voteCount / totalVotes : 0;

      if (confidence >= this.threshold) {
        if (best === null || voteCount > best.count) {
          best = { id: responseId, count: voteCount };
        }
      }
    }

    if (best !== null) {
      state.finalized = best.id;
    }
  }

  /** Get the consensus result for a query */
  async getResult(queryId: QueryId): Promise<ConsensusResult | null> {
    const state = this.queries.get(queryId);
    if (!state || state.finalized === null) {
      return null;
    }

    const response = state.responses.get(state.finalized)!;
    const votes = state.votes.get(state.finalized)!.length;
    let totalVoters = 0;
    for (const voters of state.votes.values()) {
      totalVoters += voters.length;
    }

    return {
      response,
      votes,
      totalVoters,
      confidence: totalVoters > 0 ? votes / totalVoters : 0,
    };
  }

  /** Check if a query has reached consensus */
  async isFinalized(queryId: QueryId): Promise<boolean> {
    const state = this.queries.get(queryId);
    return state !== null && state?.finalized !== null;
  }

  /** Get all responses for a query */
  async getResponses(queryId: QueryId): Promise<Response[] | null> {
    const state = this.queries.get(queryId);
    if (!state) {
      return null;
    }
    return Array.from(state.responses.values());
  }

  /** Get vote counts for a query */
  async getVoteCounts(queryId: QueryId): Promise<Map<ResponseId, number> | null> {
    const state = this.queries.get(queryId);
    if (!state) {
      return null;
    }
    const counts = new Map<ResponseId, number>();
    for (const [id, voters] of state.votes) {
      counts.set(id, voters.length);
    }
    return counts;
  }
}

// Helper functions

function didUri(did: Did): string {
  return `did:${did.method}:${did.id}`;
}

function numberToBytes(n: number): Uint8Array {
  const buffer = new ArrayBuffer(8);
  const view = new DataView(buffer);
  view.setBigUint64(0, BigInt(n), true); // little-endian
  return new Uint8Array(buffer);
}

function bufferToHex(buffer: ArrayBuffer): string {
  return Array.from(new Uint8Array(buffer))
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
 * One-shot consensus decision.
 */
export async function consensusDecide(
  queryContent: string,
  submitter: Did,
  responses: Array<{ content: string; responder: Did }>,
  votes: Array<{ responseIndex: number; voter: Did }>,
  threshold: number = 0.5,
): Promise<ConsensusResult | null> {
  const consensus = new AgentConsensusVoting(threshold, 1, 1);

  const query = await createQuery(queryContent, submitter);
  await consensus.submitQuery(query);

  const responseIds: ResponseId[] = [];
  for (const { content, responder } of responses) {
    const response = await createResponse(query.id, content, responder);
    await consensus.submitResponse(response);
    responseIds.push(response.id);
  }

  for (const { responseIndex, voter } of votes) {
    const responseId = responseIds[responseIndex];
    if (responseId === undefined) {
      throw new Error(`Invalid response index: ${responseIndex}`);
    }
    await consensus.vote(query.id, responseId, voter);
  }

  return consensus.getResult(query.id);
}
