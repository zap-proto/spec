import { describe, it, expect } from 'vitest';
import {
  createQuery,
  createResponse,
  AgentConsensusVoting,
  consensusDecide,
} from '../src/agent_consensus.js';
import { Did, DidMethod } from '../src/identity.js';

function makeDid(name: string): Did {
  return { method: DidMethod.Lux, id: `z6Mk${name}` };
}

describe('Query', () => {
  it('should create a query with auto-generated ID', async () => {
    const submitter = makeDid('Alice');
    const query = await createQuery('What is 2+2?', submitter);

    expect(query.content).toBe('What is 2+2?');
    expect(query.submitter).toEqual(submitter);
    expect(query.id).toHaveLength(64); // SHA-256 hex string
    expect(query.timestamp).toBeGreaterThan(0);
  });

  it('should generate unique IDs for different queries', async () => {
    const submitter = makeDid('Alice');
    const q1 = await createQuery('What is 2+2?', submitter);
    const q2 = await createQuery('What is 3+3?', submitter);

    expect(q1.id).not.toBe(q2.id);
  });
});

describe('Response', () => {
  it('should create a response with auto-generated ID', async () => {
    const queryId = '0'.repeat(64);
    const responder = makeDid('Bob');
    const response = await createResponse(queryId, '4', responder);

    expect(response.queryId).toBe(queryId);
    expect(response.content).toBe('4');
    expect(response.responder).toEqual(responder);
    expect(response.id).toHaveLength(64);
    expect(response.timestamp).toBeGreaterThan(0);
  });

  it('should generate unique IDs for different responses', async () => {
    const queryId = '0'.repeat(64);
    const responder = makeDid('Bob');
    const r1 = await createResponse(queryId, '4', responder);
    const r2 = await createResponse(queryId, '5', responder);

    expect(r1.id).not.toBe(r2.id);
  });
});

describe('AgentConsensusVoting', () => {
  it('should submit a query', async () => {
    const consensus = new AgentConsensusVoting(0.5, 1, 1);
    const query = await createQuery('What is 2+2?', makeDid('Alice'));
    const queryId = await consensus.submitQuery(query);

    expect(queryId).toBe(query.id);
  });

  it('should submit a response', async () => {
    const consensus = new AgentConsensusVoting(0.5, 1, 1);
    const query = await createQuery('What is 2+2?', makeDid('Alice'));
    await consensus.submitQuery(query);

    const response = await createResponse(query.id, '4', makeDid('Bob'));
    const responseId = await consensus.submitResponse(response);

    expect(responseId).toBe(response.id);
  });

  it('should throw when submitting response to non-existent query', async () => {
    const consensus = new AgentConsensusVoting(0.5, 1, 1);
    const response = await createResponse('0'.repeat(64), '4', makeDid('Bob'));

    await expect(consensus.submitResponse(response)).rejects.toThrow('Query not found');
  });

  it('should vote for a response', async () => {
    const consensus = new AgentConsensusVoting(0.5, 1, 1);
    const query = await createQuery('What is 2+2?', makeDid('Alice'));
    await consensus.submitQuery(query);

    const response = await createResponse(query.id, '4', makeDid('Bob'));
    const responseId = await consensus.submitResponse(response);

    await consensus.vote(query.id, responseId, makeDid('Voter1'));

    const finalized = await consensus.isFinalized(query.id);
    expect(finalized).toBe(true);
  });

  it('should prevent double voting', async () => {
    const consensus = new AgentConsensusVoting(0.5, 1, 2);
    const query = await createQuery('Test', makeDid('Alice'));
    await consensus.submitQuery(query);

    const response = await createResponse(query.id, 'Answer', makeDid('Bob'));
    const responseId = await consensus.submitResponse(response);

    const voter = makeDid('Voter1');
    await consensus.vote(query.id, responseId, voter);

    await expect(consensus.vote(query.id, responseId, voter)).rejects.toThrow(
      'Already voted',
    );
  });

  it('should throw when voting on non-existent query', async () => {
    const consensus = new AgentConsensusVoting(0.5, 1, 1);

    await expect(
      consensus.vote('0'.repeat(64), '0'.repeat(64), makeDid('Voter')),
    ).rejects.toThrow('Query not found');
  });

  it('should throw when voting for non-existent response', async () => {
    const consensus = new AgentConsensusVoting(0.5, 1, 1);
    const query = await createQuery('Test', makeDid('Alice'));
    await consensus.submitQuery(query);

    await expect(
      consensus.vote(query.id, '0'.repeat(64), makeDid('Voter')),
    ).rejects.toThrow('Response not found');
  });

  it('should reach consensus with threshold', async () => {
    const consensus = new AgentConsensusVoting(0.5, 2, 3);
    const query = await createQuery('Best language?', makeDid('Alice'));
    await consensus.submitQuery(query);

    const r1 = await createResponse(query.id, 'Rust', makeDid('Bob'));
    const r1Id = await consensus.submitResponse(r1);

    const r2 = await createResponse(query.id, 'Python', makeDid('Carol'));
    const r2Id = await consensus.submitResponse(r2);

    // Vote: 2 for Rust, 1 for Python
    await consensus.vote(query.id, r1Id, makeDid('V1'));
    await consensus.vote(query.id, r1Id, makeDid('V2'));
    await consensus.vote(query.id, r2Id, makeDid('V3'));

    expect(await consensus.isFinalized(query.id)).toBe(true);

    const result = await consensus.getResult(query.id);
    expect(result).not.toBeNull();
    expect(result!.response.content).toBe('Rust');
    expect(result!.votes).toBe(2);
    expect(result!.totalVoters).toBe(3);
  });

  it('should not reach consensus below threshold', async () => {
    const consensus = new AgentConsensusVoting(0.6, 3, 3);
    const query = await createQuery('Test', makeDid('Alice'));
    await consensus.submitQuery(query);

    const r1 = await createResponse(query.id, 'A', makeDid('Bob'));
    const r1Id = await consensus.submitResponse(r1);

    const r2 = await createResponse(query.id, 'B', makeDid('Carol'));
    const r2Id = await consensus.submitResponse(r2);

    const r3 = await createResponse(query.id, 'C', makeDid('Dave'));
    const r3Id = await consensus.submitResponse(r3);

    // Split vote: 1-1-1 (none reaches 60%)
    await consensus.vote(query.id, r1Id, makeDid('V1'));
    await consensus.vote(query.id, r2Id, makeDid('V2'));
    await consensus.vote(query.id, r3Id, makeDid('V3'));

    expect(await consensus.isFinalized(query.id)).toBe(false);
  });

  it('should get all responses for a query', async () => {
    const consensus = new AgentConsensusVoting(0.5, 1, 1);
    const query = await createQuery('Test', makeDid('Alice'));
    await consensus.submitQuery(query);

    const r1 = await createResponse(query.id, 'A', makeDid('Bob'));
    const r2 = await createResponse(query.id, 'B', makeDid('Carol'));
    await consensus.submitResponse(r1);
    await consensus.submitResponse(r2);

    const responses = await consensus.getResponses(query.id);
    expect(responses).not.toBeNull();
    expect(responses).toHaveLength(2);
  });

  it('should get vote counts', async () => {
    const consensus = new AgentConsensusVoting(0.5, 1, 1);
    const query = await createQuery('Test', makeDid('Alice'));
    await consensus.submitQuery(query);

    const response = await createResponse(query.id, 'Answer', makeDid('Bob'));
    const responseId = await consensus.submitResponse(response);

    await consensus.vote(query.id, responseId, makeDid('V1'));

    const counts = await consensus.getVoteCounts(query.id);
    expect(counts).not.toBeNull();
    expect(counts!.get(responseId)).toBe(1);
  });
});

describe('consensusDecide', () => {
  it('should perform one-shot consensus decision', async () => {
    // With threshold=0.5, a single vote (100% > 50%) reaches consensus
    const result = await consensusDecide(
      'What is 2+2?',
      makeDid('Alice'),
      [
        { content: '4', responder: makeDid('Bob') },
        { content: '5', responder: makeDid('Carol') },
      ],
      [
        { responseIndex: 0, voter: makeDid('V1') }, // 100% for "4", consensus reached
      ],
      0.5,
    );

    expect(result).not.toBeNull();
    expect(result!.response.content).toBe('4');
    expect(result!.votes).toBe(1);
  });

  it('should return null when no consensus reached', async () => {
    // With no votes, no consensus can be reached
    const result = await consensusDecide(
      'Test',
      makeDid('Alice'),
      [
        { content: 'A', responder: makeDid('Bob') },
        { content: 'B', responder: makeDid('Carol') },
      ],
      [], // No votes = no consensus
      0.5,
    );

    expect(result).toBeNull();
  });

  it('should throw on invalid response index', async () => {
    await expect(
      consensusDecide(
        'Test',
        makeDid('Alice'),
        [{ content: 'A', responder: makeDid('Bob') }],
        [{ responseIndex: 99, voter: makeDid('V1') }],
      ),
    ).rejects.toThrow('Invalid response index');
  });
});
