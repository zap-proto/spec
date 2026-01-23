"""
Agentic consensus for response voting.

Agents vote on responses to queries. No trust needed - majority wins.
As long as majority are honest, you get correct results.
"""

from __future__ import annotations

import asyncio
import hashlib
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .identity import Did


@dataclass
class Query:
    """A query submitted to the agent network."""
    id: bytes
    content: str
    submitter: Did
    timestamp: int

    @classmethod
    def create(cls, content: str, submitter: Did) -> "Query":
        """Create a new query with auto-generated ID."""
        timestamp = int(time.time())
        hasher = hashlib.blake2b(digest_size=32)
        hasher.update(content.encode())
        hasher.update(submitter.uri().encode())
        hasher.update(timestamp.to_bytes(8, 'little'))
        return cls(
            id=hasher.digest(),
            content=content,
            submitter=submitter,
            timestamp=timestamp,
        )


@dataclass
class Response:
    """A response to a query."""
    id: bytes
    query_id: bytes
    content: str
    responder: Did
    timestamp: int

    @classmethod
    def create(cls, query_id: bytes, content: str, responder: Did) -> "Response":
        """Create a new response with auto-generated ID."""
        timestamp = int(time.time())
        hasher = hashlib.blake2b(digest_size=32)
        hasher.update(query_id)
        hasher.update(content.encode())
        hasher.update(responder.uri().encode())
        hasher.update(timestamp.to_bytes(8, 'little'))
        return cls(
            id=hasher.digest(),
            query_id=query_id,
            content=content,
            responder=responder,
            timestamp=timestamp,
        )


@dataclass
class ConsensusResult:
    """Result of consensus voting."""
    response: Response
    votes: int
    total_voters: int
    confidence: float


@dataclass
class QueryState:
    """Internal state for a query."""
    query: Query
    responses: Dict[bytes, Response] = field(default_factory=dict)
    votes: Dict[bytes, List[Did]] = field(default_factory=dict)
    finalized: Optional[bytes] = None


class AgentConsensusVoting:
    """
    Agentic consensus for response voting.

    Agents submit responses and vote. Majority wins.

    Args:
        threshold: Fraction of votes needed (0.5 = majority)
        min_responses: Minimum responses before checking consensus
        min_votes: Minimum votes before checking consensus
    """

    def __init__(
        self,
        threshold: float = 0.5,
        min_responses: int = 1,
        min_votes: int = 1,
    ):
        self.threshold = max(0.0, min(1.0, threshold))
        self.min_responses = min_responses
        self.min_votes = min_votes
        self._queries: Dict[bytes, QueryState] = {}
        self._lock = asyncio.Lock()

    async def submit_query(self, query: Query) -> bytes:
        """Submit a new query."""
        async with self._lock:
            self._queries[query.id] = QueryState(query=query)
            return query.id

    async def submit_response(self, response: Response) -> bytes:
        """Submit a response to a query."""
        async with self._lock:
            state = self._queries.get(response.query_id)
            if state is None:
                raise ValueError("Query not found")
            if state.finalized is not None:
                raise ValueError("Query already finalized")

            state.responses[response.id] = response
            state.votes[response.id] = []
            return response.id

    async def vote(self, query_id: bytes, response_id: bytes, voter: Did) -> None:
        """
        Vote for a response.

        Each agent can only vote once per query (across all responses).
        """
        async with self._lock:
            state = self._queries.get(query_id)
            if state is None:
                raise ValueError("Query not found")
            if state.finalized is not None:
                raise ValueError("Query already finalized")
            if response_id not in state.responses:
                raise ValueError("Response not found")

            # Check if voter already voted
            for voters in state.votes.values():
                if any(v.uri() == voter.uri() for v in voters):
                    raise ValueError("Already voted on this query")

            state.votes[response_id].append(voter)
            self._check_consensus(state)

    def _check_consensus(self, state: QueryState) -> None:
        """Check if consensus has been reached."""
        if state.finalized is not None:
            return

        if len(state.responses) < self.min_responses:
            return

        total_votes = sum(len(v) for v in state.votes.values())
        if total_votes < self.min_votes:
            return

        # Find response with most votes that meets threshold
        best: Optional[tuple[bytes, int]] = None
        for response_id, voters in state.votes.items():
            vote_count = len(voters)
            confidence = vote_count / total_votes if total_votes > 0 else 0

            if confidence >= self.threshold:
                if best is None or vote_count > best[1]:
                    best = (response_id, vote_count)

        if best is not None:
            state.finalized = best[0]

    async def get_result(self, query_id: bytes) -> Optional[ConsensusResult]:
        """Get the consensus result for a query."""
        async with self._lock:
            state = self._queries.get(query_id)
            if state is None or state.finalized is None:
                return None

            response = state.responses[state.finalized]
            votes = len(state.votes[state.finalized])
            total_voters = sum(len(v) for v in state.votes.values())

            return ConsensusResult(
                response=response,
                votes=votes,
                total_voters=total_voters,
                confidence=votes / total_voters if total_voters > 0 else 0,
            )

    async def is_finalized(self, query_id: bytes) -> bool:
        """Check if a query has reached consensus."""
        async with self._lock:
            state = self._queries.get(query_id)
            return state is not None and state.finalized is not None

    async def get_responses(self, query_id: bytes) -> Optional[List[Response]]:
        """Get all responses for a query."""
        async with self._lock:
            state = self._queries.get(query_id)
            if state is None:
                return None
            return list(state.responses.values())

    async def get_vote_counts(self, query_id: bytes) -> Optional[Dict[bytes, int]]:
        """Get vote counts for a query."""
        async with self._lock:
            state = self._queries.get(query_id)
            if state is None:
                return None
            return {rid: len(voters) for rid, voters in state.votes.items()}


# Convenience functions

async def consensus_decide(
    query: str,
    submitter: Did,
    responses: List[tuple[str, Did]],
    votes: List[tuple[int, Did]],
    threshold: float = 0.5,
) -> Optional[ConsensusResult]:
    """
    One-shot consensus decision.

    Args:
        query: The query content
        submitter: Who submitted the query
        responses: List of (content, responder) tuples
        votes: List of (response_index, voter) tuples
        threshold: Voting threshold

    Returns:
        ConsensusResult if consensus reached, None otherwise
    """
    consensus = AgentConsensusVoting(
        threshold=threshold,
        min_responses=1,
        min_votes=1,
    )

    q = Query.create(query, submitter)
    await consensus.submit_query(q)

    response_ids = []
    for content, responder in responses:
        r = Response.create(q.id, content, responder)
        await consensus.submit_response(r)
        response_ids.append(r.id)

    for response_idx, voter in votes:
        await consensus.vote(q.id, response_ids[response_idx], voter)

    return await consensus.get_result(q.id)


__all__ = [
    'Query',
    'Response',
    'ConsensusResult',
    'AgentConsensusVoting',
    'consensus_decide',
]
