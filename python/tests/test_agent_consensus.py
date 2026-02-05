"""Tests for zap_schema.agent_consensus module."""

import pytest
from zap_schema.identity import Did, DidMethod
from zap_schema.agent_consensus import (
    Query,
    Response,
    ConsensusResult,
    AgentConsensusVoting,
    consensus_decide,
)


def make_did(name: str) -> Did:
    """Create a test DID."""
    return Did(method=DidMethod.LUX, id=f"z6Mk{name}")


class TestQuery:
    """Tests for Query class."""

    def test_create_query(self):
        """Test creating a query."""
        submitter = make_did("Alice")
        query = Query.create("What is 2+2?", submitter)

        assert query.content == "What is 2+2?"
        assert query.submitter == submitter
        assert len(query.id) == 32  # blake2b digest size
        assert query.timestamp > 0

    def test_query_id_unique(self):
        """Test that different queries have different IDs."""
        submitter = make_did("Alice")
        q1 = Query.create("What is 2+2?", submitter)
        q2 = Query.create("What is 3+3?", submitter)

        assert q1.id != q2.id

    def test_query_id_deterministic_content(self):
        """Test that same content from different submitters gives different IDs."""
        alice = make_did("Alice")
        bob = make_did("Bob")
        q1 = Query.create("What is 2+2?", alice)
        q2 = Query.create("What is 2+2?", bob)

        assert q1.id != q2.id


class TestResponse:
    """Tests for Response class."""

    def test_create_response(self):
        """Test creating a response."""
        query_id = bytes(32)
        responder = make_did("Bob")
        response = Response.create(query_id, "4", responder)

        assert response.query_id == query_id
        assert response.content == "4"
        assert response.responder == responder
        assert len(response.id) == 32
        assert response.timestamp > 0

    def test_response_id_unique(self):
        """Test that different responses have different IDs."""
        query_id = bytes(32)
        responder = make_did("Bob")
        r1 = Response.create(query_id, "4", responder)
        r2 = Response.create(query_id, "5", responder)

        assert r1.id != r2.id


class TestAgentConsensusVoting:
    """Tests for AgentConsensusVoting class."""

    @pytest.mark.asyncio
    async def test_submit_query(self):
        """Test submitting a query."""
        consensus = AgentConsensusVoting(threshold=0.5, min_responses=1, min_votes=1)
        query = Query.create("What is 2+2?", make_did("Alice"))
        query_id = await consensus.submit_query(query)

        assert query_id == query.id

    @pytest.mark.asyncio
    async def test_submit_response(self):
        """Test submitting a response."""
        consensus = AgentConsensusVoting(threshold=0.5, min_responses=1, min_votes=1)
        query = Query.create("What is 2+2?", make_did("Alice"))
        await consensus.submit_query(query)

        response = Response.create(query.id, "4", make_did("Bob"))
        response_id = await consensus.submit_response(response)

        assert response_id == response.id

    @pytest.mark.asyncio
    async def test_submit_response_invalid_query(self):
        """Test submitting response to non-existent query."""
        consensus = AgentConsensusVoting(threshold=0.5, min_responses=1, min_votes=1)
        response = Response.create(bytes(32), "4", make_did("Bob"))

        with pytest.raises(ValueError, match="Query not found"):
            await consensus.submit_response(response)

    @pytest.mark.asyncio
    async def test_vote(self):
        """Test voting for a response."""
        consensus = AgentConsensusVoting(threshold=0.5, min_responses=1, min_votes=1)
        query = Query.create("What is 2+2?", make_did("Alice"))
        await consensus.submit_query(query)

        response = Response.create(query.id, "4", make_did("Bob"))
        response_id = await consensus.submit_response(response)

        await consensus.vote(query.id, response_id, make_did("Voter1"))

        # Should reach consensus with 1 vote at threshold 0.5
        assert await consensus.is_finalized(query.id)

    @pytest.mark.asyncio
    async def test_vote_double_vote_prevented(self):
        """Test that double voting is prevented."""
        consensus = AgentConsensusVoting(threshold=0.5, min_responses=1, min_votes=2)
        query = Query.create("Test", make_did("Alice"))
        await consensus.submit_query(query)

        response = Response.create(query.id, "Answer", make_did("Bob"))
        response_id = await consensus.submit_response(response)

        voter = make_did("Voter1")
        await consensus.vote(query.id, response_id, voter)

        with pytest.raises(ValueError, match="Already voted"):
            await consensus.vote(query.id, response_id, voter)

    @pytest.mark.asyncio
    async def test_vote_invalid_query(self):
        """Test voting on non-existent query."""
        consensus = AgentConsensusVoting(threshold=0.5, min_responses=1, min_votes=1)

        with pytest.raises(ValueError, match="Query not found"):
            await consensus.vote(bytes(32), bytes(32), make_did("Voter"))

    @pytest.mark.asyncio
    async def test_vote_invalid_response(self):
        """Test voting for non-existent response."""
        consensus = AgentConsensusVoting(threshold=0.5, min_responses=1, min_votes=1)
        query = Query.create("Test", make_did("Alice"))
        await consensus.submit_query(query)

        with pytest.raises(ValueError, match="Response not found"):
            await consensus.vote(query.id, bytes(32), make_did("Voter"))

    @pytest.mark.asyncio
    async def test_consensus_threshold(self):
        """Test consensus with multiple responses and votes."""
        consensus = AgentConsensusVoting(threshold=0.5, min_responses=2, min_votes=3)
        query = Query.create("Best language?", make_did("Alice"))
        await consensus.submit_query(query)

        r1 = Response.create(query.id, "Rust", make_did("Bob"))
        r1_id = await consensus.submit_response(r1)

        r2 = Response.create(query.id, "Python", make_did("Carol"))
        r2_id = await consensus.submit_response(r2)

        # Vote: 2 for Rust, 1 for Python
        await consensus.vote(query.id, r1_id, make_did("V1"))
        await consensus.vote(query.id, r1_id, make_did("V2"))
        await consensus.vote(query.id, r2_id, make_did("V3"))

        assert await consensus.is_finalized(query.id)

        result = await consensus.get_result(query.id)
        assert result is not None
        assert result.response.content == "Rust"
        assert result.votes == 2
        assert result.total_voters == 3

    @pytest.mark.asyncio
    async def test_no_consensus_below_threshold(self):
        """Test that consensus is not reached below threshold."""
        consensus = AgentConsensusVoting(threshold=0.6, min_responses=3, min_votes=3)
        query = Query.create("Test", make_did("Alice"))
        await consensus.submit_query(query)

        r1 = Response.create(query.id, "A", make_did("Bob"))
        r1_id = await consensus.submit_response(r1)

        r2 = Response.create(query.id, "B", make_did("Carol"))
        r2_id = await consensus.submit_response(r2)

        r3 = Response.create(query.id, "C", make_did("Dave"))
        r3_id = await consensus.submit_response(r3)

        # Split vote: 1-1-1 (none reaches 60%)
        await consensus.vote(query.id, r1_id, make_did("V1"))
        await consensus.vote(query.id, r2_id, make_did("V2"))
        await consensus.vote(query.id, r3_id, make_did("V3"))

        assert not await consensus.is_finalized(query.id)

    @pytest.mark.asyncio
    async def test_get_responses(self):
        """Test getting all responses for a query."""
        consensus = AgentConsensusVoting(threshold=0.5, min_responses=1, min_votes=1)
        query = Query.create("Test", make_did("Alice"))
        await consensus.submit_query(query)

        r1 = Response.create(query.id, "A", make_did("Bob"))
        r2 = Response.create(query.id, "B", make_did("Carol"))
        await consensus.submit_response(r1)
        await consensus.submit_response(r2)

        responses = await consensus.get_responses(query.id)
        assert responses is not None
        assert len(responses) == 2

    @pytest.mark.asyncio
    async def test_get_vote_counts(self):
        """Test getting vote counts."""
        consensus = AgentConsensusVoting(threshold=0.5, min_responses=1, min_votes=1)
        query = Query.create("Test", make_did("Alice"))
        await consensus.submit_query(query)

        response = Response.create(query.id, "Answer", make_did("Bob"))
        response_id = await consensus.submit_response(response)

        await consensus.vote(query.id, response_id, make_did("V1"))

        counts = await consensus.get_vote_counts(query.id)
        assert counts is not None
        assert counts.get(response_id) == 1


class TestConsensusDecide:
    """Tests for convenience function consensus_decide."""

    @pytest.mark.asyncio
    async def test_consensus_decide_simple(self):
        """Test one-shot consensus decision."""
        # Note: consensus_decide allows voting until consensus is reached
        # With threshold=0.5 and 2 votes for response[0], we reach 100% > 50%
        # So we only pass the votes that will be accepted before finalization
        result = await consensus_decide(
            query="What is 2+2?",
            submitter=make_did("Alice"),
            responses=[
                ("4", make_did("Bob")),
                ("5", make_did("Carol")),
            ],
            votes=[
                (0, make_did("V1")),  # 100% for "4", consensus reached
            ],
            threshold=0.5,
        )

        assert result is not None
        assert result.response.content == "4"
        assert result.votes == 1

    @pytest.mark.asyncio
    async def test_consensus_decide_no_consensus(self):
        """Test one-shot with no consensus reached."""
        # With no votes at all, no consensus can be reached
        result = await consensus_decide(
            query="Test",
            submitter=make_did("Alice"),
            responses=[
                ("A", make_did("Bob")),
                ("B", make_did("Carol")),
            ],
            votes=[],  # No votes = no consensus
            threshold=0.5,
        )

        assert result is None
