//! Agentic consensus for response voting
//!
//! Agents vote on responses to queries. No trust needed - majority wins.
//! As long as majority are honest, you get correct results.

use crate::error::Error;
use crate::identity::Did;
use blake3::Hasher;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

/// Query ID (32-byte hash)
pub type QueryId = [u8; 32];

/// Response ID (32-byte hash)
pub type ResponseId = [u8; 32];

/// A query submitted to the agent network
#[derive(Debug, Clone)]
pub struct Query {
    pub id: QueryId,
    pub content: String,
    pub submitter: Did,
    pub timestamp: u64,
}

impl Query {
    /// Create a new query
    pub fn new(content: String, submitter: Did) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut hasher = Hasher::new();
        hasher.update(content.as_bytes());
        hasher.update(submitter.to_string().as_bytes());
        hasher.update(&timestamp.to_le_bytes());
        let hash: [u8; 32] = *hasher.finalize().as_bytes();
        Self {
            id: hash,
            content,
            submitter,
            timestamp,
        }
    }
}

/// A response to a query
#[derive(Debug, Clone)]
pub struct Response {
    pub id: ResponseId,
    pub query_id: QueryId,
    pub content: String,
    pub responder: Did,
    pub timestamp: u64,
}

impl Response {
    /// Create a new response
    pub fn new(query_id: QueryId, content: String, responder: Did) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut hasher = Hasher::new();
        hasher.update(&query_id);
        hasher.update(content.as_bytes());
        hasher.update(responder.to_string().as_bytes());
        hasher.update(&timestamp.to_le_bytes());
        let hash: [u8; 32] = *hasher.finalize().as_bytes();
        Self {
            id: hash,
            query_id,
            content,
            responder,
            timestamp,
        }
    }
}

/// Result of consensus voting
#[derive(Debug, Clone)]
pub struct ConsensusResult {
    /// The winning response
    pub response: Response,
    /// Number of votes for this response
    pub votes: usize,
    /// Total number of voters
    pub total_voters: usize,
    /// Confidence (votes / total)
    pub confidence: f64,
}

/// Internal state for a query
struct QueryState {
    query: Query,
    responses: HashMap<ResponseId, Response>,
    votes: HashMap<ResponseId, Vec<Did>>,
    finalized: Option<ResponseId>,
}

/// Agentic consensus for response voting
///
/// Agents submit responses and vote. Majority wins.
pub struct AgentConsensusVoting {
    queries: Arc<RwLock<HashMap<QueryId, QueryState>>>,
    /// Threshold for consensus (e.g., 0.5 for simple majority)
    threshold: f64,
    /// Minimum responses before consensus can be reached
    min_responses: usize,
    /// Minimum votes before consensus can be reached
    min_votes: usize,
}

impl AgentConsensusVoting {
    /// Create new consensus instance
    ///
    /// # Arguments
    /// * `threshold` - Fraction of votes needed (0.5 = majority)
    /// * `min_responses` - Minimum responses before checking consensus
    /// * `min_votes` - Minimum votes before checking consensus
    pub fn new(threshold: f64, min_responses: usize, min_votes: usize) -> Self {
        Self {
            queries: Arc::new(RwLock::new(HashMap::new())),
            threshold: threshold.clamp(0.0, 1.0),
            min_responses,
            min_votes,
        }
    }

    /// Submit a new query
    pub async fn submit_query(&self, query: Query) -> QueryId {
        let mut queries = self.queries.write().await;
        let id = query.id;
        queries.insert(
            id,
            QueryState {
                query,
                responses: HashMap::new(),
                votes: HashMap::new(),
                finalized: None,
            },
        );
        id
    }

    /// Submit a response to a query
    pub async fn submit_response(&self, response: Response) -> Result<ResponseId, Error> {
        let mut queries = self.queries.write().await;
        let state = queries
            .get_mut(&response.query_id)
            .ok_or_else(|| Error::Consensus("Query not found".into()))?;

        if state.finalized.is_some() {
            return Err(Error::Consensus("Query already finalized".into()));
        }

        let id = response.id;
        state.responses.insert(id, response);
        state.votes.insert(id, Vec::new());
        Ok(id)
    }

    /// Vote for a response
    ///
    /// Each agent can only vote once per query (across all responses)
    pub async fn vote(
        &self,
        query_id: QueryId,
        response_id: ResponseId,
        voter: Did,
    ) -> Result<(), Error> {
        let mut queries = self.queries.write().await;
        let state = queries
            .get_mut(&query_id)
            .ok_or_else(|| Error::Consensus("Query not found".into()))?;

        if state.finalized.is_some() {
            return Err(Error::Consensus("Query already finalized".into()));
        }

        if !state.responses.contains_key(&response_id) {
            return Err(Error::Consensus("Response not found".into()));
        }

        // Check if voter already voted
        for votes in state.votes.values() {
            if votes.iter().any(|v| v == &voter) {
                return Err(Error::Consensus("Already voted on this query".into()));
            }
        }

        state.votes.get_mut(&response_id).unwrap().push(voter);

        // Check if consensus reached
        self.check_consensus(state);
        Ok(())
    }

    /// Check if consensus has been reached
    fn check_consensus(&self, state: &mut QueryState) {
        if state.finalized.is_some() {
            return;
        }

        // Need minimum responses
        if state.responses.len() < self.min_responses {
            return;
        }

        // Count total votes
        let total_votes: usize = state.votes.values().map(|v| v.len()).sum();
        if total_votes < self.min_votes {
            return;
        }

        // Find response with most votes that meets threshold
        let mut best: Option<(ResponseId, usize)> = None;
        for (response_id, voters) in &state.votes {
            let vote_count = voters.len();
            let confidence = vote_count as f64 / total_votes as f64;

            if confidence >= self.threshold {
                match best {
                    None => best = Some((*response_id, vote_count)),
                    Some((_, best_count)) if vote_count > best_count => {
                        best = Some((*response_id, vote_count))
                    }
                    _ => {}
                }
            }
        }

        if let Some((response_id, _)) = best {
            state.finalized = Some(response_id);
        }
    }

    /// Get the consensus result for a query
    pub async fn get_result(&self, query_id: QueryId) -> Option<ConsensusResult> {
        let queries = self.queries.read().await;
        let state = queries.get(&query_id)?;
        let winning_id = state.finalized?;
        let response = state.responses.get(&winning_id)?.clone();
        let votes = state.votes.get(&winning_id)?.len();
        let total_voters: usize = state.votes.values().map(|v| v.len()).sum();

        Some(ConsensusResult {
            response,
            votes,
            total_voters,
            confidence: if total_voters > 0 {
                votes as f64 / total_voters as f64
            } else {
                0.0
            },
        })
    }

    /// Check if a query has reached consensus
    pub async fn is_finalized(&self, query_id: QueryId) -> bool {
        let queries = self.queries.read().await;
        queries
            .get(&query_id)
            .map(|s| s.finalized.is_some())
            .unwrap_or(false)
    }

    /// Get all responses for a query
    pub async fn get_responses(&self, query_id: QueryId) -> Option<Vec<Response>> {
        let queries = self.queries.read().await;
        let state = queries.get(&query_id)?;
        Some(state.responses.values().cloned().collect())
    }

    /// Get vote counts for a query
    pub async fn get_vote_counts(&self, query_id: QueryId) -> Option<HashMap<ResponseId, usize>> {
        let queries = self.queries.read().await;
        let state = queries.get(&query_id)?;
        Some(
            state
                .votes
                .iter()
                .map(|(id, voters)| (*id, voters.len()))
                .collect(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::DidMethod;

    fn make_did(name: &str) -> Did {
        Did {
            method: DidMethod::Lux,
            id: format!("z6Mk{}", name),
        }
    }

    #[tokio::test]
    async fn test_submit_query() {
        let consensus = AgentConsensusVoting::new(0.5, 1, 1);
        let query = Query::new("What is 2+2?".into(), make_did("Alice"));
        let id = consensus.submit_query(query.clone()).await;
        assert_eq!(id, query.id);
    }

    #[tokio::test]
    async fn test_submit_response() {
        let consensus = AgentConsensusVoting::new(0.5, 1, 1);
        let query = Query::new("What is 2+2?".into(), make_did("Alice"));
        let query_id = consensus.submit_query(query).await;

        let response = Response::new(query_id, "4".into(), make_did("Bob"));
        let result = consensus.submit_response(response.clone()).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_vote_and_consensus() {
        let consensus = AgentConsensusVoting::new(0.5, 1, 2);
        let query = Query::new("What is 2+2?".into(), make_did("Alice"));
        let query_id = consensus.submit_query(query).await;

        let response = Response::new(query_id, "4".into(), make_did("Bob"));
        let response_id = consensus.submit_response(response).await.unwrap();

        // First vote - not enough yet
        consensus
            .vote(query_id, response_id, make_did("Voter1"))
            .await
            .unwrap();
        assert!(!consensus.is_finalized(query_id).await);

        // Second vote - should reach consensus
        consensus
            .vote(query_id, response_id, make_did("Voter2"))
            .await
            .unwrap();
        assert!(consensus.is_finalized(query_id).await);

        let result = consensus.get_result(query_id).await.unwrap();
        assert_eq!(result.response.content, "4");
        assert_eq!(result.votes, 2);
        assert_eq!(result.confidence, 1.0);
    }

    #[tokio::test]
    async fn test_double_vote_prevented() {
        let consensus = AgentConsensusVoting::new(0.5, 1, 1);
        let query = Query::new("Test".into(), make_did("Alice"));
        let query_id = consensus.submit_query(query).await;

        let response = Response::new(query_id, "Answer".into(), make_did("Bob"));
        let response_id = consensus.submit_response(response).await.unwrap();

        let voter = make_did("Voter1");
        consensus.vote(query_id, response_id, voter.clone()).await.unwrap();

        // Second vote from same voter should fail
        let result = consensus.vote(query_id, response_id, voter).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_majority_wins() {
        let consensus = AgentConsensusVoting::new(0.5, 2, 3);
        let query = Query::new("Best language?".into(), make_did("Alice"));
        let query_id = consensus.submit_query(query).await;

        let r1 = Response::new(query_id, "Rust".into(), make_did("Bob"));
        let r1_id = consensus.submit_response(r1).await.unwrap();

        let r2 = Response::new(query_id, "Python".into(), make_did("Carol"));
        let r2_id = consensus.submit_response(r2).await.unwrap();

        // Vote: 2 for Rust, 1 for Python
        consensus.vote(query_id, r1_id, make_did("V1")).await.unwrap();
        consensus.vote(query_id, r1_id, make_did("V2")).await.unwrap();
        consensus.vote(query_id, r2_id, make_did("V3")).await.unwrap();

        assert!(consensus.is_finalized(query_id).await);
        let result = consensus.get_result(query_id).await.unwrap();
        assert_eq!(result.response.content, "Rust");
        assert_eq!(result.votes, 2);
        assert_eq!(result.total_voters, 3);
    }

    #[tokio::test]
    async fn test_no_consensus_below_threshold() {
        let consensus = AgentConsensusVoting::new(0.6, 2, 3);
        let query = Query::new("Test".into(), make_did("Alice"));
        let query_id = consensus.submit_query(query).await;

        let r1 = Response::new(query_id, "A".into(), make_did("Bob"));
        let r1_id = consensus.submit_response(r1).await.unwrap();

        let r2 = Response::new(query_id, "B".into(), make_did("Carol"));
        let r2_id = consensus.submit_response(r2).await.unwrap();

        // Split vote: 1-1-1 (none reaches 60%)
        let r3 = Response::new(query_id, "C".into(), make_did("Dave"));
        let r3_id = consensus.submit_response(r3).await.unwrap();

        consensus.vote(query_id, r1_id, make_did("V1")).await.unwrap();
        consensus.vote(query_id, r2_id, make_did("V2")).await.unwrap();
        consensus.vote(query_id, r3_id, make_did("V3")).await.unwrap();

        // No consensus - 33% each, threshold is 60%
        assert!(!consensus.is_finalized(query_id).await);
    }

    #[tokio::test]
    async fn test_get_vote_counts() {
        let consensus = AgentConsensusVoting::new(0.5, 1, 1);
        let query = Query::new("Test".into(), make_did("Alice"));
        let query_id = consensus.submit_query(query).await;

        let r1 = Response::new(query_id, "A".into(), make_did("Bob"));
        let r1_id = consensus.submit_response(r1).await.unwrap();

        consensus.vote(query_id, r1_id, make_did("V1")).await.unwrap();

        let counts = consensus.get_vote_counts(query_id).await.unwrap();
        assert_eq!(counts.get(&r1_id), Some(&1));
    }
}
