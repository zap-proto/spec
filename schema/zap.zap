# ZAP - Zero-Copy App Proto
# Whitespace-significant Cap'n Proto schema
# Clean, minimal syntax - ordering determines ordinals

using Go = import "/go.capnp"

# =============================================================================
# Core Types
# =============================================================================

struct Timestamp
  seconds Int64
  nanos UInt32

struct Metadata
  entries List(Entry)

  struct Entry
    key Text
    value Text

# =============================================================================
# Tool Definitions
# =============================================================================

struct Tool
  name Text
  description Text
  schema Data
  annotations Metadata

struct ToolList
  tools List(Tool)

struct ToolCall
  id Text
  name Text
  args Data
  metadata Metadata

struct ToolResult
  id Text
  content Data
  error Text
  metadata Metadata

# =============================================================================
# Resource Definitions
# =============================================================================

struct Resource
  uri Text
  name Text
  description Text
  mimeType Text
  annotations Metadata

struct ResourceList
  resources List(Resource)

struct ResourceContent
  uri Text
  mimeType Text
  union content
    text Text
    blob Data

# =============================================================================
# Prompt Definitions
# =============================================================================

struct Prompt
  name Text
  description Text
  arguments List(Argument)

  struct Argument
    name Text
    description Text
    required Bool

struct PromptList
  prompts List(Prompt)

struct PromptMessage
  role Role
  content Content

  enum Role
    user
    assistant
    system

  struct Content
    union
      text Text
      image ImageContent
      resource ResourceContent

  struct ImageContent
    data Data
    mimeType Text

# =============================================================================
# Server Info
# =============================================================================

struct ServerInfo
  name Text
  version Text
  capabilities Capabilities

  struct Capabilities
    tools Bool
    resources Bool
    prompts Bool
    logging Bool

struct ClientInfo
  name Text
  version Text

# =============================================================================
# Main ZAP Interface
# =============================================================================

interface Zap
  init (client ClientInfo) -> (server ServerInfo)
  listTools () -> (tools ToolList)
  callTool (call ToolCall) -> (result ToolResult)
  listResources () -> (resources ResourceList)
  readResource (uri Text) -> (content ResourceContent)
  subscribe (uri Text) -> (stream ResourceStream)
  listPrompts () -> (prompts PromptList)
  getPrompt (name Text, args Metadata) -> (messages List(PromptMessage))
  log (level LogLevel, message Text, data Data) -> ()

  enum LogLevel
    debug
    info
    warn
    error

interface ResourceStream
  next () -> (content ResourceContent, done Bool)
  cancel () -> ()

# =============================================================================
# Gateway Interface
# =============================================================================

interface Gateway extends Zap
  addServer (name Text, url Text, config ServerConfig) -> (id Text)
  removeServer (id Text) -> ()
  listServers () -> (servers List(ConnectedServer))
  serverStatus (id Text) -> (status ServerStatus)

  struct ServerConfig
    transport Transport
    auth Auth
    timeout UInt32

    enum Transport
      stdio
      http
      websocket
      zap
      unix

    struct Auth
      union
        none Void
        bearer Text
        basic BasicAuth

      struct BasicAuth
        username Text
        password Text

  struct ConnectedServer
    id Text
    name Text
    url Text
    status ServerStatus
    tools UInt32
    resources UInt32

  enum ServerStatus
    connecting
    connected
    disconnected
    error

# =============================================================================
# Coordinator Interface
# =============================================================================

interface Coordinator
  register (agent AgentInfo) -> (id Text, gateway Gateway)
  heartbeat (id Text) -> (ok Bool)
  discover (filter AgentFilter) -> (agents List(AgentInfo))

  struct AgentInfo
    id Text
    name Text
    capabilities List(Text)
    metadata Metadata

  struct AgentFilter
    capabilities List(Text)
    metadata Metadata

# =============================================================================
# Post-Quantum Cryptography
# =============================================================================

struct MLKEMPublicKey
  data Data

struct MLKEMCiphertext
  data Data

struct MLDSAPublicKey
  data Data

struct MLDSASignature
  data Data

struct X25519PublicKey
  data Data

struct PQHandshake
  x25519PublicKey Data
  mlkemPublicKey MLKEMPublicKey
  mlkemCiphertext MLKEMCiphertext
  signature MLDSASignature

struct PQHandshakeInit
  x25519PublicKey Data
  mlkemPublicKey MLKEMPublicKey
  identityKey MLDSAPublicKey
  identitySignature MLDSASignature
  nonce Data
  version UInt16

struct PQHandshakeResponse
  x25519PublicKey Data
  mlkemCiphertext MLKEMCiphertext
  identityKey MLDSAPublicKey
  identitySignature MLDSASignature
  clientNonce Data
  serverNonce Data

struct PQChannelMessage
  sequence UInt64
  ciphertext Data
  tag Data
  associatedData Data

struct PQKeyRotation
  newMlkemPublicKey MLKEMPublicKey
  mlkemCiphertext MLKEMCiphertext
  signature MLDSASignature
  epoch UInt64

# =============================================================================
# Ringtail Consensus
# =============================================================================

struct Poly
  coeffs List(UInt64)

struct PolyVector
  polys List(Poly)

struct PolyMatrix
  rows List(PolyVector)

struct RingtailParams
  m UInt16 = 8
  n UInt16 = 7
  dbar UInt16 = 48
  kappa UInt16 = 23
  phi UInt16 = 256
  keySize UInt16 = 32
  q UInt64 = 0x1000000004A01
  xi UInt32 = 30
  nu UInt32 = 29

struct RingtailPartyInfo
  partyId UInt32
  totalParties UInt32
  threshold UInt32
  address Text
  publicKey Data

struct RingtailMac
  senderId UInt32
  recipientId UInt32
  value Data

struct RingtailRound1Output
  partyId UInt32
  sessionId UInt64
  dMatrix PolyMatrix
  macs List(RingtailMac)
  timestamp Timestamp

struct RingtailRound2Output
  partyId UInt32
  sessionId UInt64
  zShare PolyVector
  timestamp Timestamp

struct RingtailSignature
  c Poly
  z PolyVector
  delta PolyVector
  signers List(UInt32)
  sessionId UInt64

struct RingtailSignRequest
  message Data
  sessionId UInt64
  participants List(UInt32)
  timeoutMs UInt32

struct RingtailSignResponse
  union
    signature RingtailSignature
    error Text
    progress RingtailSignProgress

struct RingtailSignProgress
  sessionId UInt64
  currentRound UInt8
  completedParties List(UInt32)
  pendingParties List(UInt32)
  estimatedTimeMs UInt32

struct RingtailVerifyRequest
  message Data
  signature RingtailSignature
  publicKey PolyVector
  publicMatrix PolyMatrix

struct RingtailVerifyResponse
  valid Bool
  error Text

struct RingtailPeerMessage
  from UInt32
  to UInt32
  sessionId UInt64
  timestamp Timestamp
  union
    round1 RingtailRound1Output
    round2 RingtailRound2Output
    signRequest RingtailSignRequest
    signResponse RingtailSignResponse
    heartbeat RingtailHeartbeat
    abort RingtailAbort

struct RingtailHeartbeat
  partyId UInt32
  status RingtailPartyStatus
  currentSession UInt64
  load Float32

enum RingtailPartyStatus
  idle
  signingRound1
  signingRound2
  combining
  busy
  offline

struct RingtailAbort
  sessionId UInt64
  reason Text
  partyId UInt32

# =============================================================================
# Agent Consensus
# =============================================================================

struct AgentQueryId
  hash Data

struct AgentQueryState
  queryId AgentQueryId
  query Text
  responses List(AgentResponseEntry)
  votes List(AgentResponseVote)
  finalized Bool
  result Text
  createdAt Timestamp

struct AgentResponseEntry
  agentId Text
  response Text
  timestamp Timestamp
  signature Data
  confidence Float32

struct AgentResponseVote
  responseHash Data
  voteCount UInt32
  voters List(Text)

struct AgentConsensusConfig
  threshold Float64
  minResponses UInt32
  timeoutSecs UInt32
  requireSignatures Bool

struct AgentSubmitQueryRequest
  query Text
  config AgentConsensusConfig

struct AgentSubmitQueryResponse
  queryId AgentQueryId

struct AgentSubmitResponseRequest
  queryId AgentQueryId
  agentId Text
  response Text
  signature Data
  confidence Float32

struct AgentSubmitResponseResult
  union
    success Void
    error Text
    duplicate Void

struct AgentTryConsensusRequest
  queryId AgentQueryId

struct AgentTryConsensusResponse
  union
    result Text
    pending AgentQueryState
    noConsensus AgentQueryState
    error Text

# =============================================================================
# RPC Interfaces for Consensus
# =============================================================================

interface RingtailParty
  getInfo () -> (info RingtailPartyInfo)
  signRound1 (request RingtailSignRequest) -> (output RingtailRound1Output)
  signRound2 (request RingtailSignRequest, round1Outputs List(RingtailRound1Output)) -> (output RingtailRound2Output)
  finalize (request RingtailSignRequest, round2Outputs List(RingtailRound2Output)) -> (response RingtailSignResponse)
  verify (request RingtailVerifyRequest) -> (response RingtailVerifyResponse)

interface AgentConsensusService
  submitQuery (request AgentSubmitQueryRequest) -> (response AgentSubmitQueryResponse)
  submitResponse (request AgentSubmitResponseRequest) -> (result AgentSubmitResponseResult)
  tryConsensus (request AgentTryConsensusRequest) -> (response AgentTryConsensusResponse)
  getQuery (queryId AgentQueryId) -> (state AgentQueryState)
  cleanup () -> ()
  activeQueries () -> (count UInt32)

interface RingtailCoordinator
  initSession (message Data, participants List(UInt32)) -> (sessionId UInt64)
  collectRound1 (sessionId UInt64) -> (outputs List(RingtailRound1Output))
  collectRound2 (sessionId UInt64) -> (outputs List(RingtailRound2Output))
  getSignature (sessionId UInt64) -> (response RingtailSignResponse)
  cancelSession (sessionId UInt64) -> ()
  listSessions () -> (sessions List(UInt64))

# =============================================================================
# W3C DID Types
# =============================================================================

enum DidMethod
  lux
  key
  web

struct Did
  method DidMethod
  id Text

enum VerificationMethodType
  jsonWebKey2020
  multikey
  mlDsa65VerificationKey2024

struct VerificationMethod
  id Text
  type VerificationMethodType
  controller Text
  publicKeyMultibase Text
  publicKeyJwk Data
  blockchainAccountId Text

enum ServiceType
  zapAgent
  didCommMessaging
  linkedDomains
  credentialRegistry

struct ServiceEndpoint
  union
    uri Text
    uris List(Text)
    structured StructuredEndpoint

  struct StructuredEndpoint
    uri Text
    accept List(Text)
    routingKeys List(Text)

struct Service
  id Text
  type ServiceType
  serviceEndpoint ServiceEndpoint

struct DidDocument
  context List(Text)
  id Text
  controller Text
  verificationMethod List(VerificationMethod)
  authentication List(Text)
  assertionMethod List(Text)
  keyAgreement List(Text)
  capabilityInvocation List(Text)
  capabilityDelegation List(Text)
  service List(Service)

struct NodeIdentity
  did Did
  publicKey Data
  stake UInt64
  stakeRegistry Text

struct StakeEntry
  did Did
  amount UInt64
  timestamp Timestamp

struct DidResolveRequest
  did Text

struct DidResolveResponse
  union
    document DidDocument
    error Text
    notFound Void

struct DidCreateRequest
  method DidMethod
  publicKey Data
  services List(Service)

struct DidCreateResponse
  union
    did Did
    error Text

interface DidRegistry
  resolve (request DidResolveRequest) -> (response DidResolveResponse)
  create (request DidCreateRequest) -> (response DidCreateResponse)
  update (did Text, document DidDocument, signature Data) -> (success Bool, error Text)
  deactivate (did Text, signature Data) -> (success Bool, error Text)
  getStake (did Text) -> (amount UInt64)
  setStake (did Text, amount UInt64, signature Data) -> (success Bool, error Text)
