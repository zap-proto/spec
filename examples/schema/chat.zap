# chat.zap - Real-time chat application schema
# Demonstrates nested types, enums, unions, and interfaces

struct User
  id Text
  name Text
  avatar Text
  status Status

  enum Status
    online
    away
    busy
    offline

struct Message
  id Text
  author User
  timestamp UInt64
  content Content
  reactions List(Reaction)

  union Content
    text TextContent
    image ImageContent
    file FileContent
    system SystemContent

  struct TextContent
    body Text
    mentions List(Text)

  struct ImageContent
    url Text
    width UInt32
    height UInt32
    alt Text

  struct FileContent
    url Text
    name Text
    size UInt64
    mimeType Text

  struct SystemContent
    event Text
    data Text

struct Reaction
  emoji Text
  users List(Text)

struct Room
  id Text
  name Text
  description Text
  members List(User)
  messages List(Message)
  settings RoomSettings

  struct RoomSettings
    isPrivate Bool
    maxMembers UInt32 = 100
    allowFiles Bool = true
    allowImages Bool = true

interface ChatService
  # Authentication
  login (credentials Credentials) -> (session Session)
  logout (sessionId Text) -> ()

  # Rooms
  createRoom (name Text, settings RoomSettings) -> (room Room)
  joinRoom (roomId Text) -> (room Room)
  leaveRoom (roomId Text) -> ()
  listRooms () -> (rooms List(Room))

  # Messages
  sendMessage (roomId Text, content Content) -> (message Message)
  editMessage (messageId Text, content Content) -> (message Message)
  deleteMessage (messageId Text) -> ()
  getMessages (roomId Text, before UInt64, limit UInt32) -> (messages List(Message))

  # Real-time
  subscribe (roomId Text) -> (events List(ChatEvent))

  # Reactions
  addReaction (messageId Text, emoji Text) -> ()
  removeReaction (messageId Text, emoji Text) -> ()

struct Credentials
  username Text
  password Text

struct Session
  id Text
  user User
  expiresAt UInt64

struct ChatEvent
  type EventType
  payload Data
  timestamp UInt64

  enum EventType
    messageCreated
    messageUpdated
    messageDeleted
    userJoined
    userLeft
    userStatusChanged
    reactionAdded
    reactionRemoved
