# haven-core

Shared TypeScript library providing cryptographic primitives, API client, and type definitions used by the web frontend (and any future clients).

## Structure

```
src/
├── types.ts            # All shared TypeScript interfaces and types
├── index.ts            # Public API re-exports
├── crypto/
│   ├── utils.ts        # libsodium init, base64 helpers, key generation
│   ├── x3dh.ts         # X3DH key agreement (initiator + responder)
│   ├── double-ratchet.ts  # Double Ratchet session (DM encryption)
│   ├── sender-keys.ts  # Sender Keys protocol (group channel encryption)
│   ├── file-crypto.ts  # XChaCha20-Poly1305 file encryption
│   └── store.ts        # MemoryStore for key material (in-memory only)
├── net/
│   ├── api.ts          # HavenApi — type-safe REST client with JWT management
│   └── ws.ts           # HavenWs — WebSocket client with auto-reconnect
└── store/
    └── memory-store.ts # In-memory key/session storage
```

## E2EE Model

### DMs (X3DH + Double Ratchet)
1. Initiator fetches recipient's key bundle (identity key + signed prekey + one-time prekey)
2. X3DH key agreement produces a shared secret
3. Double Ratchet session provides forward secrecy and break-in recovery
4. Wire format: `[0x01 or 0x02][encrypted payload]`

### Server Channels (Sender Keys)
1. Each user generates a sender key per channel
2. Sender Key Distribution Messages (SKDMs) are encrypted to each member's identity key via `crypto_box_seal`
3. Wire format: `[0x03][distributionId:16][chainIndex:4 LE][nonce:24][ciphertext+tag]`

### Files
- XChaCha20-Poly1305 client-side encryption
- Key and nonce embedded in the message payload (encrypted along with the message)
- File sizes are padded to prevent type inference

## Building

```bash
npm install
npm run build    # Compiles to dist/ via tsc
```

**Important**: The web frontend imports from `dist/`, not `src/`. You must rebuild haven-core after any changes for the frontend to pick them up.

## Testing

```bash
npx vitest run    # 78 tests
```

## API Client

The `HavenApi` class handles JWT token management, automatic PoW solving for registration, and typed request/response for every endpoint:

```typescript
import { HavenApi } from '@haven/core';

const api = new HavenApi({ baseUrl: 'https://chat.example.com' });
await api.register({ username, password, ...keys });
await api.login({ username, password });
const servers = await api.listServers();
```

Covers all Haven API areas: auth, servers, channels, messages, sender keys, roles, friends, invites, voice (join/leave/participants/mute/deafen), attachments (upload/download), link previews, admin, and user management.
