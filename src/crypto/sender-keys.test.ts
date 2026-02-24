import { describe, it, expect, beforeAll } from "vitest";
import { initSodium, getSodium, randomBytes } from "./utils.js";
import { generateIdentityKeyPair } from "./keys.js";
import {
  generateSenderKey,
  createSkdmPayload,
  parseSkdmPayload,
  encryptSkdm,
  decryptSkdm,
  senderKeyEncrypt,
  senderKeyDecrypt,
  GROUP_MSG_TYPE,
  type SenderKeyState,
  type ReceivedSenderKey,
} from "./sender-keys.js";

beforeAll(async () => {
  await initSodium();
});

// ─── Helper ────────────────────────────────────────────

/** Deep-clone a SenderKeyState so mutations don't cross-contaminate. */
function cloneSenderKey(sk: SenderKeyState): ReceivedSenderKey {
  return {
    distributionId: new Uint8Array(sk.distributionId),
    chainKey: new Uint8Array(sk.chainKey),
    chainIndex: sk.chainIndex,
  };
}

const plaintext = () => new TextEncoder().encode("hello group");

// ─── generateSenderKey ─────────────────────────────────

describe("generateSenderKey", () => {
  it("returns a valid sender key with 16-byte distributionId, 32-byte chainKey, and index 0", () => {
    const sk = generateSenderKey();
    expect(sk.distributionId).toBeInstanceOf(Uint8Array);
    expect(sk.distributionId.length).toBe(16);
    expect(sk.chainKey).toBeInstanceOf(Uint8Array);
    expect(sk.chainKey.length).toBe(32);
    expect(sk.chainIndex).toBe(0);
  });

  it("generates unique keys on each call", () => {
    const a = generateSenderKey();
    const b = generateSenderKey();
    expect(a.distributionId).not.toEqual(b.distributionId);
    expect(a.chainKey).not.toEqual(b.chainKey);
  });
});

// ─── SKDM payload serialization ────────────────────────

describe("SKDM payload round-trip", () => {
  it("createSkdmPayload → parseSkdmPayload preserves all fields", () => {
    const sk = generateSenderKey();
    const buf = createSkdmPayload(sk);
    expect(buf.length).toBe(52);

    const parsed = parseSkdmPayload(buf);
    expect(parsed.distributionId).toEqual(sk.distributionId);
    expect(parsed.chainKey).toEqual(sk.chainKey);
    expect(parsed.chainIndex).toBe(sk.chainIndex);
  });

  it("preserves non-zero chainIndex", () => {
    const sk = generateSenderKey();
    sk.chainIndex = 42;
    const parsed = parseSkdmPayload(createSkdmPayload(sk));
    expect(parsed.chainIndex).toBe(42);
  });

  it("rejects payloads shorter than 52 bytes", () => {
    expect(() => parseSkdmPayload(new Uint8Array(51))).toThrow("too short");
  });
});

// ─── SKDM encryption / decryption ──────────────────────

describe("SKDM encrypt / decrypt", () => {
  it("round-trips through crypto_box_seal", () => {
    const identity = generateIdentityKeyPair();
    const sk = generateSenderKey();
    const payload = createSkdmPayload(sk);

    const encrypted = encryptSkdm(payload, identity.publicKey);
    expect(encrypted.length).toBeGreaterThan(payload.length); // seal overhead

    const decrypted = decryptSkdm(encrypted, identity);
    const parsed = parseSkdmPayload(decrypted);
    expect(parsed.distributionId).toEqual(sk.distributionId);
    expect(parsed.chainKey).toEqual(sk.chainKey);
    expect(parsed.chainIndex).toBe(sk.chainIndex);
  });

  it("fails to decrypt with a different identity key", () => {
    const sender = generateIdentityKeyPair();
    const stranger = generateIdentityKeyPair();
    const sk = generateSenderKey();
    const encrypted = encryptSkdm(createSkdmPayload(sk), sender.publicKey);

    expect(() => decryptSkdm(encrypted, stranger)).toThrow();
  });
});

// ─── Basic encrypt / decrypt ───────────────────────────

describe("senderKeyEncrypt / senderKeyDecrypt", () => {
  it("encrypts and decrypts a single message", () => {
    const sk = generateSenderKey();
    const received = cloneSenderKey(sk);
    const msg = plaintext();

    const wire = senderKeyEncrypt(sk, msg);
    expect(wire[0]).toBe(GROUP_MSG_TYPE);

    const decrypted = senderKeyDecrypt(wire, received);
    expect(decrypted).toEqual(msg);
  });

  it("encrypts and decrypts multiple sequential messages", () => {
    const sk = generateSenderKey();
    const received = cloneSenderKey(sk);

    for (let i = 0; i < 10; i++) {
      const msg = new TextEncoder().encode(`message ${i}`);
      const wire = senderKeyEncrypt(sk, msg);
      const dec = senderKeyDecrypt(wire, received);
      expect(new TextDecoder().decode(dec)).toBe(`message ${i}`);
    }

    // After 10 messages, both sides should be at chainIndex 10
    expect(sk.chainIndex).toBe(10);
    expect(received.chainIndex).toBe(10);
  });

  it("advances chainIndex and chainKey on the sender after encryption", () => {
    const sk = generateSenderKey();
    const origChainKey = new Uint8Array(sk.chainKey);
    expect(sk.chainIndex).toBe(0);

    senderKeyEncrypt(sk, plaintext());

    expect(sk.chainIndex).toBe(1);
    expect(sk.chainKey).not.toEqual(origChainKey);
  });

  it("rejects a message with wrong distribution ID", () => {
    const sk = generateSenderKey();
    const wire = senderKeyEncrypt(sk, plaintext());

    // Create a received key with a different distribution ID
    const wrongReceived: ReceivedSenderKey = {
      distributionId: randomBytes(16),
      chainKey: randomBytes(32),
      chainIndex: 0,
    };

    expect(() => senderKeyDecrypt(wire, wrongReceived)).toThrow("Distribution ID mismatch");
  });

  it("rejects a message with wrong type byte", () => {
    const sk = generateSenderKey();
    const wire = senderKeyEncrypt(sk, plaintext());
    wire[0] = 0x01; // DM type, not group

    const received = cloneSenderKey(sk);
    received.chainIndex = 0;
    expect(() => senderKeyDecrypt(wire, received)).toThrow("Expected group message type");
  });
});

// ─── Self-decryption (the critical bug fix) ────────────

describe("self-decryption: sender decrypts own messages via cloned key", () => {
  it("decrypts own message using a clone made at generation time", () => {
    const sk = generateSenderKey();
    // Clone at generation time (chainIndex 0) — this is what the client does
    const selfCopy = cloneSenderKey(sk);

    const msg = new TextEncoder().encode("my own message");
    const wire = senderKeyEncrypt(sk, msg);

    // The self-copy should be able to decrypt by ratcheting forward
    const decrypted = senderKeyDecrypt(wire, selfCopy);
    expect(decrypted).toEqual(msg);
  });

  it("decrypts multiple own messages using the same clone", () => {
    const sk = generateSenderKey();
    const selfCopy = cloneSenderKey(sk);

    const messages = ["first", "second", "third", "fourth", "fifth"];
    const wires = messages.map((m) => senderKeyEncrypt(sk, new TextEncoder().encode(m)));

    // Decrypt all in order using the self-copy
    for (let i = 0; i < wires.length; i++) {
      const dec = senderKeyDecrypt(wires[i], selfCopy);
      expect(new TextDecoder().decode(dec)).toBe(messages[i]);
    }
  });

  it("clone is independent — encrypting does not mutate the clone", () => {
    const sk = generateSenderKey();
    const selfCopy = cloneSenderKey(sk);

    const origCloneChainKey = new Uint8Array(selfCopy.chainKey);
    const origCloneIndex = selfCopy.chainIndex;

    // Encrypt 5 messages — this should only mutate sk, not selfCopy
    for (let i = 0; i < 5; i++) {
      senderKeyEncrypt(sk, plaintext());
    }

    // Clone should be untouched
    expect(selfCopy.chainKey).toEqual(origCloneChainKey);
    expect(selfCopy.chainIndex).toBe(origCloneIndex);
  });

  it("self-copy can catch up after many skipped encryptions", () => {
    const sk = generateSenderKey();
    const selfCopy = cloneSenderKey(sk);

    // Encrypt 100 messages but only try to decrypt the last one
    let lastWire: Uint8Array = new Uint8Array(0);
    for (let i = 0; i < 100; i++) {
      lastWire = senderKeyEncrypt(sk, new TextEncoder().encode(`msg-${i}`));
    }

    // Self-copy is at index 0, message is at index 99 — needs to ratchet 100 steps
    const dec = senderKeyDecrypt(lastWire, selfCopy);
    expect(new TextDecoder().decode(dec)).toBe("msg-99");

    // Self-copy should now be at index 100
    expect(selfCopy.chainIndex).toBe(100);
  });
});

// ─── Chain ratcheting edge cases ───────────────────────

describe("chain ratcheting", () => {
  it("skipped messages: can decrypt message N without decrypting 0..N-1 first", () => {
    const sk = generateSenderKey();
    const received = cloneSenderKey(sk);

    // Encrypt 5 messages, keep only the 5th (index 4)
    let fifthWire: Uint8Array = new Uint8Array(0);
    for (let i = 0; i < 5; i++) {
      const wire = senderKeyEncrypt(sk, new TextEncoder().encode(`msg-${i}`));
      if (i === 4) fifthWire = wire;
    }

    // Decrypt only the 5th message — receiver ratchets from 0 to 4
    const dec = senderKeyDecrypt(fifthWire, received);
    expect(new TextDecoder().decode(dec)).toBe("msg-4");
    expect(received.chainIndex).toBe(5);
  });

  it("rejects messages with chain index before current state", () => {
    const sk = generateSenderKey();
    const received = cloneSenderKey(sk);

    // Encrypt 3 messages
    const wires = [0, 1, 2].map((i) =>
      senderKeyEncrypt(sk, new TextEncoder().encode(`msg-${i}`)),
    );

    // Decrypt message at index 2, advancing received to index 3
    senderKeyDecrypt(wires[2], received);
    expect(received.chainIndex).toBe(3);

    // Trying to decrypt message at index 0 should fail (already consumed)
    expect(() => senderKeyDecrypt(wires[0], received)).toThrow("already consumed");
  });

  it("rejects messages that skip more than MAX_SKIP (256)", () => {
    const sk = generateSenderKey();
    const received = cloneSenderKey(sk);

    // Encrypt 258 messages, try to decrypt only the last one
    let lastWire: Uint8Array = new Uint8Array(0);
    for (let i = 0; i < 258; i++) {
      lastWire = senderKeyEncrypt(sk, new TextEncoder().encode(`msg-${i}`));
    }

    // Receiver is at index 0, message at index 257 — skip of 258 > MAX_SKIP (256)
    expect(() => senderKeyDecrypt(lastWire, received)).toThrow("Too many skipped");
  });

  it("exactly MAX_SKIP (256) skipped messages is allowed", () => {
    const sk = generateSenderKey();
    const received = cloneSenderKey(sk);

    // Encrypt 257 messages (indices 0-256), decrypt only the last (index 256)
    // Skip = 256 - 0 = 256, which equals MAX_SKIP and should succeed
    let lastWire: Uint8Array = new Uint8Array(0);
    for (let i = 0; i < 257; i++) {
      lastWire = senderKeyEncrypt(sk, new TextEncoder().encode(`msg-${i}`));
    }

    const dec = senderKeyDecrypt(lastWire, received);
    expect(new TextDecoder().decode(dec)).toBe("msg-256");
  });
});

// ─── Wire format integrity ─────────────────────────────

describe("wire format", () => {
  it("first byte is GROUP_MSG_TYPE (0x03)", () => {
    const sk = generateSenderKey();
    const wire = senderKeyEncrypt(sk, plaintext());
    expect(wire[0]).toBe(0x03);
  });

  it("embeds the distribution ID at bytes 1-16", () => {
    const sk = generateSenderKey();
    const distId = new Uint8Array(sk.distributionId);
    const wire = senderKeyEncrypt(sk, plaintext());
    expect(wire.slice(1, 17)).toEqual(distId);
  });

  it("embeds the chain index as uint32 LE at bytes 17-20", () => {
    const sk = generateSenderKey();
    // Encrypt 3 messages so index is 2 for the third
    senderKeyEncrypt(sk, plaintext());
    senderKeyEncrypt(sk, plaintext());
    const wire = senderKeyEncrypt(sk, plaintext());

    const view = new DataView(wire.buffer, wire.byteOffset, wire.byteLength);
    expect(view.getUint32(17, true)).toBe(2);
  });

  it("tampered ciphertext fails decryption", () => {
    const sk = generateSenderKey();
    const received = cloneSenderKey(sk);
    const wire = senderKeyEncrypt(sk, plaintext());

    // Flip a byte in the ciphertext area (after the 45-byte header)
    wire[50] ^= 0xff;

    expect(() => senderKeyDecrypt(wire, received)).toThrow();
  });

  it("tampered nonce fails decryption", () => {
    const sk = generateSenderKey();
    const received = cloneSenderKey(sk);
    const wire = senderKeyEncrypt(sk, plaintext());

    // Flip a byte in the nonce area (bytes 21-44)
    wire[25] ^= 0xff;

    expect(() => senderKeyDecrypt(wire, received)).toThrow();
  });
});
