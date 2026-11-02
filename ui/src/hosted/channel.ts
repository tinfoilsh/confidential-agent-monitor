import { chacha20poly1305 } from "@noble/ciphers/chacha.js";
import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { blake2s } from "@noble/hashes/blake2.js";
import { hmac } from "@noble/hashes/hmac.js";
import { concatBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import {
  Handshake,
  type AEAD,
  type Algorithms,
  type Nonce,
  type TransportState,
} from "salty-crypto";
import {
  OwnerError,
  fromBase64,
  toBase64,
  type OwnerChannel,
  type OwnerRpc,
} from "../owner";

const SESSION_CONTEXT = "tinfoil owner session v1\0";
// A frame is a flag byte, then data filling the rest of one Noise message.
const FRAME_BYTES = 65518,
  FRAME_MORE = 0,
  FRAME_LAST = 1;
const decoder = new TextDecoder();

// Noise's ChaChaPoly nonce is 4 zero bytes, then the 64-bit counter, little-endian.
const cipher = (key: DataView, { extra, lo, hi }: Nonce, ad?: Uint8Array) => {
  const nonce = new DataView(new ArrayBuffer(12));
  [extra, lo, hi].forEach((word, i) => nonce.setUint32(4 * i, word, true));
  return chacha20poly1305(
    new Uint8Array(key.buffer, key.byteOffset, 32),
    new Uint8Array(nonce.buffer),
    ad,
  );
};

// salty keeps only the Noise protocol logic; noble supplies every primitive.
class BLAKE2s {
  static NAME = "BLAKE2s";
  static KEYBYTES = 32;
  static OUTBYTES = 32;
  static BLOCKLEN = 64;
  static digest = (input: Uint8Array) => blake2s(input);
  #state = blake2s.create();
  update(input: Uint8Array) {
    this.#state.update(input);
  }
  final() {
    return this.#state.digest();
  }
}
const NOISE: Algorithms = {
  dh: {
    NAME: "25519",
    DHLEN: 32,
    generateKeypair: () => {
      const { secretKey, publicKey } = x25519.keygen();
      return { secret: secretKey, public: publicKey };
    },
    dh: (pair, peer) => x25519.getSharedSecret(pair.secret, peer),
  },
  aead: {
    NAME: "ChaChaPoly",
    KEYBYTES: 32,
    NONCEBYTES: 12,
    TAGBYTES: 16,
    encrypt: (plaintext, key, nonce, ad) =>
      cipher(key, nonce, ad).encrypt(plaintext),
    decrypt: (ciphertext, key, nonce, ad) =>
      cipher(key, nonce, ad).decrypt(ciphertext),
  } as AEAD,
  hash: BLAKE2s,
  hmac: Object.assign(
    (key: Uint8Array, data: Uint8Array) => hmac(blake2s, key, data),
    { NAME: "HMAC-BLAKE2s" },
  ),
};

/** An NK handshake to an attested key, then a hello signed by the owner over its hash. */
export type Session = {
  serverKey: Uint8Array;
  prologue: string;
  seed: Uint8Array;
  hello: object;
};

// Runs each session's handshake in turn over one WebSocket. The last carries the
// channel, so a relay session can tunnel the next through the server it reaches.
export async function openChannel(
  url: string,
  sessions: Session[],
  signal?: AbortSignal,
): Promise<OwnerChannel> {
  signal?.throwIfAborted();
  const socket = new WebSocket(url);
  socket.binaryType = "arraybuffer";
  signal?.addEventListener("abort", () => socket.close(), { once: true });
  const inbox: Uint8Array[] = [];
  let wake = () => {},
    closed: Error | undefined,
    transport!: TransportState;
  socket.onopen = () => wake();
  socket.onmessage = ({ data }) => (inbox.push(new Uint8Array(data)), wake());
  socket.onclose = ({ reason }) => {
    closed = new Error(reason || "The owner connection closed.");
    wake();
  };
  // salty types its output over any buffer, but it always allocates ArrayBuffers.
  const write = (data: Uint8Array) =>
    socket.send(data as Uint8Array<ArrayBuffer>);
  const until = async <T>(ready: () => T | undefined) => {
    for (let value; ; await new Promise<void>((resolve) => (wake = resolve))) {
      if ((value = ready()) !== undefined) return value;
      if (closed) throw closed;
    }
  };
  const send = (message: Uint8Array) => {
    if (closed) throw closed;
    for (let at = 0; ; at += FRAME_BYTES) {
      const last = at + FRAME_BYTES >= message.length;
      const flag = Uint8Array.of(last ? FRAME_LAST : FRAME_MORE);
      const data = message.subarray(at, at + FRAME_BYTES);
      write(transport.send.encrypt(concatBytes(flag, data)));
      if (last) return;
    }
  };
  await until(() => socket.readyState === WebSocket.OPEN || undefined);
  for (const { serverKey, prologue, seed, hello } of sessions) {
    const handshake = new Handshake(NOISE, "NK", "initiator", {
      prologue: utf8ToBytes(prologue),
      remoteStaticPublicKey: serverKey,
    });
    write(handshake.writeMessage(new Uint8Array()).packet);
    transport = handshake.readMessage(
      await until(() => inbox.shift()),
    ).finished!;
    const signed = concatBytes(
      utf8ToBytes(SESSION_CONTEXT),
      handshake.handshakeHash,
    );
    const signature = toBase64(ed25519.sign(signed, seed));
    send(utf8ToBytes(JSON.stringify({ signature, ...hello })));
  }
  return {
    send,
    async receive() {
      const parts: Uint8Array[] = [];
      for (;;) {
        const frame = transport.recv.decrypt(await until(() => inbox.shift()));
        parts.push(frame.subarray(1));
        if (frame[0] === FRAME_LAST) return concatBytes(...parts);
      }
    },
    close: () => socket.close(),
  };
}

type Reply = { id: number; status: number; body: string };

// Owner RPC over a channel opened on first use. Replies arrive by id in any order. A
// dropped socket fails its calls as outcome unknown, and the next call reconnects. A
// failed open refreshes attestation and retries once, since a new boot has a new key.
export function rpcChannel(
  open: () => Promise<OwnerChannel>,
  refresh: () => Promise<void>,
): OwnerRpc {
  let current: ReturnType<typeof connect> | undefined;
  async function connect() {
    const channel = await open().catch(async () => (await refresh(), open()));
    const pending = new Map<number, (reply: Reply | Error) => void>();
    let ids = 0;
    void (async () => {
      for (;;) {
        const reply: Reply = JSON.parse(
          decoder.decode(await channel.receive()),
        );
        pending.get(reply.id)?.(reply);
        pending.delete(reply.id);
      }
    })().catch((cause) => {
      current = undefined;
      const unknown = new Error(
        `The owner connection closed, so the outcome is unknown: ${cause.message}`,
      );
      for (const settle of pending.values()) settle(unknown);
    });
    return (call: object, signal?: AbortSignal) =>
      new Promise<Reply>((resolve, reject) => {
        const id = ids++;
        pending.set(id, (reply) =>
          reply instanceof Error ? reject(reply) : resolve(reply),
        );
        signal?.addEventListener(
          "abort",
          () => (pending.delete(id), reject(signal.reason)),
          { once: true },
        );
        channel.send(utf8ToBytes(JSON.stringify({ id, ...call })));
      });
  }
  return async (method, path, body, generation, signal) => {
    signal?.throwIfAborted();
    const send = await (current ??= connect().catch((cause) => {
      current = undefined;
      throw cause;
    }));
    const encoded = method === "GET" ? "" : JSON.stringify(body);
    const reply = await send(
      { method, path, generation, body: toBase64(utf8ToBytes(encoded)) },
      signal,
    );
    const text = decoder.decode(fromBase64(reply.body ?? ""));
    if (reply.status >= 400)
      throw new OwnerError(
        text.trim() || `Request failed (${reply.status})`,
        reply.status,
      );
    return text ? JSON.parse(text) : null;
  };
}
