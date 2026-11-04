import { ed25519 } from "@noble/curves/ed25519.js";
import { concatBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import { Handshake, type Transport } from "@tinfoilsh/noise";
import {
  OwnerError,
  fromBase64,
  toBase64,
  type OwnerChannel,
  type OwnerRpc,
} from "../monitor/owner";

const PROTOCOL = "Noise_NK_25519_ChaChaPoly_BLAKE2s";
const SESSION_CONTEXT = "tinfoil owner session v1\0";
// A frame is a flag byte, then data filling the rest of one Noise message.
const FRAME_BYTES = 65518,
  FRAME_MORE = 0,
  FRAME_LAST = 1;
const decoder = new TextDecoder();

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
  let reason = "The owner connection closed.",
    transport!: Transport;
  // Closing keeps queued messages readable, so a final message is not lost.
  const inbox = new ReadableStream<ArrayBuffer>({
    start(queue) {
      socket.onmessage = ({ data }) => queue.enqueue(data);
      socket.onclose = (event) => {
        reason = event.reason || reason;
        queue.close();
      };
    },
  }).getReader();
  const next = async () => {
    const { done, value } = await inbox.read();
    if (done) throw new Error(reason);
    return new Uint8Array(value);
  };
  const send = (message: Uint8Array) => {
    if (socket.readyState !== WebSocket.OPEN) throw new Error(reason);
    for (let at = 0; ; at += FRAME_BYTES) {
      const last = at + FRAME_BYTES >= message.length;
      const flag = Uint8Array.of(last ? FRAME_LAST : FRAME_MORE);
      const data = message.subarray(at, at + FRAME_BYTES);
      socket.send(transport.writeMessage(concatBytes(flag, data)));
      if (last) return;
    }
  };
  await new Promise((resolve, reject) => {
    socket.onopen = resolve;
    socket.onerror = () => reject(new Error(reason));
  });
  for (const { serverKey, prologue, seed, hello } of sessions) {
    const handshake = Handshake.initiator({
      protocol: PROTOCOL,
      prologue: utf8ToBytes(prologue),
      remoteStaticPublicKey: serverKey,
    });
    socket.send(handshake.writeMessage());
    handshake.readMessage(await next());
    transport = handshake.intoTransport();
    const signed = concatBytes(
      utf8ToBytes(SESSION_CONTEXT),
      transport.handshakeHash,
    );
    const signature = toBase64(ed25519.sign(signed, seed));
    send(utf8ToBytes(JSON.stringify({ signature, ...hello })));
  }
  return {
    send,
    async receive() {
      const parts: Uint8Array[] = [];
      for (;;) {
        const frame = transport.readMessage(await next());
        if (frame[0] !== FRAME_LAST && frame[0] !== FRAME_MORE)
          throw new Error("The owner connection sent a malformed message.");
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
