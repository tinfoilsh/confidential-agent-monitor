import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { initiateNK } from "./noise";

type Vector = {
  init_prologue: string;
  init_ephemeral: string;
  init_remote_static: string;
  handshake_hash?: string;
  messages: { payload: string; ciphertext: string }[];
};

const load = (file: string): Vector[] =>
  JSON.parse(readFileSync(new URL(`testdata/${file}`, import.meta.url), "utf8"))
    .vectors;
const vectors = [
  ...load("noise-nk-published.json"),
  ...load("noise-nk-flynn.json"),
];

const initiate = (v: Vector, prologue = v.init_prologue) =>
  initiateNK(
    hexToBytes(v.init_remote_static),
    hexToBytes(prologue),
    hexToBytes(v.messages[0].payload),
    hexToBytes(v.init_ephemeral),
  );

const flip = (hex: string, seed: number) => {
  const bytes = hexToBytes(hex);
  bytes[seed % bytes.length] ^= 1 << (seed % 8);
  return bytes;
};

test("reproduces every NK vector", () => {
  for (const v of vectors) {
    const [first, reply, ...rest] = v.messages;
    const handshake = initiate(v);
    assert.equal(bytesToHex(handshake.message), first.ciphertext);
    const { payload, hash, send, recv } = handshake.finish(
      hexToBytes(reply.ciphertext),
    );
    assert.equal(bytesToHex(payload), reply.payload);
    if (v.handshake_hash) assert.equal(bytesToHex(hash), v.handshake_hash);
    rest.forEach(({ payload, ciphertext }, i) =>
      i % 2 === 0
        ? assert.equal(
            bytesToHex(send.encrypt(hexToBytes(payload))),
            ciphertext,
          )
        : assert.equal(
            bytesToHex(recv.decrypt(hexToBytes(ciphertext))),
            payload,
          ),
    );
  }
});

test("rejects altered server messages and prologues", () => {
  vectors.forEach((v, seed) => {
    const [, reply, ...rest] = v.messages;
    assert.throws(() => initiate(v).finish(flip(reply.ciphertext, seed)));
    assert.throws(() =>
      initiate(v, v.init_prologue + "00").finish(hexToBytes(reply.ciphertext)),
    );
    const { recv } = initiate(v).finish(hexToBytes(reply.ciphertext));
    rest.forEach(({ payload, ciphertext }, i) => {
      if (i % 2 === 0) return;
      assert.throws(() => recv.decrypt(flip(ciphertext, seed + i)));
      assert.equal(bytesToHex(recv.decrypt(hexToBytes(ciphertext))), payload);
    });
  });
});
