import { chacha20poly1305 } from "@noble/ciphers/chacha.js";
import { x25519 } from "@noble/curves/ed25519.js";
import { blake2s } from "@noble/hashes/blake2.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { concatBytes, utf8ToBytes } from "@noble/hashes/utils.js";

// The name is longer than BLAKE2s's output, so the spec hashes it rather than padding it.
const PROTOCOL = utf8ToBytes("Noise_NK_25519_ChaChaPoly_BLAKE2s");
const KEY_BYTES = 32;
const NONCE_BYTES = 12;
const COUNTER_OFFSET = 4;
const MAX_NONCE = 2n ** 64n - 1n;

export type CipherState = {
  encrypt(plaintext: Uint8Array, ad?: Uint8Array): Uint8Array<ArrayBuffer>;
  decrypt(ciphertext: Uint8Array, ad?: Uint8Array): Uint8Array<ArrayBuffer>;
};

export type Transport = {
  payload: Uint8Array;
  hash: Uint8Array;
  send: CipherState;
  recv: CipherState;
};

// The counter advances only on success, as the spec requires after a failed decrypt.
function cipherState(key: Uint8Array): CipherState {
  let n = 0n;
  const aead = (ad?: Uint8Array) => {
    if (n === MAX_NONCE) throw new Error("The Noise nonce is exhausted.");
    const nonce = new Uint8Array(NONCE_BYTES);
    new DataView(nonce.buffer).setBigUint64(COUNTER_OFFSET, n, true);
    return chacha20poly1305(key, nonce, ad);
  };
  return {
    encrypt(plaintext, ad) {
      const ciphertext = aead(ad).encrypt(plaintext);
      n++;
      return ciphertext;
    },
    decrypt(ciphertext, ad) {
      const plaintext = aead(ad).decrypt(ciphertext);
      n++;
      return plaintext;
    },
  };
}

/** Noise NK as the initiator: `<- s`, then `-> e, es` and `<- e, ee`. */
export function initiateNK(
  serverKey: Uint8Array,
  prologue: Uint8Array,
  payload = new Uint8Array(),
  fixedEphemeralForTesting = x25519.utils.randomSecretKey(),
) {
  const ephemeral = fixedEphemeralForTesting;
  let h = blake2s(PROTOCOL),
    ck = h;
  const mixHash = (data: Uint8Array) => {
    h = blake2s(concatBytes(h, data));
  };
  const deriveKeys = (secret: Uint8Array) =>
    hkdf(blake2s, secret, ck, undefined, 2 * KEY_BYTES);
  const mixKey = (secret: Uint8Array) => {
    const keys = deriveKeys(secret);
    ck = keys.slice(0, KEY_BYTES);
    return cipherState(keys.slice(KEY_BYTES));
  };
  const e = x25519.getPublicKey(ephemeral);
  mixHash(prologue);
  mixHash(serverKey);
  mixHash(e);
  const sealed = mixKey(x25519.getSharedSecret(ephemeral, serverKey)).encrypt(
    payload,
    h,
  );
  mixHash(sealed);
  return {
    message: concatBytes(e, sealed),
    finish(reply: Uint8Array): Transport {
      const re = reply.subarray(0, KEY_BYTES),
        sealed = reply.subarray(KEY_BYTES);
      mixHash(re);
      const payload = mixKey(x25519.getSharedSecret(ephemeral, re)).decrypt(
        sealed,
        h,
      );
      mixHash(sealed);
      const keys = deriveKeys(new Uint8Array());
      return {
        payload,
        hash: h,
        send: cipherState(keys.slice(0, KEY_BYTES)),
        recv: cipherState(keys.slice(KEY_BYTES)),
      };
    },
  };
}
