import { describe, expect, test } from "bun:test";
import { ed25519 } from "@noble/curves/ed25519.js";
import { KEM_DHKEM_X25519_HKDF_SHA256 } from "@panva/hpke-noble";
import { AEAD_AES_256_GCM, CipherSuite, KDF_HKDF_SHA256 } from "hpke";
import fixture from "./owner-contract-v1.json";
import {
  PRF_PROFILES,
  b64u,
  canonicalKeySyncRequest,
  confirmationCode,
  confirmationCodeMatches,
  keySyncEnvelopeInfo,
  manualKEKStorageKey,
  manualRecoveryFile,
  openMK,
  parseKeySyncCompletion,
  parseKeySyncLaunch,
  parseMKPayload,
  parseManualRecoveryFile,
  parseStartRequest,
  sealKeySyncEnvelope,
  sealMK,
  signOwnerRequest,
  startErrorURL,
  startReturnURL,
  unb64u,
  unwrapManualKEK,
  wrapManualKEK,
  type KeySyncRequest,
  type OwnerRequest,
} from "../src/hosted/contract";

const utf8 = (text: string) => new TextEncoder().encode(text);
const hash = (url: string) => new URL(url).hash;
const keySyncRequest = (
  r: typeof fixture.key_sync.request,
): KeySyncRequest => ({
  ...r,
  hpke_pubkey: unb64u(r.hpke_pubkey, 32),
});

describe("MK", () => {
  const { mk } = fixture;
  const dek = unb64u(mk.dek, 32);

  test("opens the Go- and TypeScript-sealed envelopes to the canonical payload", async () => {
    expect(mk.envelopes.map((e) => e.sealed_by)).toEqual(["go", "typescript"]);
    for (const { envelope } of mk.envelopes) {
      expect(JSON.stringify(await openMK(envelope, dek, mk.context))).toBe(
        mk.plaintext,
      );
      for (const wrong of mk.wrong_context)
        await expect(openMK(envelope, dek, wrong.context)).rejects.toThrow();
      await expect(
        openMK(envelope, unb64u(mk.wrong_dek, 32), mk.context),
      ).rejects.toThrow();
    }
    for (const wrong of mk.wrong_envelopes)
      await expect(openMK(wrong.envelope, dek, mk.context)).rejects.toThrow();
  });

  test("rejects invalid payloads and reseals with a fresh nonce", async () => {
    for (const invalid of mk.invalid_plaintexts)
      expect(() => parseMKPayload(invalid.plaintext), invalid.case).toThrow();
    const payload = parseMKPayload(mk.plaintext);
    const resealed = await sealMK(payload, dek, mk.context);
    expect(resealed).not.toBe(mk.envelopes[1].envelope);
    expect(await openMK(resealed, dek, mk.context)).toEqual(payload);
  });

  test("bounds are coherent and checked before decoding", async () => {
    const { limits } = fixture;
    const envelopeChars = (plaintext: number) =>
      "mk1.".length + 16 + 1 + Math.ceil(((plaintext + 16) * 4) / 3);
    expect(envelopeChars(limits.mk_plaintext_bytes_max)).toBe(
      limits.mk_envelope_chars_max,
    );
    expect(envelopeChars(limits.mk_plaintext_bytes_max + 1)).toBeGreaterThan(
      limits.mk_envelope_chars_max,
    );
    // Well-formed base64 of zeros: at the limit it reaches decryption, one past it is refused first.
    const head = `mk1.${b64u(new Uint8Array(12))}.`;
    const filler = (n: number) => head + "A".repeat(n - head.length);
    await expect(
      openMK(filler(limits.mk_envelope_chars_max), dek, mk.context),
    ).rejects.toThrow("does not open");
    await expect(
      openMK(filler(limits.mk_envelope_chars_max + 1), dek, mk.context),
    ).rejects.toThrow("damaged");
  });
});

describe("manual recovery", () => {
  const m = fixture.manual_kek;
  const kek = unb64u(m.kek, 32);

  test("unwraps the frozen DEK only in its own recovery context", async () => {
    expect(
      b64u(
        await unwrapManualKEK(m.encrypted_dek, kek, m.context, m.recovery_id),
      ),
    ).toBe(m.dek);
    await expect(
      unwrapManualKEK(m.encrypted_dek, kek, m.context, m.wrong_recovery_id),
    ).rejects.toThrow();
    for (const wrong of fixture.mk.wrong_context)
      await expect(
        unwrapManualKEK(m.encrypted_dek, kek, wrong.context, m.recovery_id),
      ).rejects.toThrow();
    const rewrapped = await wrapManualKEK(
      kek,
      unb64u(m.dek, 32),
      m.context,
      m.recovery_id,
    );
    expect(
      b64u(await unwrapManualKEK(rewrapped, kek, m.context, m.recovery_id)),
    ).toBe(m.dek);
  });

  test("file and localStorage record use the frozen encodings", () => {
    const file = parseManualRecoveryFile(m.file.replace(/\n/g, "\r\n"));
    expect([b64u(file.kek), file.dek_id, file.recovery_id]).toEqual([
      m.kek,
      m.context.dek_id,
      m.recovery_id,
    ]);
    expect(manualRecoveryFile(file)).toBe(m.file);
    expect(() =>
      parseManualRecoveryFile(
        m.file.replace('{"version":1,', '{"version":1 ,'),
      ),
    ).toThrow();
    expect(manualKEKStorageKey(m.context, m.recovery_id)).toBe(
      m.local_storage_key,
    );
  });

  test("PRF profiles are distinct and frozen", () => {
    for (const name of ["production", "development"] as const) {
      const want = fixture.passkey_profiles[name];
      const got = PRF_PROFILES[name];
      expect([
        got.relyingPartyId,
        b64u(got.prfSalt),
        b64u(got.hkdfInfo),
      ]).toEqual([want.relyingPartyId, want.prfSalt, want.hkdfInfo]);
    }
  });
});

describe("signed owner requests", () => {
  const o = fixture.owner_request;
  const verify = (owner: string, bytes: string, signature: string) =>
    ed25519.verify(
      unb64u(signature, 64),
      utf8(o.context + bytes),
      Uint8Array.from(atob(owner.slice("ed25519:".length)), (c) =>
        c.charCodeAt(0),
      ),
    );

  test("reproduces the frozen request bytes and signatures", () => {
    for (const r of o.requests) {
      const request = JSON.parse(r.bytes) as OwnerRequest;
      expect(new TextDecoder().decode(unb64u(request.body))).toBe(r.inner_body);
      expect(signOwnerRequest(unb64u(o.seed, 32), request)).toBe(r.envelope);
      expect(verify(o.owner, r.bytes, r.signature)).toBe(true);
    }
  });

  test("refuses to sign non-canonical or malformed fields", () => {
    for (const invalid of o.invalid_requests)
      expect(
        () =>
          signOwnerRequest(
            unb64u(o.seed, 32),
            JSON.parse(invalid.bytes) as OwnerRequest,
          ),
        invalid.case,
      ).toThrow();
  });

  test("only invalid_signature cases fail against the measured owner", () => {
    for (const r of o.server_rejects)
      expect(verify(r.server.owner, r.bytes, r.signature), r.case).toBe(
        r.error !== "invalid_signature",
      );
  });
});

describe("CLI key sync", () => {
  const l = fixture.key_sync;
  const request = keySyncRequest(l.request);

  test("parses the launch and derives the frozen code", () => {
    expect(
      parseKeySyncLaunch(hash(l.launch_url), l.request.expires - 300),
    ).toEqual(request);
    for (const now of [l.request.expires, l.request.expires - 601])
      expect(() => parseKeySyncLaunch(hash(l.launch_url), now)).toThrow();
    expect(() =>
      parseKeySyncLaunch(
        hash(l.launch_url) + "&account=personal",
        l.request.expires - 300,
      ),
    ).toThrow();
    const canonical = canonicalKeySyncRequest(request, l.targets);
    expect(new TextDecoder().decode(canonical)).toBe(l.canonical);
    expect(confirmationCode(canonical)).toBe(l.code);
    for (const input of l.code_inputs)
      expect(confirmationCodeMatches(input.input, l.code), input.input).toBe(
        input.matches,
      );
    for (const changed of l.changed_context_codes) {
      const code = confirmationCode(
        canonicalKeySyncRequest(
          keySyncRequest(changed.request),
          changed.targets,
        ),
      );
      expect(code, changed.case).toBe(changed.code);
      expect(code).not.toBe(l.code);
    }
  });

  test("opens the Go- and TypeScript-sealed callbacks only for the confirmed request", async () => {
    const suite = new CipherSuite(
      KEM_DHKEM_X25519_HKDF_SHA256,
      KDF_HKDF_SHA256,
      AEAD_AES_256_GCM,
    );
    const key = await suite.DeserializePrivateKey(
      unb64u(l.recipient_private_key, 32),
    );
    const open = async (payload: string, info: Uint8Array) => {
      const sealed = unb64u(payload);
      return new TextDecoder().decode(
        await suite.Open(key, sealed.subarray(0, 32), sealed.subarray(32), {
          info,
        }),
      );
    };
    expect(l.payloads.map((p) => p.sealed_by)).toEqual(["go", "typescript"]);
    const info = keySyncEnvelopeInfo(
      canonicalKeySyncRequest(request, l.targets),
    );
    for (const { payload } of l.payloads) {
      expect(await open(payload, info)).toBe(l.envelope_plaintext);
      for (const changed of l.changed_context_codes)
        await expect(
          open(
            payload,
            keySyncEnvelopeInfo(
              canonicalKeySyncRequest(
                keySyncRequest(changed.request),
                changed.targets,
              ),
            ),
          ),
        ).rejects.toThrow();
    }
    const envelope = JSON.parse(l.envelope_plaintext);
    const dek = { dek_id: envelope.dek_id, dek: unb64u(envelope.dek, 32) };
    await expect(
      sealKeySyncEnvelope(request, l.targets, { user_id: "user_other", dek }),
    ).rejects.toThrow();
    await expect(
      sealKeySyncEnvelope(request, l.targets, {
        user_id: envelope.user_id,
        dek: { ...dek, dek: new Uint8Array(31) },
      }),
    ).rejects.toThrow();
    expect(
      await open(
        await sealKeySyncEnvelope(request, l.targets, {
          user_id: envelope.user_id,
          dek,
        }),
        info,
      ),
    ).toBe(l.envelope_plaintext);
    expect(parseKeySyncCompletion(hash(l.completion_url))).toEqual({
      request: l.request.request,
      user: fixture.mk.context.user_id,
      account: "org_2fixtureB",
    });
  });
});

describe("/start", () => {
  const s = fixture.start;
  const dashboard = "https://dash.tinfoil.sh/?tab=sandboxes";

  test("parses the key-only request and builds the key-only return", () => {
    const request = parseStartRequest(hash(s.request_url));
    expect(request).toEqual(s.request as typeof request);
    expect(startReturnURL(dashboard, request, s.keys)).toBe(s.return_url);
    expect(startErrorURL(dashboard, s.request.state, "setup_lost")).toBe(
      s.error_return_url,
    );
    for (const reject of s.reject_requests)
      expect(() => parseStartRequest(hash(reject.url)), reject.case).toThrow();
  });
});
