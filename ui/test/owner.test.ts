import { expect, test } from "bun:test";
import { sealedOwnerClient, type OwnerCall } from "../src/owner";

const lostBody = () =>
  new Response(
    new ReadableStream({
      start: (c) => c.error(new TypeError("reply stream lost after headers")),
    }),
    { status: 200 },
  );

function client(replies: (() => Response)[]) {
  const signed: OwnerCall[] = [];
  const api = sealedOwnerClient({
    endpoint: "https://monitor.example",
    storageKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    sign: async (call) => {
      signed.push(structuredClone(call));
      return JSON.stringify(call);
    },
    fetch: (async () => replies.shift()!()) as typeof fetch,
  });
  return { api, signed };
}

test("a reply lost while its body streams is retried as the same operation", async () => {
  const { api, signed } = client([lostBody, () => Response.json({ ok: true })]);
  expect(await api.call("POST", "/enroll", {})).toEqual({ ok: true });
  expect(signed).toHaveLength(2);
  expect(signed[1].operation).toBe(signed[0].operation);
  expect(signed[1].issued_at).toBe(signed[0].issued_at);
});

test("forwarded sandbox ciphertext is never replayed by the Monitor client", async () => {
  const { api, signed } = client([lostBody, () => Response.json({ ok: true })]);
  await expect(api.call("POST", "/sandboxes/relay", {})).rejects.toThrow(
    "reply stream lost",
  );
  expect(signed).toHaveLength(1);
});

test("bodyless replies keep a null body, as browsers require", async () => {
  const Native = globalThis.Response;
  // Browsers reject any body, even an empty string, for these statuses.
  class BrowserResponse extends Native {
    constructor(body?: BodyInit | null, init?: ResponseInit) {
      if ([204, 205, 304].includes(init?.status ?? 200) && body !== null)
        throw new TypeError("Invalid response status code");
      super(body, init);
    }
  }
  const { api, signed } = client([() => new Native(null, { status: 204 })]);
  globalThis.Response = BrowserResponse as typeof Response;
  try {
    expect(await api.call("POST", "/enroll", {})).toBeNull();
    expect(signed).toHaveLength(1);
  } finally {
    globalThis.Response = Native;
  }
});
