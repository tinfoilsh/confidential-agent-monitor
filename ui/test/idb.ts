import "fake-indexeddb/auto";
import { afterEach, beforeEach } from "bun:test";

// The schema src/hosted/keys.ts creates, opened here as another tab would.
const DB = "tinfoil.manual-kek";
const STORE = "records";

const request = <T>(req: IDBRequest<T>) =>
  new Promise<T>((resolve, reject) => {
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });

async function connect() {
  const req = indexedDB.open(DB, 1);
  req.onupgradeneeded = () => req.result.createObjectStore(STORE);
  const db = await request(req);
  db.onversionchange = () => db.close();
  return db;
}

// Kept so this file's reads are unaffected by fail().
const { getAll } = IDBObjectStore.prototype;

// Readwrite transactions requested so far, to order competing writers.
export const transactions = { readwrite: 0 };
const transaction = IDBDatabase.prototype.transaction;
IDBDatabase.prototype.transaction = function (
  this: IDBDatabase,
  ...args: Parameters<IDBDatabase["transaction"]>
) {
  if (args[1] === "readwrite") transactions.readwrite++;
  return transaction.apply(this, args);
};

const restores: (() => void)[] = [];
// Called by each test file: every test starts with an empty database (deleting
// it closes every connection, the cached one too) and no injected failure.
export function isolate() {
  beforeEach(() => request(indexedDB.deleteDatabase(DB)));
  afterEach(() => restores.splice(0).forEach((restore) => restore()));
}

// Every committed entry, read in its own transaction.
export async function stored() {
  const db = await connect();
  const store = db.transaction(STORE).objectStore(STORE);
  const [keys, values] = await Promise.all([
    request(store.getAllKeys()),
    request<string[]>(getAll.call(store)),
  ]);
  db.close();
  return new Map(keys.map((key, i) => [key as string, values[i]]));
}
export const kekRecords = async () =>
  [...(await stored()).keys()].filter((k) =>
    k.startsWith("tinfoil.manual-kek.v1|"),
  );

export async function put(key: string, value: string) {
  const db = await connect();
  const tx = db.transaction(STORE, "readwrite");
  tx.objectStore(STORE).put(value, key);
  await new Promise((resolve) => (tx.oncomplete = resolve));
  db.close();
}

// Keeps a readwrite transaction busy, so every later transaction waits behind
// it, until the returned release is called.
export async function hold() {
  const db = await connect();
  const tx = db.transaction(STORE, "readwrite");
  const store = tx.objectStore(STORE);
  let holding = true;
  const spin = () => {
    if (holding) store.get("").onsuccess = spin;
  };
  spin();
  return () => {
    holding = false;
    return new Promise<void>((resolve) => {
      tx.oncomplete = () => {
        db.close();
        resolve();
      };
    });
  };
}

// Until the test ends, matching object store calls throw `name`, or with
// "abort" are made and then have their transaction aborted.
export function fail(
  method: "put" | "delete" | "getAll",
  name: string,
  when: (...args: unknown[]) => boolean = () => true,
) {
  const proto = IDBObjectStore.prototype as unknown as Record<
    string,
    (this: IDBObjectStore, ...args: unknown[]) => unknown
  >;
  const original = proto[method];
  proto[method] = function (...args: unknown[]) {
    if (!when(...args)) return original.apply(this, args);
    if (name !== "abort") throw new DOMException("injected", name);
    const req = original.apply(this, args);
    this.transaction.abort();
    return req;
  };
  restores.push(() => (proto[method] = original));
}

// Makes indexedDB.open fail, as a browser with site storage blocked does.
export async function blocked() {
  await request(indexedDB.deleteDatabase(DB));
  const factory = globalThis.indexedDB;
  globalThis.indexedDB = {
    open() {
      throw new DOMException("injected", "SecurityError");
    },
  } as unknown as IDBFactory;
  restores.push(() => (globalThis.indexedDB = factory));
}
