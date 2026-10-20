import { createMemo, untrack, type Accessor } from "solid-js";
import { stateAt, type RequestRecord } from "./owner.js";

// Share request state between the list, navigation and title. The existing clock
// only invalidates the log when it crosses a deadline, not on every countdown.
export function createRequestLog(
  source: Accessor<RequestRecord[]>,
  now: Accessor<number>,
) {
  const pending = createMemo(() =>
    source().filter((record) => record.state === "pending"),
  );
  const deadlines = createMemo(() =>
    pending()
      .map((record) => Date.parse(record.expires ?? ""))
      .filter(Number.isFinite)
      .sort((a, b) => a - b),
  );
  const expired = createMemo(() => {
    const times = deadlines();
    if (!times.length) return 0;
    const time = now();
    let start = 0,
      end = times.length;
    while (start < end) {
      const middle = (start + end) >>> 1;
      if (times[middle] <= time) start = middle + 1;
      else end = middle;
    }
    return start;
  });
  const records = createMemo(() => {
    const current = source();
    if (!expired()) return current;
    const time = untrack(now);
    return current.map((record) => {
      const state = stateAt(record, time);
      return state === record.state ? record : { ...record, state };
    });
  });
  const byId = createMemo(
    () => new Map(records().map((record) => [record.id, record])),
  );
  const pendingCount = createMemo(() => pending().length - expired());
  return { records, byId, pendingCount };
}
