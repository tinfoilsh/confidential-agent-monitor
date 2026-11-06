import { createMemo, untrack, type Accessor } from "solid-js";
import { isProposal, ordered, stateAt, type RequestRecord } from "./owner.js";

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
  const requests = createMemo(() =>
    records().filter((record) => !isProposal(record)),
  );
  const proposals = createMemo(() => records().filter(isProposal));
  const pendingRequests = createMemo(() =>
    ordered(requests().filter((record) => record.state === "pending")),
  );
  const pendingProposals = createMemo(() =>
    proposals().filter((record) => record.state === "pending"),
  );
  const pendingCount = () =>
    pendingRequests().length + pendingProposals().length;
  return {
    byId,
    pendingCount,
    requests,
    proposals,
    pendingRequests,
    pendingProposals,
  };
}
