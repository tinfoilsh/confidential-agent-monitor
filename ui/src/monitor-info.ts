export type MonitorInfo = {
  name: string;
  release?: string;
  cpus?: number;
  memoryMb?: number | null;
  createdAt?: string;
};

export function monitorResources(info: MonitorInfo): string {
  const valid = (n: unknown): n is number =>
    typeof n === "number" && Number.isFinite(n) && n > 0;
  return [
    valid(info.cpus) ? `${info.cpus} CPU` : null,
    valid(info.memoryMb)
      ? info.memoryMb >= 1024
        ? `${info.memoryMb / 1024} GB RAM`
        : `${info.memoryMb} MB RAM`
      : null,
  ]
    .filter(Boolean)
    .join(" / ");
}

export function monitorReleaseURL(info: MonitorInfo): string | undefined {
  if (!info.release || !/^v\d+\.\d+\.\d+(?:[-+][\w.-]+)?$/.test(info.release))
    return;
  return `https://github.com/tinfoilsh/confidential-agent-monitor/releases/tag/${encodeURIComponent(info.release)}`;
}

export function monitorCreatedAt(info: MonitorInfo): Date | undefined {
  if (typeof info.createdAt !== "string" || !info.createdAt) return;
  const date = new Date(info.createdAt);
  return Number.isFinite(date.getTime()) ? date : undefined;
}
