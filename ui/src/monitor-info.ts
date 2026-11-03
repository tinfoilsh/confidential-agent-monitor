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

export function monitorCreatedAt(info: MonitorInfo): Date | undefined {
  if (typeof info.createdAt !== "string" || !info.createdAt) return;
  const date = new Date(info.createdAt);
  return Number.isFinite(date.getTime()) ? date : undefined;
}
