import monitor from "../../../tinfoil-config.yml?raw";
import sandbox from "./sandbox-config.yml?raw";

// Trusted workload templates are compiled in, never taken from inventory.
export const TEMPLATES = { monitor, sandbox };
