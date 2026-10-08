import type { AggregatorService } from "@agent-aggregator/core";
import type { ServerConfig } from "./config.js";
import type { Limits } from "./limits.js";
import type { Logger } from "./log.js";
import type { Storage } from "./storage.js";

export const SERVER_NAME = "agent-aggregator";
export const SERVER_VERSION = "0.2.0";
export const PRODUCT_NAME = "Agent aggregator";

/** Everything a route handler needs. `publicUrl` is fixed once the server listens. */
export interface AppContext {
  readonly config: ServerConfig;
  readonly service: AggregatorService;
  readonly storage: Storage;
  readonly limits: Limits;
  readonly logger: Logger;
  /** Key for consent-form CSRF tokens, derived from the encryption key. */
  readonly csrfKey: Buffer;
  publicUrl: string;
}

export function urls(ctx: AppContext) {
  const base = ctx.publicUrl;
  return {
    base,
    issuer: base,
    mcp: `${base}/mcp`,
    api: `${base}/api`,
    resourceMetadata: `${base}/.well-known/oauth-protected-resource/mcp`,
    authorize: `${base}/oauth/authorize`,
    token: `${base}/oauth/token`,
    register: `${base}/oauth/register`,
    revoke: `${base}/oauth/revoke`,
  };
}
