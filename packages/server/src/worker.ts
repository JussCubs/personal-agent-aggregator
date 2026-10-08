import type { AggregatorService } from "@agent-aggregator/core";
import { errorFields, type Logger } from "./log.js";

export interface WorkerOptions {
  /** How often due deliveries are attempted. Default 2000 ms. */
  deliverEveryMs?: number;
  /** How often questions expire and old rows are pruned. Default 60000 ms. */
  sweepEveryMs?: number;
  /** Extra work run with every sweep (e.g. pruning in-memory limits). */
  onSweep?: () => void;
}

export interface Worker {
  /** Runs a delivery pass soon (called when new deliveries are queued). */
  kick(): void;
  stop(): Promise<void>;
}

const BATCH = 50;

/**
 * The delivery loop: every 2 s it sends due webhook and MCP-event deliveries
 * (signed, retried with backoff by the core), and every 60 s it expires
 * questions and prunes old events. Passes never overlap.
 */
export function startWorker(service: AggregatorService, logger: Logger, opts: WorkerOptions = {}): Worker {
  let delivering: Promise<void> | null = null;
  let again = false;
  let sweeping: Promise<void> | null = null;
  let stopped = false;

  const deliver = (): void => {
    if (stopped) return;
    if (delivering) {
      again = true;
      return;
    }
    delivering = (async () => {
      try {
        do {
          again = false;
          const result = await service.deliverDue({ limit: BATCH });
          const total = result.delivered + result.failed + result.retried;
          if (total > 0) logger.info("deliveries", result);
          if (total >= BATCH) again = true;
        } while (again && !stopped);
      } catch (error) {
        logger.error("delivery_error", errorFields(error));
      } finally {
        delivering = null;
      }
    })();
  };

  const sweep = (): void => {
    if (stopped || sweeping) return;
    sweeping = (async () => {
      try {
        const result = await service.sweep();
        opts.onSweep?.();
        if (result.expired > 0 || result.prunedEvents > 0) logger.info("sweep", result);
      } catch (error) {
        logger.error("sweep_error", errorFields(error));
      } finally {
        sweeping = null;
      }
    })();
  };

  const deliverTimer = setInterval(deliver, opts.deliverEveryMs ?? 2000);
  const sweepTimer = setInterval(sweep, opts.sweepEveryMs ?? 60_000);
  deliverTimer.unref();
  sweepTimer.unref();

  return {
    kick() {
      if (!stopped) setImmediate(deliver);
    },
    async stop() {
      stopped = true;
      clearInterval(deliverTimer);
      clearInterval(sweepTimer);
      await Promise.allSettled([delivering, sweeping].filter(Boolean) as Promise<void>[]);
    },
  };
}
