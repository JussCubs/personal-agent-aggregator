// Shared startup for the agg-server and agg-owner executables.
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

/**
 * Makes node:sqlite available and quiet:
 * - hides the one-line ExperimentalWarning that node:sqlite prints (every other warning still prints);
 * - on Node 22.5–22.12, where node:sqlite needs --experimental-sqlite, re-runs the entry point with
 *   that flag and forwards signals and the exit code. Returns false when the child process took over.
 */
export async function prepareRuntime(entryUrl) {
  const listeners = process.listeners("warning");
  process.removeAllListeners("warning");
  process.on("warning", (warning) => {
    if (warning.name === "ExperimentalWarning" && /SQLite/i.test(warning.message)) return;
    for (const listener of listeners) listener(warning);
  });
  try {
    await import("node:sqlite");
    return true;
  } catch (error) {
    if (process.execArgv.includes("--experimental-sqlite")) throw error;
    const child = spawn(process.execPath, ["--experimental-sqlite", ...process.execArgv, fileURLToPath(entryUrl), ...process.argv.slice(2)], { stdio: "inherit" });
    for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"]) process.on(signal, () => child.kill(signal));
    child.on("exit", (code, signal) => {
      process.exitCode = code ?? (signal ? 1 : 0);
    });
    return false;
  }
}
