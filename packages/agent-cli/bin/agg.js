#!/usr/bin/env node
// agg: thin executable around the core's deterministic agent CLI (runAgentCli).
import { readFileSync } from "node:fs";
import { defaultConfigDir, runAgentCli } from "@agent-aggregator/core/cli";

const { version } = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));

/** @returns {Promise<string>} */
async function readStdin() {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  return Buffer.concat(chunks).toString("utf8");
}

process.exitCode = await runAgentCli(
  process.argv.slice(2),
  {
    command: "agg",
    envPrefix: "AGG",
    configDir: defaultConfigDir("agent-aggregator"),
    userAgent: `agent-aggregator-cli/${version}`,
    cronMarker: "agent-aggregator-poller",
  },
  {
    stdout: (text) => process.stdout.write(text),
    stderr: (text) => process.stderr.write(text),
    env: process.env,
    readStdin,
  },
);
