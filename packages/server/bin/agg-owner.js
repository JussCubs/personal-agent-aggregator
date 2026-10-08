#!/usr/bin/env node
import { prepareRuntime } from "./runtime.js";

if (await prepareRuntime(import.meta.url)) {
  const { runOwnerCli } = await import("../dist/owner-cli.js");
  process.exitCode = await runOwnerCli(process.argv.slice(2), {
    stdout: (text) => process.stdout.write(text),
    stderr: (text) => process.stderr.write(text),
    env: process.env,
  });
}
