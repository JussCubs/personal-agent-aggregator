#!/usr/bin/env node
import { prepareRuntime } from "./runtime.js";

if (await prepareRuntime(import.meta.url)) {
  const { main } = await import("../dist/bin/agg-server.js");
  process.exitCode = await main(process.argv.slice(2));
}
