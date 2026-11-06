#!/usr/bin/env node
import { readFile } from "node:fs/promises";
import { run } from "./cli.js";

async function readStdin(): Promise<string> {
  const chunks: string[] = [];
  process.stdin.setEncoding("utf8");
  for await (const chunk of process.stdin) {
    chunks.push(String(chunk));
  }
  return chunks.join("");
}

process.exitCode = await run(process.argv.slice(2), {
  stdout: (text) => {
    process.stdout.write(text);
  },
  stderr: (text) => {
    process.stderr.write(text);
  },
  stdin: readStdin,
  readFile: (path) => readFile(path, "utf8"),
  now: () => Math.floor(Date.now() / 1000),
});
