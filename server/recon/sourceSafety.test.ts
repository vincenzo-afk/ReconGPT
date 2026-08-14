import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

function sourceFiles(directory: string): string[] {
  return readdirSync(directory).flatMap(entry => {
    const path = join(directory, entry);
    return statSync(path).isDirectory() ? sourceFiles(path) : [path];
  });
}

describe("ReconGPT credential boundaries", () => {
  it("does not place credential-shaped values in browser or server source", () => {
    const files = ["client", "server", "drizzle"].flatMap(directory => sourceFiles(join(process.cwd(), directory))).filter(path => /\.(?:ts|tsx|css)$/.test(path));
    const values = files.map(path => readFileSync(path, "utf8")).join("\n");
    expect(values).not.toMatch(/gsk_[A-Za-z0-9_-]{20,}/);
    expect(values).not.toMatch(/(?:sk|rk)_[A-Za-z0-9_-]{24,}/);
    expect(values).not.toMatch(/(?:api[_-]?key|token|secret)\s*[:=]\s*["'][A-Za-z0-9_-]{16,}["']/i);
  });
});
