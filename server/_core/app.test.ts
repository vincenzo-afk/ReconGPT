import { describe, expect, it } from "vitest";
import { createApiApp } from "./app";

describe("createApiApp", () => {
  it("returns an Express-compatible request handler for serverless adapters", () => {
    const app = createApiApp();

    expect(typeof app).toBe("function");
    expect(app.handle).toBeTypeOf("function");
  });
});
