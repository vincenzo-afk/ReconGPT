import { describe, expect, it } from "vitest";
import { usernamePresenceForTests } from "./usernamePresence";

describe("ReconGPT bounded username-presence catalogue", () => {
  it("maintains a large review catalogue while enforcing a small automation budget", () => {
    expect(usernamePresenceForTests.catalogSize()).toBeGreaterThanOrEqual(100);
    expect(usernamePresenceForTests.usernameCheckBudget("focused")).toBe(6);
    expect(usernamePresenceForTests.usernameCheckBudget("balanced")).toBe(12);
    expect(usernamePresenceForTests.usernameCheckBudget("deep")).toBe(18);
  });

  it("encodes handles and treats restrictions as indeterminate evidence", () => {
    expect(usernamePresenceForTests.profileUrl("https://example.test/{u}", "@a name")).toBe("https://example.test/a%20name");
    expect(usernamePresenceForTests.statusFromResponse(new Response("", { status: 429 }), "analyst", "")).toBe("restricted");
  });
});
