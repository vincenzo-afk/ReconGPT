import { describe, expect, it } from "vitest";
import { mediaMetadataForTests } from "./mediaMetadata";

describe("ReconGPT provided-media safety", () => {
  it("accepts only matching image signatures and retains a fixed size ceiling", () => {
    expect(mediaMetadataForTests.validSignature(Buffer.from([0xff, 0xd8, 0xff, 0xe0]), "image/jpeg")).toBe(true);
    expect(mediaMetadataForTests.validSignature(Buffer.from("not-an-image"), "image/jpeg")).toBe(false);
    expect(mediaMetadataForTests.MAX_BYTES).toBe(12 * 1024 * 1024);
  });
});
