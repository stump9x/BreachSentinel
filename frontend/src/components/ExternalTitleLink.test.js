import { describe, expect, it } from "vitest";
import { resolveThreatHref } from "./ExternalTitleLink";

describe("resolveThreatHref", () => {
  it("uses the source detail URL when available", () => {
    expect(
      resolveThreatHref({
        source: "ransomware",
        source_url: "https://www.ransomware.live/id/example",
      })
    ).toBe("https://www.ransomware.live/id/example");
  });

  it("falls back to ransomware.live when the upstream detail URL is missing", () => {
    expect(resolveThreatHref({ source: "ransomware", source_url: "" })).toBe(
      "https://www.ransomware.live/"
    );
  });

  it("does not create a fallback for unrelated threats", () => {
    expect(resolveThreatHref({ source: "rss", source_url: "" })).toBe("");
  });
});
