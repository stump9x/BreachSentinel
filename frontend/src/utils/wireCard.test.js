import { describe, expect, it } from "vitest";
import { wireFeedName } from "./wireCard";

describe("wireFeedName", () => {
  it("prefers the RSS feed name from raw_payload", () => {
    expect(
      wireFeedName({ source: "news", raw_payload: { feed: "scmp-china" } })
    ).toBe("scmp-china");
  });

  it("falls back to the source category", () => {
    expect(wireFeedName({ source: "cert", raw_payload: {} })).toBe("cert");
    expect(wireFeedName({ source: "ransomware" })).toBe("ransomware");
    expect(wireFeedName(null)).toBe("");
  });
});
