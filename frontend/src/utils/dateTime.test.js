import { describe, expect, it } from "vitest";
import { compareWireRows } from "./dateTime";

describe("The Wire order", () => {
  const now = Date.parse("2026-09-17T01:00:00Z");

  it("places a recent story before an older high-priority story", () => {
    const recent = {
      id: 2,
      published_at: "2026-09-17T00:00:00Z",
      created_at: "2026-09-17T00:10:00Z",
      wire_priority: 25,
    };
    const oldPinned = {
      id: 1,
      published_at: "2025-09-14T00:00:00Z",
      created_at: "2025-09-14T00:10:00Z",
      wire_priority: 100,
    };

    expect([oldPinned, recent].sort((a, b) => compareWireRows(a, b, now))).toEqual([
      recent,
      oldPinned,
    ]);
  });

  it("uses priority when publication times match", () => {
    const published_at = "2026-09-16T20:00:00Z";
    const low = { id: 2, published_at, wire_priority: 25 };
    const high = { id: 1, published_at, wire_priority: 100 };

    expect([low, high].sort((a, b) => compareWireRows(a, b, now))).toEqual([
      high,
      low,
    ]);
  });
});
