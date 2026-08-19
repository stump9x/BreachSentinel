import { describe, expect, it } from "vitest";
import {
  compareByWireDisplayTime,
  compareWireRows,
  formatDateWithRelative,
  formatWireDateWithRelative,
  relativeTimeLabel,
  wireDisplayInstantMs,
} from "./dateTime";

describe("formatDateWithRelative", () => {
  const published = new Date(2026, 6, 16, 10, 0, 0);

  it("formats dd/mm/yyyy with minutes ago", () => {
    expect(
      formatDateWithRelative(
        published.toISOString(),
        published.getTime() + 12 * 60_000
      )
    ).toBe("16/07/2026 · 12 minutes ago");
  });

  it("uses hours and days for older timestamps", () => {
    expect(
      formatDateWithRelative(
        published.toISOString(),
        published.getTime() + 3 * 60 * 60_000
      )
    ).toBe("16/07/2026 · 3 hours ago");
    expect(
      formatDateWithRelative(
        published.toISOString(),
        published.getTime() + 4 * 24 * 60 * 60_000
      )
    ).toBe("16/07/2026 · 4 days ago");
  });

  it("handles missing and invalid timestamps", () => {
    expect(formatDateWithRelative("")).toBe("—");
    expect(formatDateWithRelative("invalid")).toBe("—");
  });
});

describe("relativeTimeLabel", () => {
  it("returns just now under one minute", () => {
    const base = Date.UTC(2026, 6, 20, 8, 0, 0);
    expect(relativeTimeLabel(new Date(base).toISOString(), base + 30_000)).toBe(
      "just now"
    );
  });
});

describe("wireDisplayInstant / formatWireDateWithRelative", () => {
  const wireNow = Date.UTC(2026, 6, 20, 8, 0, 0);

  it("uses created_at when published_at would be just now but row is older", () => {
    const row = {
      published_at: new Date(wireNow - 20_000).toISOString(),
      created_at: new Date(wireNow - 5 * 60_000).toISOString(),
    };
    expect(formatWireDateWithRelative(row, wireNow)).toBe(
      "20/07/2026 · 5 minutes ago"
    );
  });

  it("keeps published_at when it is already older than just now", () => {
    const row = {
      published_at: new Date(wireNow - 12 * 60_000).toISOString(),
      created_at: new Date(wireNow - 2 * 60_000).toISOString(),
    };
    expect(formatWireDateWithRelative(row, wireNow)).toBe(
      "20/07/2026 · 12 minutes ago"
    );
  });

  it("shows just now from created_at right after ingest", () => {
    const row = {
      published_at: new Date(wireNow - 10_000).toISOString(),
      created_at: new Date(wireNow - 5_000).toISOString(),
    };
    expect(formatWireDateWithRelative(row, wireNow)).toBe(
      "20/07/2026 · just now"
    );
  });

  it("falls back to published_at when created_at is missing", () => {
    const row = {
      published_at: new Date(wireNow - 15_000).toISOString(),
    };
    expect(formatWireDateWithRelative(row, wireNow)).toBe(
      "20/07/2026 · just now"
    );
  });

  it("clamps future published_at to created_at for sort", () => {
    const row = {
      id: 1,
      published_at: new Date(wireNow + 2 * 60 * 60_000).toISOString(),
      created_at: new Date(wireNow - 30 * 60_000).toISOString(),
    };
    expect(wireDisplayInstantMs(row, wireNow)).toBe(wireNow - 30 * 60_000);
  });

  it("overview sort puts truly newer ahead of fake just-now", () => {
    const fakeJustNow = {
      id: 1,
      published_at: new Date(wireNow - 10_000).toISOString(),
      created_at: new Date(wireNow - 3 * 60 * 60_000).toISOString(),
    };
    const realNew = {
      id: 2,
      published_at: new Date(wireNow - 15 * 60_000).toISOString(),
      created_at: new Date(wireNow - 15 * 60_000).toISOString(),
    };
    expect(compareByWireDisplayTime(fakeJustNow, realNew, wireNow)).toBeGreaterThan(
      0
    );
  });

  it("wire sort keeps fresh high priority above newer low-priority", () => {
    const vn = {
      id: 1,
      wire_priority: 100,
      published_at: new Date(wireNow - 2 * 60 * 60_000).toISOString(),
    };
    const fresh = {
      id: 2,
      wire_priority: 0,
      published_at: new Date(wireNow - 5 * 60_000).toISOString(),
    };
    expect(compareWireRows(vn, fresh, wireNow)).toBeLessThan(0);
  });

  it("wire sort decays vietnam older than one week below fresh mid-priority news", () => {
    const staleVn = {
      id: 1,
      wire_priority: 100,
      published_at: new Date(wireNow - 10 * 24 * 60 * 60_000).toISOString(),
    };
    const freshNews = {
      id: 2,
      wire_priority: 25,
      published_at: new Date(wireNow - 10 * 60_000).toISOString(),
    };
    expect(compareWireRows(staleVn, freshNews, wireNow)).toBeGreaterThan(0);
  });

  it("wire sort still pins vietnam within the last week above fresh mid-priority", () => {
    const freshVn = {
      id: 1,
      wire_priority: 100,
      published_at: new Date(wireNow - 2 * 24 * 60 * 60_000).toISOString(),
    };
    const freshNews = {
      id: 2,
      wire_priority: 25,
      published_at: new Date(wireNow - 10 * 60_000).toISOString(),
    };
    expect(compareWireRows(freshVn, freshNews, wireNow)).toBeLessThan(0);
  });
});
