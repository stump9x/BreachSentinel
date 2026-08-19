import { describe, expect, it } from "vitest";
import { buildQuery, getApiBase } from "./client";

describe("buildQuery", () => {
  it("omits empty values", () => {
    expect(buildQuery({ a: "1", b: "", c: null, d: "x" })).toBe("?a=1&d=x");
  });
});

describe("getApiBase", () => {
  it("returns string without trailing slash when env empty-ish", () => {
    const base = getApiBase();
    expect(typeof base).toBe("string");
    expect(base.endsWith("/")).toBe(false);
  });
});
