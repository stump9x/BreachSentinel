import { describe, expect, it } from "vitest";
import {
  flagEmojiFromIso2,
  geographyFlagUrl,
  geographyIso2,
  geographyTagLabel,
  isGeographyTag,
  orderedWireTags,
  preferCountryGeography,
} from "./wireTags";

describe("Wire tag ordering", () => {
  it("reserves country geography at the end even when topics are crowded", () => {
    const result = orderedWireTags(
      {
        is_kev: true,
        tags: [
          { slug: "geo-romania" },
          { slug: "ransomware" },
          { slug: "site-example-com" },
          { slug: "data-breach" },
          { slug: "cert" },
          { slug: "geo-europe" },
        ],
      },
      5
    );

    expect(result.map((item) => item.kind)).toEqual([
      "website",
      "kev",
      "topic",
      "geography",
      "geography",
    ]);
    expect(
      result.filter((item) => item.kind === "geography").map((i) => i.tag.slug)
    ).toEqual(["geo-romania", "geo-europe"]);
    expect(result).toHaveLength(5);
  });

  it("hides alleged-claim and still puts geography last", () => {
    const result = orderedWireTags({
      tags: [
        { slug: "alleged-claim" },
        { slug: "geo-romania" },
        { slug: "data-breach" },
        { slug: "site-example-com" },
      ],
    });

    expect(result.map((item) => item.kind)).toEqual([
      "website",
      "topic",
      "geography",
    ]);
    expect(result.some((item) => item.tag?.slug === "alleged-claim")).toBe(
      false
    );
  });

  it("prefers country tags over regions", () => {
    const ordered = preferCountryGeography([
      { slug: "geo-europe" },
      { slug: "geo-romania" },
      { slug: "vietnam" },
    ]);
    expect(ordered.map((t) => t.slug)).toEqual([
      "vietnam",
      "geo-romania",
      "geo-europe",
    ]);
  });

  it("exposes ISO2 and flagcdn URL for official flag images", () => {
    expect(isGeographyTag({ slug: "vietnam" })).toBe(true);
    expect(geographyIso2({ slug: "geo-united-states" })).toBe("US");
    expect(geographyIso2({ slug: "vietnam" })).toBe("VN");
    expect(geographyFlagUrl({ slug: "geo-canada" }, 20)).toBe(
      "https://flagcdn.com/w20/ca.png"
    );
    expect(flagEmojiFromIso2("US")).toBe("🇺🇸");
    expect(geographyTagLabel({ slug: "geo-united-states" })).toBe(
      "United States"
    );
    expect(geographyTagLabel({ slug: "vietnam" })).toBe("Vietnam");
  });
});
