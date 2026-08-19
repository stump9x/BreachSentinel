import { describe, expect, it } from "vitest";
import { displayThreatTitle } from "./threatTitle";

describe("displayThreatTitle", () => {
  it("shows Vietnamese title when present", () => {
    expect(
      displayThreatTitle({
        title: "Ransomware: Digipro (nova)",
        title_vi: "Mã độc tống tiền: Digipro (nova)",
      })
    ).toBe("Mã độc tống tiền: Digipro (nova)");
  });

  it("does not fall back to English while translation is pending", () => {
    expect(
      displayThreatTitle({
        title: "Hospital data breach",
        title_vi: "",
        title_vi_status: "pending",
      })
    ).toBe("Đang dịch…");
  });

  it("shows translating placeholder when title_vi is empty", () => {
    expect(displayThreatTitle({ title: "Hospital data breach", title_vi: "" })).toBe(
      "Đang dịch…"
    );
  });
});
