import { describe, expect, it } from "vitest";
import css from "./styles.css?raw";
function luminance(hex: string) {
  const color = hex.replace("#", "");
  const channels = [0, 2, 4].map((index) => {
    const value = parseInt(color.slice(index, index + 2), 16) / 255;
    return value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4;
  });
  return channels[0] * 0.2126 + channels[1] * 0.7152 + channels[2] * 0.0722;
}
function contrast(a: string, b: string) {
  const x = luminance(a);
  const y = luminance(b);
  return (Math.max(x, y) + 0.05) / (Math.min(x, y) + 0.05);
}
describe("Static accessibility tokens (not a replacement for browser axe)", () => {
  for (const [theme, selector] of [
    ["dark", /\.web-app\s*\{([^}]+)\}/],
    ["light", /\.web-app\[data-theme=["']?light["']?\]\s*\{([^}]+)\}/],
  ] as const) {
    const values = Object.fromEntries(
      Array.from(
        (css.match(selector)?.[1] ?? "").matchAll(
          /--([a-z-]+):\s*(#(?:[a-f\d]{6}|[a-f\d]{3}));/g,
        ),
        (match) => [
          match[1],
          match[2].length === 4
            ? "#" +
              match[2]
                .slice(1)
                .split("")
                .map((char) => char + char)
                .join("")
            : match[2],
        ],
      ),
    );
    it.each(["text", "muted", "subtle", "accent", "good", "caution", "risk"])(
      `${theme}: %s remains AA on base/surface`,
      (token) => {
        expect(contrast(values[token], values.bg)).toBeGreaterThanOrEqual(4.5);
        expect(contrast(values[token], values.surface)).toBeGreaterThanOrEqual(
          4.5,
        );
      },
    );
    it(`${theme}: primary button text contrast`, () => {
      expect(
        contrast(values.accent, values["accent-ink"]),
      ).toBeGreaterThanOrEqual(4.5);
    });
  }
  it("provides reduced-motion, visible focus and mobile URL font rules", () => {
    expect(css).toMatch(/prefers-reduced-motion:\s*reduce/);
    expect(css).toContain(":focus-visible");
    expect(css).toMatch(/\.url-field input\s*\{[^}]*font-size:\s*16px/);
    expect(css).toMatch(/min-height:\s*100dvh/);
  });
});
