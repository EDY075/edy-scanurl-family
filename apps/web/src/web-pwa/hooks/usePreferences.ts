import { useEffect, useState } from "react";
import {
  FAMILY_THEME_KEY,
  parseFamilyTheme,
  type FamilyTheme,
} from "../../family/family-presentation";

export function readPreference(key: string): string | null {
  try {
    return localStorage.getItem(key);
  } catch {
    return null;
  }
}
export function writePreference(key: string, value: string | null): boolean {
  try {
    if (value === null) localStorage.removeItem(key);
    else localStorage.setItem(key, value);
    return true;
  } catch {
    return false;
  }
}
export function useTheme() {
  const [theme, setTheme] = useState<FamilyTheme>(() =>
    parseFamilyTheme(readPreference(FAMILY_THEME_KEY)),
  );
  const [systemDark, setSystemDark] = useState(
    () => matchMedia("(prefers-color-scheme: dark)").matches,
  );
  useEffect(() => {
    const media = matchMedia("(prefers-color-scheme: dark)");
    const update = () => {
      setSystemDark(media.matches);
    };
    media.addEventListener("change", update);
    return () => {
      media.removeEventListener("change", update);
    };
  }, []);
  const resolved = theme === "system" ? (systemDark ? "dark" : "light") : theme;
  useEffect(() => {
    document.documentElement.style.colorScheme = resolved;
    document
      .querySelector('meta[name="theme-color"]')
      ?.setAttribute("content", resolved === "dark" ? "#0b1414" : "#f5f7f3");
  }, [resolved]);
  return {
    theme,
    resolved,
    changeTheme: (value: FamilyTheme) => {
      setTheme(value);
      writePreference(FAMILY_THEME_KEY, value);
    },
  };
}
