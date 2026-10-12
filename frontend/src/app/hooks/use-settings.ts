// 设置（settings）域：设置状态 + 密钥可见性 + 主题解析 + 保存/重置归仓（阶段 2 收尾档）。
// settings 是全体域 hook 的输入根，由 page 经本 hook 持有并向下分发；
// boot 恢复（readStorage → sanitize）与 clearLocalData 的整体重置留在 page（跨域编排），
// 通过本 hook 返回的 setSettings 复用同一份状态。

import { useEffect, useState } from "react";
import type { AppSettings, Toast } from "../types";
import { DEFAULT_SETTINGS, sanitizeSettingsForStorage, STORAGE_KEYS, writeStorage } from "../app-meta";
import { DEFAULT_API_BASE } from "../app-meta";

export function useSettings({ addToast }: { addToast: (message: string, type?: Toast["type"]) => void }) {
  const [settings, setSettings] = useState<AppSettings>(DEFAULT_SETTINGS);
  const [keysVisible, setKeysVisible] = useState(false);
  const [resolvedTheme, setResolvedTheme] = useState<"light" | "dark">("light");
  const [themePickerOpen, setThemePickerOpen] = useState(false);

  useEffect(() => {
    if (typeof window === "undefined") return;

    const root = document.documentElement;
    const media = window.matchMedia("(prefers-color-scheme: dark)");
    const applyTheme = () => {
      const nextTheme = settings.themeMode === "system" ? (media.matches ? "dark" : "light") : settings.themeMode;
      root.dataset.theme = nextTheme;
      setResolvedTheme(nextTheme);
    };

    applyTheme();
    const handleChange = () => {
      if (settings.themeMode === "system") {
        applyTheme();
      }
    };

    if (typeof media.addEventListener === "function") {
      media.addEventListener("change", handleChange);
      return () => media.removeEventListener("change", handleChange);
    }

    media.addListener(handleChange);
    return () => media.removeListener(handleChange);
  }, [settings.themeMode]);

  const saveSettings = () => {
    const normalized: AppSettings = {
      ...settings,
      apiBase: (settings.apiBase || "").trim().replace(/\/$/, "") || DEFAULT_API_BASE,
      refreshInterval: Math.max(10, Number(settings.refreshInterval) || 30),
    };
    setSettings(normalized);
    writeStorage(STORAGE_KEYS.settings, sanitizeSettingsForStorage(normalized));
    addToast(
      normalized.adminApiKey.trim() || normalized.clientApiKey.trim()
        ? "设置已保存，敏感 Key 仅保留在当前浏览器会话"
        : "设置已保存",
      "success"
    );
  };

  const resetSettings = () => {
    setSettings(DEFAULT_SETTINGS);
    writeStorage(STORAGE_KEYS.settings, DEFAULT_SETTINGS);
    setThemePickerOpen(false);
    addToast("设置已恢复默认", "info");
  };

  return {
    settings,
    setSettings,
    keysVisible,
    setKeysVisible,
    resolvedTheme,
    themePickerOpen,
    setThemePickerOpen,
    saveSettings,
    resetSettings,
  };
}
