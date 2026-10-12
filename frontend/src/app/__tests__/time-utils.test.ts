/**
 * `time-utils` renders every timestamp in the console, and it has one
 * non-obvious rule: a naive ISO string (`2026-09-27T07:30:00`, which is what
 * SQLite hands back) has **no zone marker** and `new Date()` would read it as
 * *local* time. The module appends `Z` to treat it as UTC, so the Beijing
 * rendering is right regardless of the machine's timezone. That rule is what
 * these tests pin down.
 */

import { describe, expect, it } from "vitest";

import { formatBeijingTime, formatRelativeTime, formatUtcTime, parseDateValue } from "../time-utils";

describe("parseDateValue", () => {
  it("treats a naive timestamp as UTC", () => {
    const naive = parseDateValue("2026-09-27T07:30:00");
    const explicit = parseDateValue("2026-09-27T07:30:00Z");
    expect(naive?.toISOString()).toBe(explicit?.toISOString());
  });

  it("keeps an explicit offset untouched", () => {
    expect(parseDateValue("2026-09-27T15:30:00+08:00")?.toISOString()).toBe("2026-09-27T07:30:00.000Z");
  });

  it("returns null for empty and unparsable input", () => {
    expect(parseDateValue(null)).toBeNull();
    expect(parseDateValue(undefined)).toBeNull();
    expect(parseDateValue("")).toBeNull();
    expect(parseDateValue("not-a-date")).toBeNull();
  });
});

describe("formatBeijingTime / formatUtcTime", () => {
  it("renders the same instant in both zones", () => {
    expect(formatBeijingTime("2026-09-27T07:30:05")).toBe("2026-09-27 15:30:05");
    expect(formatUtcTime("2026-09-27T07:30:05")).toBe("2026-09-27 07:30:05 UTC");
  });

  it("falls back instead of printing garbage", () => {
    expect(formatBeijingTime(null)).toBe("未知时间");
    expect(formatBeijingTime("nonsense", "—")).toBe("—");
    expect(formatUtcTime(undefined)).toBe("未知时间");
  });
});

describe("formatRelativeTime", () => {
  const now = Date.now();

  it("describes past and future deltas", () => {
    expect(formatRelativeTime(new Date(now - 5 * 60_000).toISOString())).toBe("5 分钟前");
    expect(formatRelativeTime(new Date(now + 5 * 60_000).toISOString())).toBe("5 分钟后");
    expect(formatRelativeTime(new Date(now - 3 * 3_600_000).toISOString())).toBe("3 小时前");
    expect(formatRelativeTime(new Date(now - 2 * 86_400_000).toISOString())).toBe("2 天前");
  });

  it("collapses sub-minute deltas to 刚刚", () => {
    expect(formatRelativeTime(new Date(now - 10_000).toISOString())).toBe("刚刚");
  });

  it("distinguishes 'never happened' from 'could not parse'", () => {
    expect(formatRelativeTime(null)).toBe("尚未发生");
    expect(formatRelativeTime("nonsense")).toBe("未知");
  });
});
