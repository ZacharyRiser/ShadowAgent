import { defineConfig } from "vitest/config";

/**
 * The frontend has no component-test harness on purpose.
 *
 * Installing jsdom + testing-library to render `page.tsx` would be a large
 * dependency for a suite that mostly proves the same thing a CDP screenshot
 * already proves. What no build-time check and no screenshot can catch is the
 * *decision logic* — the email-shape rule and the registration copy that once
 * reported a network outage as "registration disabled". Those live in plain
 * modules (`src/app/auth-logic.ts`, `src/app/time-utils.ts`), so the suite runs
 * in a bare Node environment with no DOM.
 *
 * The `.mts` extension is deliberate: `package.json` has no `"type": "module"`,
 * so a `.ts` config is loaded as CommonJS by Vite's native loader, which warns
 * on the ESM `import` above and falls back to a slower loader.
 */
export default defineConfig({
  test: {
    environment: "node",
    include: ["src/**/*.test.ts"],
    reporters: ["default"],
  },
});
