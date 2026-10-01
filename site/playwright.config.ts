import { defineConfig } from '@playwright/test';

const port = process.env.PLAYWRIGHT_PORT || '4321';
const base = (process.env.SITE_BASE || '/').replace(/\/$/, '');
const baseURL = `http://127.0.0.1:${port}${base}/`;
const executablePath =
  process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE ||
  (!process.env.CI && process.platform === 'darwin'
    ? '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'
    : undefined);

export default defineConfig({
  testDir: './tests',
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  use: {
    baseURL,
    launchOptions: { executablePath },
  },
  webServer: {
    command: `npm run preview -- --port ${port}`,
    url: baseURL,
    reuseExistingServer: !process.env.CI,
  },
});
