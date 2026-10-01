import { defineConfig } from 'astro/config';
import sitemap from '@astrojs/sitemap';

// A public URL is deliberately opt-in. Local review builds are marked noindex.
const site = process.env.SITE_URL || undefined;
export default defineConfig({
  output: 'static',
  trailingSlash: 'always',
  site,
  base: process.env.SITE_BASE || '/',
  outDir: process.env.SITE_BUILD_DIR || './dist',
  integrations: site ? [sitemap()] : [],
  devToolbar: { enabled: false },
});
