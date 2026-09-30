import type { APIRoute } from 'astro';
import { base } from '../lib/site';
export const GET: APIRoute = ({ site }) =>
  new Response(
    site
      ? `User-agent: *\nAllow: /\nSitemap: ${new URL(`${base}/sitemap-index.xml`, site).href}\n`
      : 'User-agent: *\nDisallow: /\n',
    { headers: { 'Content-Type': 'text/plain' } },
  );
