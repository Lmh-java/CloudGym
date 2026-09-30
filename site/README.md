# CloudGym leaderboard

A local Astro + TypeScript site with animated Apache ECharts panels. The home page
shows consulted-policy rankings and links to `/leaderboard/` via View All. The
Leaderboard page has three full-width panels: the same overall rankings, category
pass rates, and inference cost with token consumption. Category and cost panels share
one set of condition tabs, defaulting to consulted policy. All results use hybrid
tools. There is no publishing workflow.

## Local preview

Use Node.js 22.12 or newer:

```sh
cd site
npm ci
npm run dev
```

Open http://127.0.0.1:4321. To review the compiled site, run `npm run build`, then
`npm run preview`. All servers bind to localhost.

## Editing

- `src/data/results.json`: Table 1 pass rates, inference costs, and token consumption for all three conditions.
- `src/pages/index.astro`: centered title, GitHub link, stats, and overall rankings.
- `src/pages/leaderboard.astro`: three result panels.
- `src/components/Rankings.astro`: identical overall ranking tables on both pages.
- `src/components/ChartPanel.astro`: accessible chart panels; ChartPlot.astro renders each metric.
- `src/layouts/Page.astro`: shared SEO metadata and navigation banner with CloudGYM and GitHub links.
- `src/styles/global.css`: responsive mission control theme with cobalt blue accents.
- `src/scripts/charts.ts`: shared policy selection, lazy loading, and chart lifecycle.
- `src/lib/chart-options.ts`: responsive chart presentation and animation.
- `src/lib/site.ts`: shared site links and model icon paths.
- `src/scripts/tooltips.ts`: accessible hover and focus explanations.
- `public/icons/`: local Claude, ChatGPT/OpenAI, and GitHub SVG marks.

The HTML rankings and default SVG charts work without JavaScript. Screen-reader
tables provide exact values for each selected condition. Inference costs are USD
per case; tokens are thousands per case, as reported in Table 1. Overall scores are copied from the manuscript, not
calculated by averaging category percentages.

## Checks

`npm run format` formats the source; `npm run format:check` verifies it.
`npm run build` checks types and builds. `npm test` verifies results, removed UI,
shared condition tabs, keyboard navigation, responsive layouts, accessibility,
and the no-JavaScript fallback.
Browser tests use local Google Chrome; another executable can be specified through
`PLAYWRIGHT_CHROMIUM_EXECUTABLE`. Screenshots are saved under `test-results/`.

## Future release

After design approval and explicit authorization to publish:

```sh
SITE_URL=https://lmh-java.github.io SITE_BASE=/CloudGym npm run build
```

This only creates local `dist/` files. A configured public URL enables canonical
metadata, social cards, the sitemap, and indexing. Local builds remain `noindex`.
Only `dist/` should be used for a future GitHub Pages deployment.

## Icon sources

Brand SVG geometry comes from `@lobehub/icons-static-svg` version 1.95.1:
https://github.com/lobehub/lobe-icons (MIT).
Claude uses `claude-color.svg`; ChatGPT uses the shared OpenAI knot in `openai.svg`;
GitHub uses `github.svg`. Monochrome fills are set for the page background.
Brand marks remain the property of their respective owners.
