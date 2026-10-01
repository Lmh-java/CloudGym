import { test, expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';

const publicSite = process.env.SITE_URL;
const siteBase = (process.env.SITE_BASE || '/').replace(/\/$/, '');

test('SEO metadata matches the preview or public build', async ({
  page,
  request,
}) => {
  for (const path of ['', 'leaderboard/']) {
    await page.goto(`./${path}`);
    await expect(page.locator('meta[name="description"]')).toHaveAttribute(
      'content',
      /\S+/,
    );
    await expect(page.locator('meta[name="robots"]')).toHaveAttribute(
      'content',
      publicSite ? 'index, follow' : 'noindex, nofollow',
    );
    const schema = JSON.parse(
      (await page.locator('script[type="application/ld+json"]').textContent())!,
    );
    expect(schema['@type']).toBe(path ? 'WebPage' : 'WebSite');
    if (publicSite) {
      const canonical = new URL(`${siteBase}/${path}`, publicSite).href;
      await expect(page.locator('link[rel="canonical"]')).toHaveAttribute(
        'href',
        canonical,
      );
      await expect(page.locator('meta[property="og:url"]')).toHaveAttribute(
        'content',
        canonical,
      );
      await expect(page.locator('meta[property="og:image"]')).toHaveAttribute(
        'content',
        new URL(`${siteBase}/social-card.png`, publicSite).href,
      );
      expect(schema.url).toBe(canonical);
    } else {
      await expect(page.locator('link[rel="canonical"]')).toHaveCount(0);
      expect(schema.url).toBeUndefined();
    }
  }
  const robots = await request.get('robots.txt');
  expect(robots.ok()).toBe(true);
  if (publicSite) {
    const sitemapURL = new URL(`${siteBase}/sitemap-index.xml`, publicSite);
    expect(await robots.text()).toContain(`Sitemap: ${sitemapURL.href}`);
    const sitemapIndex = await request.get('sitemap-index.xml');
    expect(sitemapIndex.ok()).toBe(true);
    const sitemapFiles = [
      ...(await sitemapIndex.text()).matchAll(/<loc>(.*?)<\/loc>/g),
    ];
    expect(sitemapFiles.length).toBeGreaterThan(0);
    let sitemap = '';
    for (const [, location] of sitemapFiles) {
      const url = new URL(location);
      expect(url.origin).toBe(sitemapURL.origin);
      expect(url.pathname).toMatch(new RegExp(`^${siteBase}/`));
      // Fetch from the local preview, never from the public deployment.
      const response = await request.get(url.pathname);
      expect(response.ok()).toBe(true);
      sitemap += await response.text();
    }
    for (const path of ['', 'leaderboard/']) {
      expect(sitemap).toContain(
        `<loc>${new URL(`${siteBase}/${path}`, publicSite).href}</loc>`,
      );
    }
  } else {
    expect(await robots.text()).toContain('Disallow: /');
    expect((await request.get('sitemap-index.xml')).status()).toBe(404);
  }
});

test('navigation and assets work at the configured base path', async ({
  page,
  request,
}) => {
  for (const path of ['./', 'leaderboard/']) {
    await page.goto(path);
    await expect(page.locator('.banner-brand')).toHaveAttribute(
      'href',
      `${siteBase}/`,
    );
    await expect(
      page.getByRole('link', { name: 'Leaderboard', exact: true }),
    ).toHaveAttribute('href', `${siteBase}/leaderboard/`);
    const assets = await page
      .locator('img[src], script[src], link[rel="stylesheet"]')
      .evaluateAll((elements) =>
        elements.map(
          (element) =>
            element.getAttribute('src') || element.getAttribute('href')!,
        ),
      );
    expect(assets.length).toBeGreaterThan(0);
    for (const asset of new Set(assets)) {
      expect(asset.startsWith(`${siteBase}/`)).toBe(true);
      expect((await request.get(asset)).ok(), asset).toBe(true);
    }
  }
  for (const asset of [
    'icons/chatgpt.svg',
    'icons/claude.svg',
    'icons/github.svg',
    'social-card.png',
  ]) {
    expect((await request.get(asset)).ok(), asset).toBe(true);
  }
});

test('View All opens three panels with the same overall rankings at the top', async ({
  page,
  request,
}) => {
  const errors: string[] = [];
  page.on('pageerror', (error) => errors.push(error.message));
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.goto('./');
  await expect(page.locator('.score-number')).toHaveText([
    '34.3%',
    '33.3%',
    '28.9%',
    '28.4%',
    '18.6%',
  ]);
  await expect(page.locator('.subscore-number')).toHaveText([
    '17.4%',
    '32.9%',
    '80.6%',
    '17.4%',
    '25.0%',
    '91.7%',
    '8.7%',
    '26.3%',
    '86.1%',
    '4.3%',
    '30.3%',
    '86.1%',
    '4.3%',
    '9.2%',
    '75.0%',
  ]);
  await expect(
    page.getByText('102 cases · 2 trials per case · Higher is better', {
      exact: true,
    }),
  ).toHaveCount(0);
  await expect(
    page.locator('link[rel="icon"], .chart-card, button, [download]'),
  ).toHaveCount(0);
  await expect(page.locator('.banner-brand')).toHaveText('CloudGYM');
  await expect(
    page.getByRole('link', { name: 'CloudGYM on GitHub' }),
  ).toHaveAttribute('href', 'https://github.com/Lmh-java/CloudGym');
  const rankings = await page.locator('.leaderboard-table').innerText();
  await page.screenshot({
    path: 'test-results/desktop-home.png',
    fullPage: true,
  });
  await page.getByRole('link', { name: 'View All' }).click();
  await expect(page).toHaveURL(/\/leaderboard\/$/);
  await expect(page.locator('.panels-grid section')).toHaveCount(3);
  await expect(
    page.getByRole('heading', { name: 'Across conditions' }),
  ).toHaveCount(0);
  const categoryBox = await page
    .locator('[data-kind=categories]')
    .boundingBox();
  const costBox = await page.locator('[data-kind=cost]').boundingBox();
  expect(costBox!.width).toBe(categoryBox!.width);
  expect(costBox!.x).toBe(categoryBox!.x);
  expect(
    await page.locator('.overview-panel .leaderboard-table').innerText(),
  ).toBe(rankings);
  await expect(page.locator('.panels-grid section').first()).toHaveClass(
    /overview-panel/,
  );
  for (const panel of await page.locator('.chart-viewport').all()) {
    await panel.scrollIntoViewIfNeeded();
    await expect(panel).toHaveClass(/chart-ready/);
    await expect(panel.locator('.interactive-chart svg')).toBeVisible();
  }
  await page.waitForTimeout(1500);
  await page.evaluate(() => window.scrollTo({ top: 0, behavior: 'instant' }));
  await page.screenshot({
    path: 'test-results/desktop-leaderboard.png',
    fullPage: true,
  });
  expect((await request.get('favicon.svg')).status()).toBe(404);
  expect((await request.get('results.json')).status()).toBe(404);
  expect(errors).toEqual([]);
});

test('one policy selector updates categories, cost, and tokens together', async ({
  page,
}) => {
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.goto('leaderboard/');
  const categories = page.locator('[data-kind="categories"]');
  const cost = page.locator('[data-plot="cost"]');
  const tokens = page.locator('[data-plot="tokens"]');
  await expect(page.getByRole('tablist')).toHaveCount(1);
  await expect(page.getByRole('tab')).toHaveCount(3);
  await page.getByRole('tab', { name: 'Prompted policy' }).click();
  await expect(categories).toHaveAttribute('data-condition', 'prompted');
  await expect(page.locator('[data-kind="cost"]')).toHaveAttribute(
    'data-condition',
    'prompted',
  );
  await expect(
    categories.locator('[data-table-condition="prompted"] tbody tr').first(),
  ).toContainText('40.2%');
  await expect(
    cost.locator('[data-table-condition="prompted"] tbody tr').first(),
  ).toContainText('$0.16');
  await expect(
    tokens.locator('[data-table-condition="prompted"] tbody tr').first(),
  ).toContainText('255.1K');
  // Lazily initialized plots must use the already selected policy.
  for (const plot of [categories, cost, tokens]) {
    await plot.locator('.chart-viewport').scrollIntoViewIfNeeded();
    await expect(plot.locator('.chart-viewport')).toHaveClass(/chart-ready/);
  }
  await expect(tokens.locator('.interactive-chart')).toContainText('255.1K');
  const control = page.getByRole('tab', { name: 'Isolated control' });
  await control.click();
  await expect(categories.locator('.interactive-chart')).toContainText('98.9');
  await expect(cost.locator('.interactive-chart')).toContainText('$0.12');
  await expect(tokens.locator('.interactive-chart')).toContainText('207.3K');
  await control.focus();
  await page.keyboard.press('ArrowRight');
  await expect(
    page.getByRole('tab', { name: 'Consulted policy' }),
  ).toBeFocused();
  await expect(page.getByRole('tabpanel')).toHaveAttribute(
    'aria-labelledby',
    'results-consulted-tab',
  );
  await expect(categories).toHaveAttribute('data-condition', 'consulted');
  await expect(cost.locator('.interactive-chart')).toContainText('$0.98');
  await expect(tokens.locator('.interactive-chart')).toContainText('592.9K');
  await expect(page.locator('.score-number').first()).toHaveText('34.3%');
});

for (const width of [1440, 390, 320]) {
  test(`both pages stay responsive and accessible at ${width}px`, async ({
    page,
  }) => {
    await page.emulateMedia({ reducedMotion: 'reduce' });
    await page.setViewportSize({ width, height: 844 });
    for (const path of ['./', 'leaderboard/']) {
      await page.goto(path);
      await expect(page).toHaveTitle('CloudGym');
      if (path === 'leaderboard/')
        for (const panel of await page.locator('.chart-viewport').all()) {
          await panel.scrollIntoViewIfNeeded();
          await expect(panel).toHaveClass(/chart-ready/);
        }
      expect(
        await page.evaluate(() => document.documentElement.scrollWidth),
      ).toBeLessThanOrEqual(width);
      const audit = await new AxeBuilder({ page })
        .withTags(['wcag2a', 'wcag2aa', 'wcag21aa'])
        .analyze();
      expect(audit.violations).toEqual([]);
      if (width === 390) {
        await page.evaluate(() =>
          window.scrollTo({ top: 0, behavior: 'instant' }),
        );
        await page.screenshot({
          path: `test-results/mobile-${path === './' ? 'home' : 'leaderboard'}.png`,
          fullPage: true,
        });
      }
    }
  });
}

test('all three panels retain default results without JavaScript', async ({
  browser,
  baseURL,
}) => {
  const context = await browser.newContext({
    javaScriptEnabled: false,
    baseURL,
  });
  const page = await context.newPage();
  await page.goto('./');
  await page.getByRole('link', { name: 'View All' }).click();
  await expect(page.locator('.score-number').first()).toHaveText('34.3%');
  await expect(page.locator('.static-chart:visible')).toHaveCount(3);
  await expect(page.getByRole('tab')).toHaveCount(0);
  await expect(page.locator('.category-table:visible')).toHaveCount(3);
  await context.close();
});

test('condition and hybrid tooltips support hover, focus, Escape, and small screens', async ({
  page,
}) => {
  await page.goto('./');
  await page.locator('.subscore-heading [data-help="sc"]').hover();
  await expect(page.locator('#help-sc')).toBeVisible();
  await expect(page.locator('#help-sc')).toContainText('incompatible outcomes');
  await page.keyboard.press('Escape');
  await page.locator('[data-help="hybrid"]').hover();
  await expect(page.locator('#help-hybrid')).toBeVisible();
  await expect(page.locator('#help-hybrid')).toContainText('AWS SDK');
  await page.keyboard.press('Escape');
  await expect(page.locator('#help-hybrid')).toBeHidden();
  await page.goto('leaderboard/');
  const categories = page.locator('[data-kind="categories"]');
  for (const [topic, text] of [
    ['sc', 'incompatible outcomes'],
    ['ia', 'target or value unclear'],
    ['ec', 'temporarily block progress'],
  ]) {
    await categories.locator(`.chart-legend [data-help="${topic}"]`).hover();
    await expect(page.locator(`#help-${topic}`)).toBeVisible();
    await expect(page.locator(`#help-${topic}`)).toContainText(text);
    await page.keyboard.press('Escape');
  }
  for (const [name, topic, text] of [
    ['Consulted policy', 'consulted', 'must consult'],
    ['Prompted policy', 'prompted', 'agent’s prompt'],
    ['Isolated control', 'control', 'works alone'],
  ]) {
    await page.getByRole('tab', { name, exact: true }).hover();
    await expect(page.locator(`#help-${topic}`)).toBeVisible();
    await expect(page.locator(`#help-${topic}`)).toContainText(text);
  }
  // Hovering the explanation itself must not dismiss it.
  await page.locator('#help-control').hover();
  await expect(page.locator('#help-control')).toBeVisible();
  await page.keyboard.press('Escape');
  await expect(page.locator('#help-control')).toBeHidden();
  await page.setViewportSize({ width: 320, height: 844 });
  const hybrid = categories.locator('[data-help="hybrid"]');
  await hybrid.focus();
  await expect(page.locator('#help-hybrid')).toBeVisible();
  const box = await page.locator('#help-hybrid').boundingBox();
  expect(box!.x).toBeGreaterThanOrEqual(0);
  expect(box!.x + box!.width).toBeLessThanOrEqual(320);
  await page.screenshot({ path: 'test-results/tooltip-mobile.png' });
  await page.keyboard.press('Escape');
  await expect(page.locator('#help-hybrid')).toBeHidden();
});
