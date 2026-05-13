/**
 * scrape-sitecore-lifecycle.js
 *
 * Uses Playwright to render the Sitecore developer portal changelog pages
 * and extract all entries with their titles, dates, and body text.
 *
 * Outputs: .sitecore-changelog-sitecoreai.json
 *
 * check-deps.js reads these files and scans entries for lifecycle keywords.
 * Only new (unseen) entries are alerted on — so missing a run never
 * causes you to miss an announcement.
 *
 * Usage: node scripts/scrape-sitecore-lifecycle.js
 */

const { chromium } = require("playwright");
const fs           = require("fs");
const path         = require("path");

const SOURCES = [
  {
    name:      "SitecoreAI Changelog",
    url:       "https://developers.sitecore.com/changelog/sitecoreai",
    cacheFile: path.join(__dirname, "../.sitecore-changelog-sitecoreai.json"),
  },
];

async function scrapeChangelog(page, source) {
  console.log(`\nFetching: ${source.url}`);

  try {
    await page.goto(source.url, { waitUntil: "networkidle", timeout: 30000 });
  } catch (e) {
    console.error(`  Navigation failed: ${e.message}`);
    return [];
  }

  // Wait for any changelog entry to appear — the portal renders dynamically
  try {
    await page.waitForSelector("article, [class*='changelog'], h2 a, .change-item", {
      timeout: 15000,
    });
  } catch {
    console.warn("  No changelog entries found within timeout — page may have changed structure.");
  }

  // Extract all entries visible on the page
  const entries = await page.evaluate(() => {
    const results = [];

    // Strategy 1: look for article elements (most changelog UIs use these)
    const articles = document.querySelectorAll("article");
    for (const art of articles) {
      const titleEl = art.querySelector("h1, h2, h3, a");
      const title   = titleEl?.innerText?.trim() || "";
      const link    = titleEl?.closest("a")?.href || titleEl?.href || "";
      const body    = art.innerText?.trim() || "";
      const dateEl  = art.querySelector("time, [datetime]");
      const date    = dateEl?.getAttribute("datetime") || dateEl?.innerText?.trim() || "";

      if (title) results.push({ title, url: link, date, body: body.slice(0, 1000) });
    }

    // Strategy 2: look for heading + paragraph pairs if no articles found
    if (results.length === 0) {
      const headings = document.querySelectorAll("h2, h3");
      for (const h of headings) {
        const title = h.innerText?.trim();
        if (!title || title.length < 5) continue;
        const link    = h.querySelector("a")?.href || h.closest("a")?.href || "";
        const sibling = h.nextElementSibling;
        const body    = sibling?.innerText?.trim() || "";
        results.push({ title, url: link, date: "", body: body.slice(0, 500) });
      }
    }

    return results;
  });

  console.log(`  Found ${entries.length} entries.`);
  return entries;
}

async function run() {
  console.log("Launching browser...");
  const browser = await chromium.launch({ headless: true });
  const page    = await browser.newPage();

  // Set a real browser user agent to avoid bot detection
  await page.setExtraHTTPHeaders({
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124 Safari/537.36",
  });

  for (const source of SOURCES) {
    const entries = await scrapeChangelog(page, source);

    const output = {
      scraped: new Date().toISOString(),
      source:  source.url,
      entries,
    };

    fs.writeFileSync(source.cacheFile, JSON.stringify(output, null, 2));
    console.log(`  Wrote ${entries.length} entries to ${source.cacheFile}`);
  }

  await browser.close();
  console.log("\nDone.");
}

run().catch(e => {
  console.error("Scraper failed:", e.message);

  // Write failure state for each source so check-deps.js handles it gracefully
  for (const source of SOURCES) {
    fs.writeFileSync(source.cacheFile, JSON.stringify({
      scraped: new Date().toISOString(),
      error:   e.message,
      entries: [],
    }, null, 2));
  }

  process.exit(1);
});