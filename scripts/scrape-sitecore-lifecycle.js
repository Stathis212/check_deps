/**
 * scrape-sitecore-lifecycle.js
 *
 * Uses Playwright to render the Sitecore KB lifecycle page (KB1004260)
 * and extract JSS / Content SDK EOL dates automatically.
 *
 * Outputs a JSON file: .sitecore-lifecycle-cache.json
 * consumed by check-deps.js on every run.
 *
 * Usage: node scripts/scrape-sitecore-lifecycle.js
 */

const { chromium } = require("playwright");
const fs = require("fs");
const path = require("path");

const OUTPUT_FILE = path.join(__dirname, "../.sitecore-lifecycle-cache.json");
const KB_URL = "https://support.sitecore.com/kb?id=kb_article_view&sysparm_article=KB1004260";

// Keywords to match relevant rows in the lifecycle table
const PRODUCTS_OF_INTEREST = [
  "jss",
  "javascript services",
  "content sdk",
  "xm cloud",
];

async function scrape() {
  console.log("Launching browser...");
  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage();

  console.log(`Fetching: ${KB_URL}`);
  await page.goto(KB_URL, { waitUntil: "networkidle", timeout: 30000 });

  // Wait for the table to render — the KB page loads content dynamically
  try {
    await page.waitForSelector("table", { timeout: 15000 });
    console.log("Table found.");
  } catch {
    console.error("Table did not render within timeout. Page may require login or has changed structure.");
    await browser.close();

    // Write an empty cache with a timestamp so check-deps.js knows we tried
    fs.writeFileSync(OUTPUT_FILE, JSON.stringify({
      scraped: new Date().toISOString(),
      error: "Table not found — page may require login or structure changed.",
      products: []
    }, null, 2));
    process.exit(0);
  }

  // Extract all table rows
  const rows = await page.evaluate((productsOfInterest) => {
    const results = [];
    const tables = document.querySelectorAll("table");

    for (const table of tables) {
      const headers = [...table.querySelectorAll("th")].map(th => th.innerText.trim().toLowerCase());
      const bodyRows = table.querySelectorAll("tbody tr");

      for (const row of bodyRows) {
        const cells = [...row.querySelectorAll("td")].map(td => td.innerText.trim());
        if (!cells.length) continue;

        // Check if any cell in this row matches a product we care about
        const rowText = cells.join(" ").toLowerCase();
        const matched = productsOfInterest.find(p => rowText.includes(p));
        if (!matched) continue;

        // Map cells to headers where possible
        const entry = { _matched: matched, _raw: cells };
        headers.forEach((h, i) => {
          if (cells[i] !== undefined) entry[h] = cells[i];
        });

        results.push(entry);
      }
    }

    return results;
  }, PRODUCTS_OF_INTEREST);

  await browser.close();
  console.log(`Found ${rows.length} relevant row(s).`);

  // Parse date-like strings from cells (formats: "Jun 2026", "June 30, 2026", "2026-06-30", "Q2 2026")
  function parseDate(str) {
    if (!str) return null;
    // ISO format
    if (/^\d{4}-\d{2}-\d{2}$/.test(str)) return str;
    // Try native Date parsing
    const d = new Date(str);
    if (!isNaN(d)) return d.toISOString().split("T")[0];
    // Quarter format e.g. "Q2 2026" → approximate end of quarter
    const q = str.match(/Q(\d)\s+(\d{4})/i);
    if (q) {
      const endMonth = { 1:"03-31", 2:"06-30", 3:"09-30", 4:"12-31" }[q[1]] || "12-31";
      return `${q[2]}-${endMonth}`;
    }
    return null;
  }

  // Normalize rows into a consistent product lifecycle structure
  const products = rows.map(row => {
    // Find the first date-like value in the row as EOL candidate
    const dateCells = row._raw.filter(c => /20\d\d/.test(c));
    const eolDate = dateCells.map(parseDate).find(Boolean) || null;

    // Identify version from the row text
    const versionMatch = row._raw.join(" ").match(/\b(\d+\.\d+|\d+)\b/);
    const version = versionMatch ? versionMatch[1] : null;

    return {
      product: row._matched,
      version,
      eolDate,
      rawRow: row._raw,
    };
  }).filter(p => p.eolDate); // Only keep entries where we found a date

  const output = {
    scraped: new Date().toISOString(),
    source: KB_URL,
    products,
  };

  fs.writeFileSync(OUTPUT_FILE, JSON.stringify(output, null, 2));
  console.log(`\nWrote ${products.length} product lifecycle entries to ${OUTPUT_FILE}`);
  console.log(JSON.stringify(output, null, 2));
}

scrape().catch(e => {
  console.error("Scraper failed:", e.message);
  // Write failure state so check-deps.js can fall back gracefully
  fs.writeFileSync(OUTPUT_FILE, JSON.stringify({
    scraped: new Date().toISOString(),
    error: e.message,
    products: []
  }, null, 2));
  process.exit(1);
});