/**
 * Dependency Monitor
 * - EOL dates for Sitecore products: scraped live from KB1004260 via Playwright
 * - EOL dates for Next.js: fetched live from endoflife.date API
 * - Releases: GitHub Releases API
 * - CVEs: GitHub Advisory Database (rolling 30-day window)
 *
 * No hardcoded dates. No config files. Fully automatic.
 */

const https = require("https");
const fs = require("fs");
const path = require("path");

// ─── Package definitions (no dates here — all fetched automatically) ──────────

const PACKAGES = [
  {
    name: "Sitecore JSS",
    repo: "Sitecore/jss",
    watchMajorBump: true,
    sitecoreProduct: "jss", // matched against scraped lifecycle data
    releases: "https://github.com/Sitecore/jss/releases",
    docs: "https://doc.sitecore.com/xp/en/developers/hd/latest/sitecore-headless-development/sitecore-javascript-rendering-sdks--jss-.html",
  },
  {
    name: "Sitecore Content SDK",
    repo: "Sitecore/content-sdk",
    watchMajorBump: true,
    sitecoreProduct: "content sdk",
    releases: "https://github.com/Sitecore/content-sdk/releases",
    docs: "https://developers.sitecore.com/content-sdk",
  },
  {
    name: "Sitecore XM Cloud",
    repo: "Sitecore/xm-cloud-introduction",
    watchMajorBump: true,
    sitecoreProduct: "xm cloud",
    releases: "https://github.com/Sitecore/xm-cloud-introduction/releases",
    docs: "https://doc.sitecore.com/xmc",
  },
];

// Packages whose EOL is fetched from endoflife.date API
const EOL_API_PACKAGES = [
  {
    name: "Next.js",
    repo: "vercel/next.js",
    slug: "nextjs",   // endoflife.date product slug
    watchMajorBump: true,
    releases: "https://github.com/vercel/next.js/releases",
    docs: "https://nextjs.org/docs",
  },
];

// npm packages to audit for CVEs
const NPM_PACKAGES_TO_AUDIT = [
  "next",
  "@sitecore-jss/sitecore-jss",
  "@sitecore-jss/sitecore-jss-nextjs",
  "@sitecore-content-sdk/nextjs",
  "react",
  "react-dom",
];

const CVE_ROLLING_WINDOW_DAYS = 30;
const EOL_WARN_DAYS_BEFORE = 90;
const STATE_FILE = path.join(__dirname, "../.dep-monitor-state.json");
const LIFECYCLE_CACHE = path.join(__dirname, "../.sitecore-lifecycle-cache.json");

// ─── HTTP helpers ──────────────────────────────────────────────────────────────

function httpGet(hostname, apiPath, headers = {}) {
  return new Promise((resolve, reject) => {
    https.get({ hostname, path: apiPath, headers: { "User-Agent": "dep-monitor/1.0", ...headers } }, (res) => {
      let data = "";
      res.on("data", (c) => (data += c));
      res.on("end", () => {
        if (res.statusCode === 404) { resolve(null); return; }
        if (res.statusCode !== 200) reject(new Error(`HTTP ${res.statusCode}`));
        else resolve(JSON.parse(data));
      });
    }).on("error", reject);
  });
}

function githubGet(apiPath) {
  const headers = { Accept: "application/vnd.github+json" };
  if (process.env.GITHUB_TOKEN) headers["Authorization"] = `Bearer ${process.env.GITHUB_TOKEN}`;
  return httpGet("api.github.com", apiPath, headers);
}

function githubGraphQL(query) {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify({ query });
    const headers = {
      "User-Agent": "dep-monitor/1.0", "Content-Type": "application/json", "Content-Length": body.length,
    };
    if (process.env.GITHUB_TOKEN) headers["Authorization"] = `Bearer ${process.env.GITHUB_TOKEN}`;
    const req = https.request(
      { hostname: "api.github.com", path: "/graphql", method: "POST", headers },
      (res) => {
        let data = "";
        res.on("data", (c) => (data += c));
        res.on("end", () => {
          if (res.statusCode !== 200) reject(new Error(`GraphQL HTTP ${res.statusCode}`));
          else resolve(JSON.parse(data));
        });
      }
    );
    req.on("error", reject);
    req.write(body);
    req.end();
  });
}

// ─── endoflife.date ────────────────────────────────────────────────────────────

async function fetchEolDateCycles(slug) {
  try {
    const data = await httpGet("endoflife.date", `/api/v1/products/${slug}/`);
    return data || [];
  } catch (e) {
    console.error(`  endoflife.date fetch failed for ${slug}: ${e.message}`);
    return [];
  }
}

// ─── Sitecore lifecycle cache (written by scraper) ────────────────────────────

function loadSitecoreLifecycle() {
  try {
    const cache = JSON.parse(fs.readFileSync(LIFECYCLE_CACHE, "utf8"));
    if (cache.error) {
      console.warn(`  Sitecore lifecycle cache has error: ${cache.error}`);
      return [];
    }
    console.log(`  Sitecore lifecycle cache loaded (scraped: ${cache.scraped})`);
    return cache.products || [];
  } catch {
    console.warn("  No Sitecore lifecycle cache found — scraper may not have run.");
    return [];
  }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function getMajor(tag) {
  const m = tag.replace(/^v/, "").match(/^(\d+)/);
  return m ? parseInt(m[1], 10) : null;
}

function daysFromNow(dateStr) {
  if (!dateStr) return Infinity;
  return Math.ceil((new Date(dateStr) - Date.now()) / 86400000);
}

function daysAgo(dateStr) {
  return Math.floor((Date.now() - new Date(dateStr)) / 86400000);
}

function fmt(dateStr) {
  return new Date(dateStr).toLocaleDateString("en-GB", { day: "numeric", month: "long", year: "numeric" });
}

function loadState() {
  try { return JSON.parse(fs.readFileSync(STATE_FILE, "utf8")); }
  catch { return {}; }
}

function saveState(state) {
  fs.writeFileSync(STATE_FILE, JSON.stringify(state, null, 2));
}

async function sendSlackAlert(message) {
  const url = process.env.SLACK_WEBHOOK_URL;
  if (!url) return;
  const body = JSON.stringify({ text: message });
  const parsed = new URL(url);
  return new Promise((resolve) => {
    const req = https.request(
      { hostname: parsed.hostname, path: parsed.pathname, method: "POST",
        headers: { "Content-Type": "application/json", "Content-Length": body.length } },
      (res) => { res.on("data", () => {}); res.on("end", resolve); }
    );
    req.on("error", (e) => console.error("Slack error:", e.message));
    req.write(body);
    req.end();
  });
}

// ─── EOL alert builder ────────────────────────────────────────────────────────

function buildEolAlerts(pkgName, pkgReleases, eolEntries) {
  const alerts = [];
  for (const eol of eolEntries) {
    if (!eol.eolDate) continue;
    const days = daysFromNow(eol.eolDate);
    if (days > EOL_WARN_DAYS_BEFORE) continue;

    if (days > 0) {
      alerts.push(
        `*[EOL IN ${days} DAYS]* ${pkgName}${eol.version ? ` v${eol.version}` : ""} reaches end-of-life on ${fmt(eol.eolDate)}.\n` +
        `No security patches after this date. Plan your upgrade now.\n` +
        `Releases: ${pkgReleases}`
      );
    } else {
      alerts.push(
        `*[EOL PASSED]* ${pkgName}${eol.version ? ` v${eol.version}` : ""} reached end-of-life on ${fmt(eol.eolDate)}.\n` +
        `No further patches. Upgrade immediately.\n` +
        `Releases: ${pkgReleases}`
      );
    }
  }
  return alerts;
}

// ─── CVE check ────────────────────────────────────────────────────────────────

async function checkSecurityAdvisories() {
  if (!process.env.GITHUB_TOKEN) {
    console.log("  Skipping CVE check — GITHUB_TOKEN required.");
    return [];
  }
  const advisories = [];
  for (const pkg of NPM_PACKAGES_TO_AUDIT) {
    console.log(`  Checking advisories for ${pkg}...`);
    try {
      const result = await githubGraphQL(`{
        securityVulnerabilities(ecosystem:NPM, package:"${pkg}", first:10,
          orderBy:{field:UPDATED_AT, direction:DESC}) {
          nodes {
            advisory {
              ghsaId summary severity publishedAt permalink
              cvss { score }
              identifiers { type value }
            }
            vulnerableVersionRange
            firstPatchedVersion { identifier }
          }
        }
      }`);
      const nodes = result?.data?.securityVulnerabilities?.nodes || [];
      for (const node of nodes) {
        const adv = node.advisory;
        const cveId = adv.identifiers.find((i) => i.type === "CVE")?.value || adv.ghsaId;
        advisories.push({
          package: pkg, id: cveId, summary: adv.summary, severity: adv.severity,
          cvssScore: adv.cvss?.score || null,
          vulnerableVersionRange: node.vulnerableVersionRange,
          patchedVersion: node.firstPatchedVersion?.identifier || "No patch yet",
          publishedAt: adv.publishedAt, url: adv.permalink,
        });
      }
    } catch (e) {
      console.error(`  Advisory check failed for ${pkg}: ${e.message}`);
    }
  }
  return advisories;
}

// ─── Main ─────────────────────────────────────────────────────────────────────

async function run() {
  const state = loadState();
  const releaseAlerts = [];
  const eolAlerts = [];
  const cveAlerts = [];

  // ── 1. Load Sitecore lifecycle from scraper cache ──────────────────────────
  console.log("\n=== Sitecore Lifecycle (scraped) ===");
  const sitecoreLifecycle = loadSitecoreLifecycle();

  // ── 2. Sitecore packages ───────────────────────────────────────────────────
  console.log("\n=== Sitecore Packages ===");
  for (const pkg of PACKAGES) {
    console.log(`\nChecking ${pkg.name}...`);

    // Releases
    let releases = [];
    try { releases = await githubGet(`/repos/${pkg.repo}/releases?per_page=10`) || []; }
    catch (e) { console.error(`  Releases failed: ${e.message}`); }

    if (releases.length) {
      const latest = releases[0];
      const latestTag = latest.tag_name;
      const latestMajor = getMajor(latestTag);
      const prevTag = state[pkg.repo];
      const prevMajor = prevTag ? getMajor(prevTag) : null;
      console.log(`  Latest: ${latestTag} | Previous: ${prevTag || "none"}`);

      if (prevTag && prevTag !== latestTag) {
        const isMajorBump = pkg.watchMajorBump && prevMajor !== null && latestMajor !== null && latestMajor > prevMajor;
        const label = isMajorBump ? "*[MAJOR VERSION BUMP]*" : "*[NEW RELEASE]*";
        const extra = isMajorBump ? `\nv${prevMajor} -> v${latestMajor} — review breaking changes.` : "";
        releaseAlerts.push(
          `${label} ${pkg.name} — \`${latestTag}\`${extra}\n` +
          `Published: ${new Date(latest.published_at).toDateString()}\n` +
          `Release notes: https://github.com/${pkg.repo}/releases/tag/${latestTag}`
        );
      }
      state[pkg.repo] = latestTag;
    }

    // EOL from scraped lifecycle
    if (pkg.sitecoreProduct && sitecoreLifecycle.length) {
      const matched = sitecoreLifecycle.filter(e =>
        e.product && e.product.toLowerCase().includes(pkg.sitecoreProduct.toLowerCase())
      );
      if (matched.length) {
        const alerts = buildEolAlerts(pkg.name, pkg.releases, matched);
        eolAlerts.push(...alerts);
      } else {
        console.log(`  No lifecycle data found for "${pkg.sitecoreProduct}" in scraped cache.`);
      }
    }
  }

  // ── 3. endoflife.date packages (Next.js etc.) ──────────────────────────────
  console.log("\n=== endoflife.date Packages ===");
  for (const pkg of EOL_API_PACKAGES) {
    console.log(`\nChecking ${pkg.name}...`);

    // Releases
    let releases = [];
    try { releases = await githubGet(`/repos/${pkg.repo}/releases?per_page=10`) || []; }
    catch (e) { console.error(`  Releases failed: ${e.message}`); }

    if (releases.length) {
      const latest = releases[0];
      const latestTag = latest.tag_name;
      const latestMajor = getMajor(latestTag);
      const prevTag = state[pkg.repo];
      const prevMajor = prevTag ? getMajor(prevTag) : null;
      console.log(`  Latest: ${latestTag} | Previous: ${prevTag || "none"}`);

      if (prevTag && prevTag !== latestTag) {
        const isMajorBump = pkg.watchMajorBump && prevMajor !== null && latestMajor !== null && latestMajor > prevMajor;
        const label = isMajorBump ? "*[MAJOR VERSION BUMP]*" : "*[NEW RELEASE]*";
        const extra = isMajorBump ? `\nv${prevMajor} -> v${latestMajor} — review breaking changes.` : "";
        releaseAlerts.push(
          `${label} ${pkg.name} — \`${latestTag}\`${extra}\n` +
          `Published: ${new Date(latest.published_at).toDateString()}\n` +
          `Release notes: https://github.com/${pkg.repo}/releases/tag/${latestTag}`
        );
      }
      state[pkg.repo] = latestTag;
    }

    // EOL from endoflife.date
    const cycles = await fetchEolDateCycles(pkg.slug);
    const eolEntries = cycles
      .filter(c => c.eol && c.eol !== false && c.eol !== true)
      .map(c => ({ version: String(c.cycle), eolDate: c.eol }));
    const alerts = buildEolAlerts(pkg.name, pkg.releases, eolEntries);
    eolAlerts.push(...alerts);
  }

  // ── 4. CVE check ───────────────────────────────────────────────────────────
  console.log("\n=== CVE Check ===");
  const advisories = await checkSecurityAdvisories();
  const unique = [...new Map(advisories.map(a => [a.id, a])).values()];

  for (const adv of unique) {
    const age = daysAgo(adv.publishedAt);
    const isRecent = age <= CVE_ROLLING_WINDOW_DAYS;
    const stateKey = `cve:${adv.id}`;
    const alreadySeen = !!state[stateKey];

    if (isRecent || !alreadySeen) {
      const cvss = adv.cvssScore ? ` | CVSS: ${adv.cvssScore.toFixed(1)}` : "";
      const freshLabel = !alreadySeen ? " *(new)*" : ` *(${age}d ago)*`;
      cveAlerts.push(
        `*[${adv.severity} CVE]${freshLabel}* \`${adv.id}\` — ${adv.package}${cvss}\n` +
        `${adv.summary}\n` +
        `Affected: \`${adv.vulnerableVersionRange}\` | Patched: \`${adv.patchedVersion}\`\n` +
        `Details: ${adv.url}`
      );
      if (!alreadySeen) state[stateKey] = new Date().toISOString();
    }
  }

  saveState(state);

  // ── 5. Send alerts ─────────────────────────────────────────────────────────
  const totalAlerts = releaseAlerts.length + eolAlerts.length + cveAlerts.length;

  if (totalAlerts === 0) {
    console.log("\nAll clear. No new releases, no upcoming EOLs, no recent CVEs.");
    return;
  }

  const timestamp = new Date().toUTCString();
  const sections = [];
  if (releaseAlerts.length) sections.push(`*New Releases*\n${"-".repeat(30)}\n` + releaseAlerts.join("\n\n"));
  if (eolAlerts.length)     sections.push(`*EOL Warnings*\n${"-".repeat(30)}\n` + eolAlerts.join("\n\n"));
  if (cveAlerts.length)     sections.push(`*Security Advisories*\n${"-".repeat(30)}\n` + cveAlerts.join("\n\n"));

  const fullMessage =
    `*Dependency Monitor — ${timestamp}*\n${"=".repeat(40)}\n\n` +
    sections.join("\n\n");

  console.log("\n" + fullMessage);
  process.exitCode = 1; // Triggers GitHub email notification

  if (process.env.SLACK_WEBHOOK_URL) {
    await sendSlackAlert(fullMessage);
    console.log("\nSlack notification sent.");
  }
}

run().catch(e => { console.error("Monitor failed:", e); process.exit(1); });