/**
 * Dependency Monitor
 *
 * Sources per package type:
 *
 * endoflife.date packages  (Next.js, React)
 *   → EOL dates fetched live from endoflife.date API
 *   → GitHub Releases API for new versions
 *
 * GitHub-only packages  (TypeScript, Sitecore JSS, Content SDK, XM Cloud)
 *   → GitHub Releases API for new versions
 *   → Release body text scanned for lifecycle keywords (EOL, maintenance, deprecated...)
 *
 * Sitecore developer portal changelog
 *   → Playwright fetches the SitecoreAI changelog page
 *   → All entries scanned for lifecycle keywords
 *   → New entries alerted once, then tracked in state
 *
 * CVEs
 *   → GitHub Advisory Database, rolling 30-day window
 */

const https  = require("https");
const fs     = require("fs");
const path   = require("path");

// ─── Package definitions ──────────────────────────────────────────────────────

// Packages with EOL data from endoflife.date
const EOL_API_PACKAGES = [
  {
    name: "Next.js",
    repo: "vercel/next.js",
    slug: "nextjs",
    watchMajorBump: true,
    releases: "https://github.com/vercel/next.js/releases",
    docs: "https://nextjs.org/docs",
  },
  {
    name: "React",
    repo: "facebook/react",
    slug: "react",
    watchMajorBump: true,
    releases: "https://github.com/facebook/react/releases",
    docs: "https://react.dev",
  },
];

// Packages monitored via GitHub releases + release note scanning
// No formal EOL policy — we scan release bodies for lifecycle keywords
const GITHUB_PACKAGES = [
  {
    name: "Sitecore JSS",
    repo: "Sitecore/jss",
    watchMajorBump: true,
    scanReleaseNotes: true,
    releases: "https://github.com/Sitecore/jss/releases",
    docs: "https://doc.sitecore.com/xp/en/developers/hd/latest/sitecore-headless-development/sitecore-javascript-rendering-sdks--jss-.html",
  },
  {
    name: "Sitecore Content SDK",
    repo: "Sitecore/content-sdk",
    watchMajorBump: true,
    scanReleaseNotes: true,
    releases: "https://github.com/Sitecore/content-sdk/releases",
    docs: "https://developers.sitecore.com/content-sdk",
  },
  {
    name: "Sitecore XM Cloud",
    repo: "Sitecore/xm-cloud-introduction",
    watchMajorBump: true,
    scanReleaseNotes: true,
    releases: "https://github.com/Sitecore/xm-cloud-introduction/releases",
    docs: "https://doc.sitecore.com/xmc",
  },
  {
    name: "TypeScript",
    repo: "microsoft/TypeScript",
    watchMajorBump: true,
    // TypeScript has no formal EOL policy — we scan release notes for deprecation language
    // and alert on major version bumps
    scanReleaseNotes: true,
    releases: "https://github.com/microsoft/TypeScript/releases",
    docs: "https://www.typescriptlang.org/docs/",
  },
];

// Sitecore developer portal changelog pages to monitor for lifecycle announcements
const SITECORE_CHANGELOG_PAGES = [
  {
    name: "SitecoreAI Changelog",
    url: "https://developers.sitecore.com/changelog/sitecoreai",
    cacheFile: ".sitecore-changelog-sitecoreai.json",
  },
];

// npm packages to audit for CVEs
const NPM_PACKAGES_TO_AUDIT = [
  "next",
  "react",
  "react-dom",
  "@sitecore-jss/sitecore-jss",
  "@sitecore-jss/sitecore-jss-nextjs",
  "@sitecore-content-sdk/nextjs",
  "typescript",
];

// Keywords that indicate a lifecycle announcement in release notes or changelog entries
const LIFECYCLE_KEYWORDS = [
  "end of life",
  "end-of-life",
  "eol",
  "maintenance mode",
  "maintenance only",
  "deprecated",
  "deprecation",
  "no longer supported",
  "will no longer receive",
  "security fixes only",
  "critical fixes only",
  "reaching end",
  "support ends",
  "support ending",
  "sunset",
];

const CVE_ROLLING_WINDOW_DAYS = 30;
const EOL_WARN_DAYS_BEFORE    = 90;
const STATE_FILE = path.join(__dirname, "../.dep-monitor-state.json");

// ─── HTTP helpers ─────────────────────────────────────────────────────────────

function httpGet(hostname, apiPath, headers = {}) {
  return new Promise((resolve, reject) => {
    https.get(
      { hostname, path: apiPath, headers: { "User-Agent": "dep-monitor/1.0", ...headers } },
      (res) => {
        let data = "";
        res.on("data", (c) => (data += c));
        res.on("end", () => {
          if (res.statusCode === 404) { resolve(null); return; }
          if (res.statusCode !== 200) { reject(new Error(`HTTP ${res.statusCode} for https://${hostname}${apiPath}`)); return; }
          try { resolve(JSON.parse(data)); } catch { resolve(data); }
        });
      }
    ).on("error", reject);
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
      "User-Agent": "dep-monitor/1.0",
      "Content-Type": "application/json",
      "Content-Length": Buffer.byteLength(body),
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

// ─── Helpers ──────────────────────────────────────────────────────────────────

function getMajor(tag) {
  const m = tag.replace(/^v/, "").match(/^(\d+)/);
  return m ? parseInt(m[1], 10) : null;
}

function daysFromNow(d) {
  if (!d) return Infinity;
  return Math.ceil((new Date(d) - Date.now()) / 86400000);
}

function daysAgo(d) {
  return Math.floor((Date.now() - new Date(d)) / 86400000);
}

function fmt(d) {
  return new Date(d).toLocaleDateString("en-GB", { day: "numeric", month: "long", year: "numeric" });
}

function loadState() {
  try { return JSON.parse(fs.readFileSync(STATE_FILE, "utf8")); }
  catch { return {}; }
}

function saveState(state) {
  fs.writeFileSync(STATE_FILE, JSON.stringify(state, null, 2));
}

function isStableRelease(r) {
  return !r.prerelease && !/canary|alpha|beta|rc\./i.test(r.tag_name);
}

function containsLifecycleKeyword(text) {
  if (!text) return null;
  const lower = text.toLowerCase();
  return LIFECYCLE_KEYWORDS.find(kw => lower.includes(kw)) || null;
}

// Extract a short excerpt (up to 300 chars) around a matched keyword
function extractExcerpt(text, keyword) {
  if (!text || !keyword) return "";
  const lower = text.toLowerCase();
  const idx = lower.indexOf(keyword);
  if (idx === -1) return "";
  const start = Math.max(0, idx - 80);
  const end   = Math.min(text.length, idx + 220);
  return (start > 0 ? "…" : "") + text.slice(start, end).replace(/\n+/g, " ").trim() + (end < text.length ? "…" : "");
}

async function sendSlackAlert(message) {
  const url = process.env.SLACK_WEBHOOK_URL;
  if (!url) return;
  const body = JSON.stringify({ text: message });
  const parsed = new URL(url);
  return new Promise((resolve) => {
    const req = https.request(
      {
        hostname: parsed.hostname, path: parsed.pathname, method: "POST",
        headers: { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(body) },
      },
      (res) => { res.on("data", () => {}); res.on("end", resolve); }
    );
    req.on("error", (e) => console.error("Slack error:", e.message));
    req.write(body);
    req.end();
  });
}

// ─── endoflife.date ───────────────────────────────────────────────────────────

async function fetchEolCycles(slug) {
  try {
    const data = await httpGet("endoflife.date", `/api/v1/products/${slug}/`);
    if (!data) return [];
    // API v1 returns { result: { releases: [...] } } or a flat array
    if (data?.result?.releases) return data.result.releases;
    if (Array.isArray(data)) return data;
    return Object.values(data);
  } catch (e) {
    console.error(`  endoflife.date fetch failed for ${slug}: ${e.message}`);
    return [];
  }
}

function buildEolAlerts(pkgName, pkgReleasesUrl, cycles) {
  const alerts = [];
  for (const c of cycles) {
    // Handle both API formats
    const version  = String(c.name || c.cycle || "");
    const eolDate  = c.eolFrom || (typeof c.eol === "string" ? c.eol : null);
    const isEol    = c.isEol  || (c.eol === true);
    const isMaint  = c.isMaintained === false;

    if (!eolDate && !isEol) continue;

    const days = eolDate ? daysFromNow(eolDate) : -1;
    if (days > EOL_WARN_DAYS_BEFORE) continue;

    if (isEol || days <= 0) {
      alerts.push(
        `*[EOL]* ${pkgName} v${version} has reached end-of-life${eolDate ? ` (${fmt(eolDate)})` : ""}.\n` +
        `No further security patches. Upgrade immediately.\n` +
        `Releases: ${pkgReleasesUrl}`
      );
    } else {
      alerts.push(
        `*[EOL IN ${days} DAYS]* ${pkgName} v${version} reaches end-of-life on ${fmt(eolDate)}.\n` +
        `Plan your upgrade now — no security patches after this date.\n` +
        `Releases: ${pkgReleasesUrl}`
      );
    }
  }
  return alerts;
}

// ─── Release note scanning ────────────────────────────────────────────────────

async function scanReleaseNotes(pkg, releases, state) {
  const alerts = [];

  for (const r of releases.filter(isStableRelease).slice(0, 5)) {
    const stateKey = `releasenote:${pkg.repo}:${r.tag_name}`;
    if (state[stateKey]) continue; // already scanned

    const body = r.body || "";
    const keyword = containsLifecycleKeyword(r.name + " " + body);

    state[stateKey] = true; // mark as scanned regardless

    if (keyword) {
      const excerpt = extractExcerpt(body, keyword);
      alerts.push(
        `*[LIFECYCLE NOTICE]* ${pkg.name} ${r.tag_name} release notes mention "${keyword}".\n` +
        (excerpt ? `"${excerpt}"\n` : "") +
        `Full release notes: https://github.com/${pkg.repo}/releases/tag/${r.tag_name}`
      );
      console.log(`  ⚠  Lifecycle keyword "${keyword}" found in ${r.tag_name}`);
    }
  }

  return alerts;
}

// ─── Sitecore developer portal changelog ─────────────────────────────────────

async function scanSitecoreChangelog(state) {
  const alerts = [];

  // Only run if Playwright cache files exist (written by scrape-sitecore-lifecycle.js)
  for (const source of SITECORE_CHANGELOG_PAGES) {
    const cachePath = path.join(__dirname, "..", source.cacheFile);
    let entries = [];

    try {
      const cache = JSON.parse(fs.readFileSync(cachePath, "utf8"));
      entries = cache.entries || [];
      console.log(`  Sitecore changelog cache loaded: ${entries.length} entries (${cache.scraped})`);
    } catch {
      console.log(`  No changelog cache for ${source.name} — scraper may not have run yet.`);
      continue;
    }

    for (const entry of entries) {
      const stateKey = `sitecore-changelog:${entry.url || entry.title}`;
      if (state[stateKey]) continue; // already alerted

      const text = `${entry.title || ""} ${entry.body || ""}`;
      const keyword = containsLifecycleKeyword(text);

      // Always mark as seen so we don't re-alert next run
      state[stateKey] = new Date().toISOString();

      if (keyword) {
        const excerpt = extractExcerpt(text, keyword);
        alerts.push(
          `*[SITECORE ANNOUNCEMENT]* "${entry.title}" — keyword: "${keyword}"\n` +
          (excerpt ? `"${excerpt}"\n` : "") +
          `${entry.url || source.url}`
        );
        console.log(`  ⚠  Lifecycle keyword "${keyword}" in Sitecore changelog: "${entry.title}"`);
      }
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
        const adv   = node.advisory;
        const cveId = adv.identifiers.find(i => i.type === "CVE")?.value || adv.ghsaId;
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

// ─── Shared release check ─────────────────────────────────────────────────────

async function checkReleases(pkg, state) {
  const alerts = [];
  let releases = [];

  try {
    releases = await githubGet(`/repos/${pkg.repo}/releases?per_page=20`) || [];
  } catch (e) {
    console.error(`  Releases failed for ${pkg.name}: ${e.message}`);
    return { alerts, releases: [] };
  }

  const stable = releases.filter(isStableRelease);
  if (!stable.length) return { alerts, releases };

  const latest      = stable[0];
  const latestTag   = latest.tag_name;
  const latestMajor = getMajor(latestTag);
  const prevTag     = state[pkg.repo];
  const prevMajor   = prevTag ? getMajor(prevTag) : null;

  console.log(`  Latest stable: ${latestTag} | Previous: ${prevTag || "none"}`);

  if (prevTag && prevTag !== latestTag) {
    const isMajorBump = pkg.watchMajorBump && prevMajor !== null && latestMajor !== null && latestMajor > prevMajor;
    const label = isMajorBump ? "*[MAJOR VERSION BUMP]*" : "*[NEW RELEASE]*";
    const extra = isMajorBump ? `\nv${prevMajor} → v${latestMajor} — review breaking changes before upgrading.` : "";
    alerts.push(
      `${label} ${pkg.name} — \`${latestTag}\`${extra}\n` +
      `Published: ${new Date(latest.published_at).toDateString()}\n` +
      `Release notes: https://github.com/${pkg.repo}/releases/tag/${latestTag}`
    );
  }

  state[pkg.repo] = latestTag;
  return { alerts, releases };
}

// ─── Main ─────────────────────────────────────────────────────────────────────

async function run() {
  const state           = loadState();
  const releaseAlerts   = [];
  const eolAlerts       = [];
  const lifecycleAlerts = [];
  const cveAlerts       = [];

  // ── 1. endoflife.date packages (Next.js, React) ───────────────────────────
  console.log("\n=== endoflife.date Packages (Next.js, React) ===");
  for (const pkg of EOL_API_PACKAGES) {
    console.log(`\nChecking ${pkg.name}...`);

    const { alerts: rAlerts, releases } = await checkReleases(pkg, state);
    releaseAlerts.push(...rAlerts);

    // Scan release notes for lifecycle keywords
    if (releases.length) {
      const noteAlerts = await scanReleaseNotes(pkg, releases, state);
      lifecycleAlerts.push(...noteAlerts);
    }

    // EOL from endoflife.date
    const cycles = await fetchEolCycles(pkg.slug);
    const eoAlerts = buildEolAlerts(pkg.name, pkg.releases, cycles);
    eolAlerts.push(...eoAlerts);
  }

  // ── 2. GitHub-only packages (Sitecore, TypeScript) ────────────────────────
  console.log("\n=== GitHub Packages (Sitecore, TypeScript) ===");
  for (const pkg of GITHUB_PACKAGES) {
    console.log(`\nChecking ${pkg.name}...`);

    const { alerts: rAlerts, releases } = await checkReleases(pkg, state);
    releaseAlerts.push(...rAlerts);

    // Scan release notes for lifecycle keywords
    if (pkg.scanReleaseNotes && releases.length) {
      const noteAlerts = await scanReleaseNotes(pkg, releases, state);
      lifecycleAlerts.push(...noteAlerts);
    }
  }

  // ── 3. Sitecore developer portal changelog ────────────────────────────────
  console.log("\n=== Sitecore Developer Portal Changelog ===");
  const changelogAlerts = await scanSitecoreChangelog(state);
  lifecycleAlerts.push(...changelogAlerts);

  // ── 4. CVE check ──────────────────────────────────────────────────────────
  console.log("\n=== CVE Check ===");
  const advisories = await checkSecurityAdvisories();
  const unique = [...new Map(advisories.map(a => [a.id, a])).values()];

  for (const adv of unique) {
    const age         = daysAgo(adv.publishedAt);
    const isRecent    = age <= CVE_ROLLING_WINDOW_DAYS;
    const stateKey    = `cve:${adv.id}`;
    const alreadySeen = !!state[stateKey];

    if (isRecent || !alreadySeen) {
      const cvss       = adv.cvssScore ? ` | CVSS: ${adv.cvssScore.toFixed(1)}` : "";
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

  // ── 5. Build and send alert ───────────────────────────────────────────────
  const total = releaseAlerts.length + eolAlerts.length + lifecycleAlerts.length + cveAlerts.length;

  if (total === 0) {
    console.log("\n✓ All clear — no new releases, no lifecycle notices, no CVEs.");
    return;
  }

  console.log(`\n${total} alert(s) found.`);

  const timestamp = new Date().toUTCString();
  const sections  = [];
  if (releaseAlerts.length)   sections.push(`*New Releases*\n${"-".repeat(30)}\n`   + releaseAlerts.join("\n\n"));
  if (eolAlerts.length)       sections.push(`*EOL Warnings*\n${"-".repeat(30)}\n`   + eolAlerts.join("\n\n"));
  if (lifecycleAlerts.length) sections.push(`*Lifecycle Notices*\n${"-".repeat(30)}\n` + lifecycleAlerts.join("\n\n"));
  if (cveAlerts.length)       sections.push(`*Security Advisories*\n${"-".repeat(30)}\n` + cveAlerts.join("\n\n"));

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