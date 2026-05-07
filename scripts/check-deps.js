/**
 * Dependency Monitor
 * - Tracks upcoming EOL dates (warns up to 90 days before)
 * - Re-alerts on CVEs published within the last 30 days (rolling window)
 * - Runs 3x daily via GitHub Actions
 */

const https = require("https");
const fs = require("fs");

// ─── Configure your stack here ───────────────────────────────────────────────

const PACKAGES = [
  {
    name: "Sitecore JSS",
    repo: "Sitecore/jss",
    npmPkg: "@sitecore-jss/sitecore-jss",
    watchMajorBump: true,
    // Add known EOL dates here: { version, date }
    eolDates: [
      { version: "21", date: "2025-06-30" }, // June 2025 EOL — update as needed
    ],
  },
  {
    name: "Next.js",
    repo: "vercel/next.js",
    npmPkg: "next",
    watchMajorBump: true,
    eolDates: [
      { version: "14", date: "2024-10-21" }, // Already EOL
    ],
  },
  {
    name: "Sitecore XM Cloud Starter Kit",
    repo: "Sitecore/xm-cloud-introduction",
    npmPkg: null,
    watchMajorBump: true,
    eolDates: [],
  },
];

const NPM_PACKAGES_TO_AUDIT = [
  "next",
  "@sitecore-jss/sitecore-jss",
  "@sitecore-jss/sitecore-jss-nextjs",
  "react",
  "react-dom",
];

// CVEs published within this many days will always be included in alerts
const CVE_ROLLING_WINDOW_DAYS = 30;

// Warn about EOL this many days before the date
const EOL_WARN_DAYS_BEFORE = 90;

const STATE_FILE = ".dep-monitor-state.json";

// ─── Helpers ─────────────────────────────────────────────────────────────────

function githubGet(path) {
  return new Promise((resolve, reject) => {
    const headers = { "User-Agent": "dep-monitor/1.0", Accept: "application/vnd.github+json" };
    if (process.env.GITHUB_TOKEN) headers["Authorization"] = `Bearer ${process.env.GITHUB_TOKEN}`;
    https.get({ hostname: "api.github.com", path, headers }, (res) => {
      let data = "";
      res.on("data", (c) => (data += c));
      res.on("end", () => {
        if (res.statusCode === 404) { resolve([]); return; }
        if (res.statusCode !== 200) reject(new Error(`HTTP ${res.statusCode}`));
        else resolve(JSON.parse(data));
      });
    }).on("error", reject);
  });
}

function githubGraphQL(query) {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify({ query });
    const headers = {
      "User-Agent": "dep-monitor/1.0",
      "Content-Type": "application/json",
      "Content-Length": body.length,
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

function getMajor(tag) {
  const m = tag.replace(/^v/, "").match(/^(\d+)/);
  return m ? parseInt(m[1], 10) : null;
}

function daysFromNow(dateStr) {
  return Math.ceil((new Date(dateStr) - Date.now()) / 86400000);
}

function daysAgo(dateStr) {
  return Math.floor((Date.now() - new Date(dateStr)) / 86400000);
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

// ─── EOL Check ────────────────────────────────────────────────────────────────

function checkEolDates(pkg) {
  const alerts = [];
  for (const eol of pkg.eolDates || []) {
    const days = daysFromNow(eol.date);
    const eolFormatted = new Date(eol.date).toLocaleDateString("en-GB", { day:"numeric", month:"long", year:"numeric" });

    if (days > EOL_WARN_DAYS_BEFORE) {
      // Too far out — no alert yet
      continue;
    } else if (days > 0) {
      // Upcoming — always alert regardless of state
      alerts.push(
        `*[EOL UPCOMING]* ${pkg.name} v${eol.version} reaches end-of-life in *${days} days* (${eolFormatted}).\n` +
        `Action required: plan your upgrade before this date.\n` +
        `Releases: https://github.com/${pkg.repo}/releases`
      );
    } else {
      // Already past — alert once and mark as done
      const stateKey = `${pkg.repo}:eol-passed:${eol.version}`;
      alerts.push(
        `*[EOL PASSED]* ${pkg.name} v${eol.version} reached end-of-life on ${eolFormatted}.\n` +
        `No further security patches will be issued. Upgrade immediately.\n` +
        `Releases: https://github.com/${pkg.repo}/releases`
      );
      // Return the stateKey so caller can mark it seen after one past-EOL alert
      alerts._eolPassedKey = stateKey;
    }
  }
  return alerts;
}

// ─── CVE Check ────────────────────────────────────────────────────────────────

async function checkSecurityAdvisories(packageNames) {
  if (!process.env.GITHUB_TOKEN) {
    console.log("  Skipping CVE check — GITHUB_TOKEN required.");
    return [];
  }

  const advisories = [];
  for (const pkg of packageNames) {
    console.log(`  Checking advisories for ${pkg}...`);
    try {
      const result = await githubGraphQL(`{
        securityVulnerabilities(ecosystem:NPM, package:"${pkg}", first:10,
          orderBy:{field:UPDATED_AT, direction:DESC}) {
          nodes {
            advisory {
              ghsaId summary severity publishedAt updatedAt permalink
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
          package: pkg,
          id: cveId,
          summary: adv.summary,
          severity: adv.severity,
          cvssScore: adv.cvss?.score || null,
          vulnerableVersionRange: node.vulnerableVersionRange,
          patchedVersion: node.firstPatchedVersion?.identifier || "No patch yet",
          publishedAt: adv.publishedAt,
          updatedAt: adv.updatedAt,
          url: adv.permalink,
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

  // ── 1. Release check ───────────────────────────────────────────────────────
  console.log("\n=== Release Check ===");
  for (const pkg of PACKAGES) {
    console.log(`\nChecking ${pkg.name}...`);
    let releases;
    try { releases = await githubGet(`/repos/${pkg.repo}/releases?per_page=10`); }
    catch (e) { console.error(`  Failed: ${e.message}`); continue; }
    if (!releases.length) continue;

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

  // ── 2. EOL date check ─────────────────────────────────────────────────────
  console.log("\n=== EOL Date Check ===");
  for (const pkg of PACKAGES) {
    const alerts = checkEolDates(pkg);
    for (const alert of alerts) {
      if (typeof alert === "string") {
        eolAlerts.push(alert);
        console.log(`  EOL alert: ${pkg.name}`);
      }
    }
  }

  // ── 3. CVE check — rolling window ─────────────────────────────────────────
  console.log("\n=== Security Advisory Check ===");
  const advisories = await checkSecurityAdvisories(NPM_PACKAGES_TO_AUDIT);

  // Deduplicate by ID
  const unique = [...new Map(advisories.map((a) => [a.id, a])).values()];

  for (const adv of unique) {
    const age = daysAgo(adv.publishedAt);
    const isRecent = age <= CVE_ROLLING_WINDOW_DAYS;
    const stateKey = `cve:${adv.id}`;
    const alreadySeen = !!state[stateKey];

    if (isRecent) {
      // Always surface CVEs within the rolling window — even if seen before
      const cvss = adv.cvssScore ? ` | CVSS: ${adv.cvssScore.toFixed(1)}` : "";
      const freshLabel = !alreadySeen ? " *(new)*" : ` *(${age}d ago)*`;
      cveAlerts.push(
        `*[${adv.severity} CVE]${freshLabel}* \`${adv.id}\` — ${adv.package}${cvss}\n` +
        `${adv.summary}\n` +
        `Affected: \`${adv.vulnerableVersionRange}\` | Patched: \`${adv.patchedVersion}\`\n` +
        `Details: ${adv.url}`
      );
      if (!alreadySeen) {
        state[stateKey] = new Date().toISOString();
        console.log(`  New advisory: ${adv.id} (${adv.severity}) — ${adv.package}`);
      } else {
        console.log(`  Recent (${age}d ago, re-surfacing): ${adv.id}`);
      }
    } else {
      // Older than rolling window — alert once if never seen, then drop
      if (!alreadySeen) {
        const cvss = adv.cvssScore ? ` | CVSS: ${adv.cvssScore.toFixed(1)}` : "";
        cveAlerts.push(
          `*[${adv.severity} CVE]* \`${adv.id}\` — ${adv.package}${cvss}\n` +
          `${adv.summary}\n` +
          `Affected: \`${adv.vulnerableVersionRange}\` | Patched: \`${adv.patchedVersion}\`\n` +
          `Details: ${adv.url}`
        );
        state[stateKey] = new Date().toISOString();
        console.log(`  Older unseen advisory: ${adv.id}`);
      } else {
        console.log(`  Old + already seen, skipping: ${adv.id}`);
      }
    }
  }

  saveState(state);

  // ── 4. Send alerts ─────────────────────────────────────────────────────────
  const totalAlerts = releaseAlerts.length + eolAlerts.length + cveAlerts.length;

  if (totalAlerts === 0) {
    console.log("\nAll clear. No new releases, no upcoming EOLs, no recent CVEs.");
    return;
  }

  const timestamp = new Date().toUTCString();
  const sections = [];
  if (releaseAlerts.length) sections.push(`*New Releases*\n${"-".repeat(30)}\n` + releaseAlerts.join("\n\n"));
  if (eolAlerts.length)     sections.push(`*EOL Warnings*\n${"-".repeat(30)}\n` + eolAlerts.join("\n\n"));
  if (cveAlerts.length)     sections.push(`*Security Advisories (CVEs)*\n${"-".repeat(30)}\n` + cveAlerts.join("\n\n"));

  const fullMessage =
    `*Dependency Monitor — ${timestamp}*\n${"=".repeat(40)}\n\n` +
    sections.join("\n\n") +
    `\n\n_Monitoring: ${PACKAGES.map((p) => p.name).join(", ")}_`;

  console.log("\n" + fullMessage);

  // Exit code 1 triggers GitHub's built-in email notification
  process.exitCode = 1;

  if (process.env.SLACK_WEBHOOK_URL) {
    await sendSlackAlert(fullMessage);
    console.log("\nSlack notification sent.");
  }
}

run().catch((e) => { console.error("Monitor failed:", e); process.exit(1); });