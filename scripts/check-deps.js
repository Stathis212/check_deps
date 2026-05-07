/**
 * Dependency Monitor
 * Checks GitHub releases + security advisories (CVEs) for key stack packages.
 * Runs 3x daily via GitHub Actions (morning / noon / afternoon).
 *
 * Setup:
 *   1. Add SLACK_WEBHOOK_URL to your repo secrets (optional but recommended)
 *   2. GITHUB_TOKEN is provided automatically by GitHub Actions
 *   3. Run manually first to build initial state
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
    knownEolVersions: [],
  },
  {
    name: "Next.js",
    repo: "vercel/next.js",
    npmPkg: "next",
    watchMajorBump: true,
    knownEolVersions: ["14"],
  },
  {
    name: "Sitecore XM Cloud Starter Kit",
    repo: "Sitecore/xm-cloud-introduction",
    npmPkg: null,
    watchMajorBump: true,
    knownEolVersions: [],
  },
];

// npm packages to check for CVEs via GitHub Advisory Database
// Add any package your project depends on
const NPM_PACKAGES_TO_AUDIT = [
  "next",
  "@sitecore-jss/sitecore-jss",
  "@sitecore-jss/sitecore-jss-nextjs",
  "react",
  "react-dom",
];

const STATE_FILE = ".dep-monitor-state.json";

// ─── Helpers ─────────────────────────────────────────────────────────────────

function githubGet(path) {
  return new Promise((resolve, reject) => {
    const headers = {
      "User-Agent": "dep-monitor/1.0",
      Accept: "application/vnd.github+json",
    };
    if (process.env.GITHUB_TOKEN) {
      headers["Authorization"] = `Bearer ${process.env.GITHUB_TOKEN}`;
    }
    https
      .get({ hostname: "api.github.com", path, headers }, (res) => {
        let data = "";
        res.on("data", (c) => (data += c));
        res.on("end", () => {
          if (res.statusCode === 404) { resolve([]); return; }
          if (res.statusCode !== 200) {
            reject(new Error(`HTTP ${res.statusCode} for ${path}`));
          } else {
            resolve(JSON.parse(data));
          }
        });
      })
      .on("error", reject);
  });
}

// GitHub GraphQL — needed for the Advisory Database (REST doesn't expose it well)
function githubGraphQL(query) {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify({ query });
    const headers = {
      "User-Agent": "dep-monitor/1.0",
      "Content-Type": "application/json",
      "Content-Length": body.length,
    };
    if (process.env.GITHUB_TOKEN) {
      headers["Authorization"] = `Bearer ${process.env.GITHUB_TOKEN}`;
    }
    const req = https.request(
      { hostname: "api.github.com", path: "/graphql", method: "POST", headers },
      (res) => {
        let data = "";
        res.on("data", (c) => (data += c));
        res.on("end", () => {
          if (res.statusCode !== 200) {
            reject(new Error(`GraphQL HTTP ${res.statusCode}`));
          } else {
            resolve(JSON.parse(data));
          }
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
      {
        hostname: parsed.hostname,
        path: parsed.pathname,
        method: "POST",
        headers: { "Content-Type": "application/json", "Content-Length": body.length },
      },
      (res) => { res.on("data", () => {}); res.on("end", resolve); }
    );
    req.on("error", (e) => console.error("Slack error:", e.message));
    req.write(body);
    req.end();
  });
}

// ─── CVE / Security Advisory Check ───────────────────────────────────────────

async function checkSecurityAdvisories(packageNames) {
  if (!process.env.GITHUB_TOKEN) {
    console.log("  Skipping CVE check — GITHUB_TOKEN required for Advisory Database.");
    return [];
  }

  const advisories = [];

  for (const pkg of packageNames) {
    console.log(`  Checking advisories for ${pkg}...`);
    try {
      const result = await githubGraphQL(`
        {
          securityVulnerabilities(
            ecosystem: NPM,
            package: "${pkg}",
            first: 5,
            orderBy: { field: UPDATED_AT, direction: DESC }
          ) {
            nodes {
              advisory {
                ghsaId
                summary
                severity
                publishedAt
                updatedAt
                permalink
                cvss { score vectorString }
                identifiers { type value }
              }
              vulnerableVersionRange
              firstPatchedVersion { identifier }
            }
          }
        }
      `);

      const nodes = result?.data?.securityVulnerabilities?.nodes || [];
      for (const node of nodes) {
        const adv = node.advisory;
        const cveId = adv.identifiers.find((i) => i.type === "CVE")?.value || adv.ghsaId;
        advisories.push({
          package: pkg,
          id: cveId,
          ghsaId: adv.ghsaId,
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

function severityLabel(severity) {
  return { CRITICAL: "[CRITICAL]", HIGH: "[HIGH]", MODERATE: "[MODERATE]", LOW: "[LOW]" }[severity] || "[UNKNOWN]";
}

// ─── Main ─────────────────────────────────────────────────────────────────────

async function run() {
  const state = loadState();
  const releaseAlerts = [];
  const cveAlerts = [];

  // ── 1. Check releases ──────────────────────────────────────────────────────
  console.log("\n=== Release Check ===");
  for (const pkg of PACKAGES) {
    console.log(`\nChecking ${pkg.name} (${pkg.repo})...`);
    let releases;
    try {
      releases = await githubGet(`/repos/${pkg.repo}/releases?per_page=10`);
    } catch (e) {
      console.error(`  Failed: ${e.message}`);
      continue;
    }

    if (!releases.length) { console.log("  No releases found."); continue; }

    const latest = releases[0];
    const latestTag = latest.tag_name;
    const latestMajor = getMajor(latestTag);
    const prevTag = state[pkg.repo];
    const prevMajor = prevTag ? getMajor(prevTag) : null;

    console.log(`  Latest: ${latestTag} | Previous: ${prevTag || "none"}`);

    if (prevTag && prevTag !== latestTag) {
      const isMajorBump =
        pkg.watchMajorBump && prevMajor !== null && latestMajor !== null && latestMajor > prevMajor;

      const label = isMajorBump ? "*[MAJOR VERSION BUMP]*" : "*[NEW RELEASE]*";
      const extra = isMajorBump
        ? `\nv${prevMajor} -> v${latestMajor} — review breaking changes before upgrading.`
        : "";
      releaseAlerts.push(
        `${label} ${pkg.name} — \`${latestTag}\`${extra}\n` +
        `Published: ${new Date(latest.published_at).toDateString()}\n` +
        `Release notes: https://github.com/${pkg.repo}/releases/tag/${latestTag}`
      );
    }

    for (const eolMajor of pkg.knownEolVersions || []) {
      const stateKey = `${pkg.repo}:eol:${eolMajor}`;
      if (!state[stateKey]) {
        releaseAlerts.push(
          `*[EOL WARNING]* ${pkg.name} v${eolMajor} is end-of-life.\n` +
          `Upgrade to v${latestMajor}+ is required.\n` +
          `Releases: https://github.com/${pkg.repo}/releases`
        );
        state[stateKey] = true;
      }
    }

    state[pkg.repo] = latestTag;
  }

  // ── 2. Check CVEs / Security Advisories ───────────────────────────────────
  console.log("\n=== Security Advisory Check ===");
  const advisories = await checkSecurityAdvisories(NPM_PACKAGES_TO_AUDIT);

  for (const adv of advisories) {
    const stateKey = `cve:${adv.id}`;
    if (!state[stateKey]) {
      const cvss = adv.cvssScore ? ` | CVSS: ${adv.cvssScore.toFixed(1)}` : "";
      cveAlerts.push(
        `*${severityLabel(adv.severity)} CVE* \`${adv.id}\` — ${adv.package}\n` +
        `${adv.summary}${cvss}\n` +
        `Affected: \`${adv.vulnerableVersionRange}\` | Patched in: \`${adv.patchedVersion}\`\n` +
        `Details: ${adv.url}`
      );
      state[stateKey] = new Date().toISOString();
      console.log(`  New advisory: ${adv.id} (${adv.severity}) — ${adv.package}`);
    } else {
      console.log(`  Already seen: ${adv.id}`);
    }
  }

  saveState(state);

  // ── 3. Send alerts ─────────────────────────────────────────────────────────
  const totalAlerts = releaseAlerts.length + cveAlerts.length;

  if (totalAlerts === 0) {
    console.log("\nNo new alerts. Stack is up to date and no new CVEs found.");
    return;
  }

  console.log(`\n${totalAlerts} alert(s) found.`);

  const timestamp = new Date().toUTCString();
  const sections = [];

  if (releaseAlerts.length) {
    sections.push(`*Releases & EOL*\n${"-".repeat(30)}\n` + releaseAlerts.join("\n\n"));
  }
  if (cveAlerts.length) {
    sections.push(`*Security Advisories (CVEs)*\n${"-".repeat(30)}\n` + cveAlerts.join("\n\n"));
  }

  const fullMessage =
    `*Dependency Monitor — ${timestamp}*\n${"=".repeat(40)}\n\n` +
    sections.join("\n\n") +
    `\n\n_Monitoring: ${PACKAGES.map((p) => p.name).join(", ")}_`;

  console.log("\n" + fullMessage);

  // Exit with code 1 so GitHub emails you via its built-in failure notification
  process.exitCode = 1;

  if (process.env.SLACK_WEBHOOK_URL) {
    await sendSlackAlert(fullMessage);
    console.log("\nSlack notification sent.");
  } else {
    console.log("\nTip: Add SLACK_WEBHOOK_URL as a repo secret to receive Slack notifications.");
  }
}

run().catch((e) => {
  console.error("Monitor failed:", e);
  process.exit(1);
});