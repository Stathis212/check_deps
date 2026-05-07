# Stack Monitor

Monitors releases, EOL dates, and CVE security advisories for your frontend stack. Runs automatically 3x daily via GitHub Actions and sends email alerts when something needs attention.

---

## What it monitors

| Package | Repo |
|---|---|
| Sitecore JSS | `Sitecore/jss` |
| Next.js | `vercel/next.js` |
| Sitecore XM Cloud | `Sitecore/xm-cloud-introduction` |

CVE audits cover: `next`, `@sitecore-jss/sitecore-jss`, `@sitecore-jss/sitecore-jss-nextjs`, `react`, `react-dom`

---

## Alerts

The monitor will alert on:

- **New releases** — any new version published on GitHub
- **Major version bumps** — flags breaking change risk
- **Upcoming EOL** — warns 90 days before end-of-life, daily until the date passes
- **CVEs** — any security advisory published in the last 30 days is always included in alerts (not suppressed after first sighting)

Alerts are delivered via **GitHub's built-in email notification** — you receive an email whenever the workflow exits with alerts. To enable it, go to GitHub → Settings → Notifications → Actions → enable **Failed workflows only**.

Optional: add a `SLACK_WEBHOOK_URL` repository secret to also receive Slack notifications.

---

## Repo structure

```
├── index.html                              # Live dashboard (GitHub Pages)
├── scripts/
│   └── check-deps.js                       # Monitoring script
└── .github/
    └── workflows/
        ├── dependency-monitor.yml          # Runs checks 3x daily
        └── deploy-pages.yml                # Deploys dashboard to GitHub Pages
```

---

## Setup

### 1. Enable GitHub Pages

Go to **Settings → Pages → Source** and select **GitHub Actions**. The dashboard will be deployed automatically on every push and available at:

```
https://<your-username>.github.io/<your-repo>
```

### 2. Enable email notifications

Go to **github.com → profile → Settings → Notifications → Actions** and enable **Failed workflows only** for email.

### 3. (Optional) Slack notifications

Add a `SLACK_WEBHOOK_URL` secret under **Settings → Secrets and variables → Actions**.

### 4. Run manually for the first time

Go to **Actions → Dependency Monitor → Run workflow** to build the initial state and verify everything works.

---

## Updating EOL dates

EOL dates are defined in two places — keep them in sync when new dates are announced:

**`scripts/check-deps.js`** — in the `PACKAGES` array:
```js
eolDates: [
  { version: "21", date: "2025-06-30" }
]
```

**`index.html`** — in the `PACKAGES` array at the top of the `<script>` block:
```js
eolDates: [{ version:"21", date:"2025-06-30" }]
```

Dates use `YYYY-MM-DD` format. The dashboard countdown and email alerts update automatically once the date is saved and pushed.

---

## Adjusting alert thresholds

Both `check-deps.js` and `index.html` share the same configurable constants at the top:

| Constant | Default | Description |
|---|---|---|
| `CVE_ROLLING_WINDOW_DAYS` | `30` | CVEs published within this window are always surfaced |
| `EOL_WARN_DAYS_BEFORE` | `90` | How far in advance to start warning about an EOL date |

---

## Schedule

The monitor runs at these times (UTC) every day:

| Run | Time (UTC) |
|---|---|
| Morning | 07:00 |
| Noon | 12:00 |
| Afternoon | 16:00 |

To change the schedule, edit the `cron` entries in `.github/workflows/dependency-monitor.yml`.
