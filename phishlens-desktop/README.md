# PhishLens Desktop

The installed counterpart to the PhishLens browser extension.

PhishLens is reachable two ways, and they are deliberately not equivalent:

| Surface | What it shows |
|---|---|
| Browser extension popup | Only headline counts (high risk / suspicious / legitimate), the last few detections, and a **More info** button |
| Desktop application | The complete SOC console: investigations, campaigns, intelligence graph, quarantine queue, evidence, audit trail, forensic reports |

Clicking **More info** in the extension opens a `phishlens://` deep link. The
operating system routes it to this application, which focuses (or launches) the
console. The desktop app is a shell around the same PhishLens dashboard build -
it is not a second implementation of it.

## Running from the repository

The desktop app displays the PhishLens console, so the backend and dashboard
must be running first (from the repository root, `start-all.bat`, or each
service directly). Then:

```
cd phishlens-desktop
npm install
npm run dev
```

`npm run dev` loads the live dashboard from `http://localhost:3005`. If the
console cannot be reached, the app shows a setup screen explaining what to
start rather than a blank window.

## Building an installer

```
cd phishlens-dashboard && npm run build
cd ../phishlens-desktop && npm run build
```

The dashboard build output is bundled into the installer, and the installer
registers the `phishlens://` scheme with the operating system. Installers are
produced per platform: NSIS on Windows, AppImage on Linux, DMG on macOS.

## Deep links

| Link | Result |
|---|---|
| `phishlens://dashboard` | Opens/focuses the console overview |
| `phishlens://case/<case-id>` | Opens the console and selects that case in Investigations |

Only case ids matching `[A-Za-z0-9-]{1,64}` are accepted; deep-link text is
never interpolated into the loaded URL. The window runs with context isolation
on and Node integration off, and any navigation away from the console is handed
to the user's normal browser instead of being loaded in the app window.

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `PHISHLENS_DASHBOARD_URL` | `http://localhost:3005` | Console URL used in dev mode |
| `PHISHLENS_API_URL` | `http://localhost:3001` | Backend URL reported to the renderer |
| `PHISHLENS_DEV` | unset | `1` forces loading the live dev console instead of the bundled build |

## Not yet implemented

The app does not start or supervise the PhishLens backend; the backend is
expected to be running already. Bundling and managing the backend process
inside the installer is the natural next step for a single-install deployment.
