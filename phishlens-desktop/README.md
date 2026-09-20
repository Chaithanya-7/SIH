# PhishLens Desktop

The installed counterpart to the PhishLens browser extension, and the process
that runs the backend.

PhishLens is reachable two ways, and they are deliberately not equivalent:

| Surface | What it shows |
|---|---|
| Browser extension popup | Only headline counts, the last few detections, and a **More info** button |
| Desktop application | The complete SOC console: investigations, campaigns, intelligence graph, quarantine queue, evidence, audit trail, forensic reports |

Clicking **More info** in the extension opens a `phishlens://` deep link. The
operating system routes it to this application, which focuses (or launches) the
console.

## It runs the backend for you

Launching the app is the only step. On start it:

1. **Checks whether a backend is already running.** If one is, it attaches to
   it rather than starting a second. Two backends sharing one data directory
   would corrupt the case store and sever the audit chain, so this is a safety
   rule rather than an optimisation.
2. **Generates an API key on first run** and keeps it in the per-user
   application data directory. A desktop install has no operator to invent a
   secret, so the app owns one and passes it to both the backend it starts and
   the console it loads. That is what makes the app work without setup.
3. **Waits until the backend actually answers** before loading the console. A
   dashboard rendering empty panels is indistinguishable from a healthy one
   with no mail in it, so the startup screen stays up until the backend is
   genuinely ready.
4. **Restarts a crash, but gives up on a loop.** Repeated immediate failures
   mean something is really wrong, and silently restarting forever would hide
   it. After three attempts it stops and shows the captured output.
5. **Never leaves the backend running.** The child process is stopped on every
   exit path, because an orphaned server holding the port would prevent the
   next launch. A backend it merely *attached* to is left alone — it belongs to
   whoever started it.

If the backend cannot start, the startup screen shows the failure, the reason,
and the backend's own log, with a retry button — rather than a blank window.

## Running from the repository

```
cd phishlens-desktop
npm install
npm run dev
```

`npm run dev` loads the live console from `http://localhost:3005`, so run the
dashboard dev server alongside it. Without `--dev` the app loads the built
dashboard from `phishlens-dashboard/dist`.

Run the supervisor tests with:

```
npm test
```

## Building an installer

```
cd phishlens-dashboard && npm run build
cd ../phishlens-desktop && npm run build
```

The installer bundles the dashboard build **and** the backend, and registers
the `phishlens://` scheme with the operating system. Installers are produced
per platform: NSIS on Windows, AppImage on Linux, DMG on macOS.

### The native module needs no rebuild

An earlier version of this file said `sqlite3` had to be rebuilt for Electron's
ABI before packaging. **That was wrong**, and it is corrected here rather than
quietly deleted, because acting on it would have meant a pointless build step.

`sqlite3` 6.x is a Node-API addon — its `package.json` declares
`napi_versions: [3, 6]` and the compiled binary exports `napi_*` symbols.
Node-API is ABI-stable across runtimes, so the same binary loads under system
Node and under Electron's embedded Node without being rebuilt.

Verified by running it: the same `node_sqlite3.node` opens a database, creates a
table, inserts, reads the row back and closes cleanly under system Node
(ABI 137) and under Electron's Node (ABI 149).

`PHISHLENS_BACKEND_NODE` still exists for running the backend under a Node
binary of your choosing, but it is not needed to work around this.

## Deep links

| Link | Result |
|---|---|
| `phishlens://dashboard` | Opens/focuses the console overview |
| `phishlens://case/<case-id>` | Opens the console and selects that case |

Only case ids matching `[A-Za-z0-9-]{1,64}` are accepted, and deep-link text is
never interpolated into the loaded URL. The window runs with context isolation
on and Node integration off, and any navigation away from the console is handed
to the user's normal browser.

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `PHISHLENS_API_PORT` | `3001` | Port the backend listens on |
| `PHISHLENS_DASHBOARD_URL` | `http://localhost:3005` | Console URL used in dev mode |
| `PHISHLENS_BACKEND_NODE` | unset | Path to a Node binary to run the backend with, instead of Electron's |
| `PHISHLENS_DEV` / `--dev` | unset | Load the live dev console instead of the bundled build |
| `PHISHLENS_DATA_DIR` | `<userData>/data` | Where cases, tokens and the audit ledger are kept |

### Where your data lives

Cases, tokens, the campaign graph and the audit ledger are written to
`PHISHLENS_DATA_DIR`, which the app sets to a `data` folder inside the per-user
application data directory.

They are deliberately not kept inside the installation. A packaged app's own
directory is read-only on Windows and macOS, so a backend writing there would
start and then fail the first time it tried to remember anything — and on an
upgrade or uninstall that history would be sitting in a directory the installer
replaces.
