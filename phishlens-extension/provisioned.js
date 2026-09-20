/**
 * Settings written here by the PhishLens desktop application.
 *
 * Loading an unpacked extension is already four steps in a place people do not
 * normally go. One of them was pasting a 64-character key that is generated per
 * install and lives in an application data folder, which is the step people
 * actually get stuck on - and the key is not a secret from the machine it was
 * generated on, so asking somebody to ferry it by hand bought nothing.
 *
 * The desktop app publishes a copy of this extension into its own writable data
 * directory and fills this file in on the way. Loading that copy needs no
 * configuration at all.
 *
 * In the source tree the values are empty, and the extension falls back to
 * asking for them on its options page exactly as before. Anything already saved
 * in the browser's own storage wins over this, so a deliberate change in the
 * options page is never overwritten by a provisioned default.
 */
globalThis.PHISHLENS_PROVISIONED = {
    apiBaseUrl: '',
    apiKey: '',
    provisionedAt: null
};
