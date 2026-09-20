const test = require('node:test');
const assert = require('node:assert');
const { EventEmitter } = require('node:events');
const path = require('node:path');

/**
 * Does a message that arrives actually get examined, and recorded as examined?
 *
 * Everything around the poller had been checked - credentials, folder choice,
 * coverage reporting - but never the one thing it exists to do. These drive the
 * poll against a fake IMAP server so the sequence can be observed exactly.
 */

// ---------------------------------------------------------------------------
// A fake IMAP server that behaves like the real one in the way that matters:
// the fetch stream ends as soon as the last message body has been delivered,
// without waiting for whatever the consumer does with it.
// ---------------------------------------------------------------------------
function installFakeImap(messages) {
    const imapPath = require.resolve('imap');

    class FakeImap extends EventEmitter {
        constructor(config) { super(); this.config = config; FakeImap.lastConfig = config; }
        connect() { setImmediate(() => this.emit('ready')); }
        openBox(name, readOnly, cb) { this.opened = name; cb(null, { messages: { total: messages.length } }); }
        search(criteria, cb) { FakeImap.lastSearch = criteria; cb(null, messages.map(m => m.uid)); }
        end() { this.emit('end'); }

        fetch(uids) {
            const stream = new EventEmitter();
            setImmediate(() => {
                for (const uid of uids) {
                    const wanted = messages.find(m => m.uid === uid);
                    if (!wanted) continue;
                    const msg = new EventEmitter();
                    stream.emit('message', msg, uid);
                    msg.emit('attributes', { uid });
                    const body = new EventEmitter();
                    body.setEncoding = () => {};
                    msg.emit('body', body);
                    body.emit('data', wanted.raw);
                    msg.emit('end');
                }
                // The real server does exactly this: it does not know or care
                // that the consumer's per-message handler is asynchronous.
                stream.emit('end');
            });
            return stream;
        }
    }

    require.cache[imapPath] = { id: imapPath, filename: imapPath, loaded: true, exports: FakeImap };
    return FakeImap;
}

function freshConnections() {
    ['../modules/mailConnections', '../modules/secretStore', '../modules/googleOAuth', '../modules/ingestionRegistry']
        .forEach(m => delete require.cache[require.resolve(m)]);
    return require('../modules/mailConnections');
}

const RAW = (n) => [
    'From: sender@example.com',
    'To: me@example.com',
    `Subject: Message number ${n}`,
    `Message-ID: <poll-${n}@example.com>`,
    '',
    'body'
].join('\r\n');

function connect(connections, { lastUid = 0 } = {}) {
    const secretStore = require('../modules/secretStore');
    const record = {
        id: 'c1',
        provider: 'gmail',
        email: 'me@example.com',
        host: 'imap.gmail.com',
        port: 993,
        folder: 'INBOX',
        secret: secretStore.encrypt('app-password'),
        messages_seen: 0,
        last_uid: lastUid
    };
    connections.connections.set('c1', record);
    return record;
}

test('a message that arrives is analysed, counted, and not offered again', async () => {
    installFakeImap([{ uid: 11, raw: RAW(11) }, { uid: 12, raw: RAW(12) }]);
    const connections = freshConnections();
    connections.save = () => {};

    const analysed = [];
    connections.setPipeline(async (raw, source, key, provenance) => {
        // Real analysis is asynchronous and takes far longer than this.
        await new Promise(r => setTimeout(r, 25));
        analysed.push({ subject: /Subject: (.*)/.exec(raw)[1], uid: provenance.uid });
    });

    const record = connect(connections);
    const result = await connections.pollOnce('c1');

    assert.strictEqual(analysed.length, 2, 'both messages must reach the pipeline');
    assert.deepStrictEqual(analysed.map(a => a.uid), [11, 12]);

    // The three facts that decide whether monitoring works at all. If the poll
    // finishes before the analysis it reported, every one of these is wrong:
    // the count stays at zero, the mailbox looks idle, and the next poll offers
    // the same messages again forever.
    assert.strictEqual(result.examined, 2, 'the poll must report what it actually examined');
    assert.strictEqual(record.messages_seen, 2, 'the mailbox must count what it examined');
    assert.strictEqual(record.last_uid, 12, 'the high-water mark must advance past what was handled');
});

test('the next poll offers nothing when nothing new has arrived', async () => {
    installFakeImap([{ uid: 11, raw: RAW(11) }]);
    const connections = freshConnections();
    connections.save = () => {};

    let calls = 0;
    connections.setPipeline(async () => { calls++; });

    const record = connect(connections, { lastUid: 11 });
    const result = await connections.pollOnce('c1');

    // IMAP's `N:*` returns the last message even when no message has a UID that
    // high, so a poller that trusts the server's answer re-analyses the newest
    // message on every single pass.
    assert.strictEqual(calls, 0, 'an already-handled message must not be analysed again');
    assert.strictEqual(result.examined, 0);
});

test('a mailbox is connected from now on, not from the beginning of time', async () => {
    installFakeImap([{ uid: 400, raw: RAW(400) }]);
    const connections = freshConnections();
    connections.save = () => {};
    connections.setPipeline(async () => {});

    // A newly connected mailbox must not treat its entire history as new mail:
    // the console says existing mail is not re-examined, and a real inbox holds
    // thousands of messages that would otherwise all enter the pipeline at once.
    connections.test = async () => ({ ok: true, messages_in_folder: 1, highestUid: 400 });
    const connection = await connections.add({
        provider: 'gmail', email: 'fresh@example.com', password: 'app-password', folder: 'INBOX'
    });

    const stored = connections.connections.get(connection.id);
    assert.strictEqual(stored.last_uid, 400,
        'connecting must start from the newest message present, so only later arrivals are examined');
});

test('one message failing analysis does not strand the ones after it', async () => {
    installFakeImap([
        { uid: 21, raw: RAW(21) },
        { uid: 22, raw: RAW(22) },
        { uid: 23, raw: RAW(23) }
    ]);
    const connections = freshConnections();
    connections.save = () => {};

    const seen = [];
    connections.setPipeline(async (raw, source, key, provenance) => {
        if (provenance.uid === 22) throw new Error('detection blew up on this one');
        seen.push(provenance.uid);
    });

    const record = connect(connections);
    const result = await connections.pollOnce('c1');

    assert.deepStrictEqual(seen, [21, 23], 'a failure in one message must not stop the others');
    assert.strictEqual(record.last_uid, 23, 'the high-water mark still advances past a message that failed');
    assert.strictEqual(result.examined, 2, 'only the messages actually examined are counted');
});
