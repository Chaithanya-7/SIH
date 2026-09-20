/**
 * Bounds how long something may take, and cleans up after itself.
 *
 * The pattern this replaces was written four times across this codebase and was
 * wrong in the same two ways each time.
 *
 * `Promise.race([work, timeout])` settles on whichever finishes first and
 * cancels neither. When the work wins - which is almost always - the timer
 * survives for its full duration, holding the event loop awake to reject a
 * promise nobody is waiting on. DNS and DKIM checks run on every message, so
 * the leak was proportional to traffic.
 *
 * The second fault was subtler and only in one place: a single timeout promise
 * created once and raced against two consecutive operations. The clock starts
 * when the promise is created, not when each race begins, so the second
 * operation inherited whatever time the first left over - and if the first took
 * nearly the full budget, the second failed instantly having been given no
 * chance at all. A deadline belongs to one operation.
 *
 * Rejecting with a named error rather than a bare timeout keeps the caller's
 * error handling able to tell "this took too long" from "this failed".
 */

class DeadlineExceededError extends Error {
    constructor(label, ms) {
        super(`${label} did not finish within ${ms}ms.`);
        this.name = 'DeadlineExceededError';
        this.code = 'DEADLINE_EXCEEDED';
        this.timedOut = true;
    }
}

/**
 * @param {Promise} work      the operation to bound
 * @param {number}  ms        how long it may take
 * @param {string}  label     what to call it if it does not finish
 */
function withDeadline(work, ms, label = 'The operation') {
    let timer = null;

    const deadline = new Promise((_, reject) => {
        timer = setTimeout(() => reject(new DeadlineExceededError(label, ms)), ms);
        // A pending lookup must never be the reason a process refuses to exit.
        // Called directly: Node's timers always carry unref, and guarding it
        // with a typeof check is the shape that once let a missing method hide
        // in this codebase - the hardening suite forbids it for that reason.
        timer.unref();
    });

    return Promise.race([work, deadline]).finally(() => {
        if (timer) clearTimeout(timer);
    });
}

module.exports = withDeadline;
module.exports.withDeadline = withDeadline;
module.exports.DeadlineExceededError = DeadlineExceededError;
