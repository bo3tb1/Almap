import os;
namespace ratelimit;

// modules/ratelimit.goose - Step 9: token-bucket rate limiter.
// No heap, no GC, no lifetime annotations. Limiter is a plain struct
// the caller owns; one per scan (not per host, not per port).
// Uses the stdlib monotonic clock (os clock_ns, documented as
// monotonic) and os sleep_ms, so no new C clock helper is needed.
// sleep_ms has whole-millisecond granularity: sub-millisecond
// remainders (< 1ms, i.e. rates above 1000/sec) are not slept.

struct Limiter { rate_per_sec: i64, next_ns: i64 }

// Interval between allowed actions: 0 for unlimited, else 1e9 / rate.
fn interval_ns(rate: i64) -> i64 {
    if rate <= 0 { return 0; }
    return 1000000000 / rate;
}

// Pure wait helper: nanoseconds still to wait given the last allowed
// time, now, and the interval. Returns 0 when no wait is needed
// (including unlimited or no last action yet, last_ns == 0, and the
// exact boundary elapsed == interval).
fn should_wait(last_ns: i64, now_ns: i64, interval_ns: i64) -> i64 {
    if interval_ns <= 0 { return 0; }
    if last_ns == 0 { return 0; }
    let elapsed = now_ns - last_ns;
    if elapsed >= interval_ns { return 0; }
    return interval_ns - elapsed;
}

fn limiter_new(rate_per_sec: i64) -> Limiter {
    Limiter { rate_per_sec: rate_per_sec, next_ns: 0 }
}

// Blocks until the next allowed action time (next_ns). The first
// call never waits because next_ns starts at 0. After a wait the
// schedule advances by one interval from the scheduled time, not
// from the wake time, so long scans do not drift earlier.
fn limiter_wait(l: Limiter&) {
    if l.rate_per_sec <= 0 { return; }
    let interval = interval_ns(l.rate_per_sec);
    if interval <= 0 { return; }
    let now = clock_ns();
    if l.next_ns > now {
        let need_ms = (l.next_ns - now) / 1000000;
        if need_ms > 0 { sleep_ms(need_ms); }
        l.next_ns = l.next_ns + interval;
    } else {
        l.next_ns = now + interval;
    }
}
