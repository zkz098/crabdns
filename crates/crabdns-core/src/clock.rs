use std::sync::OnceLock;
use std::time::Instant;

static MONO_EPOCH: OnceLock<Instant> = OnceLock::new();

pub(crate) fn monotonic_now_ms() -> u64 {
    let epoch = MONO_EPOCH.get_or_init(Instant::now);
    let elapsed = Instant::now().saturating_duration_since(*epoch);
    u64::try_from(elapsed.as_millis())
        .unwrap_or(u64::MAX - 1)
        .saturating_add(1)
}
