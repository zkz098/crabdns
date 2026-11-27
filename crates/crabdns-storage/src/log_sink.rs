use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use crabdns_core::{QueryEvent, QueryOutcome};
use tokio::sync::{broadcast, mpsc};

use crate::StorageEngine;
use crate::models::{HOUR_MS, TIMESERIES_RETENTION_MS, TimeSeriesPoint};

const FLUSH_BATCH_CAPACITY: usize = 256;
const FLUSH_RETRY_DELAY: Duration = Duration::from_millis(200);
const DEGRADED_BASE_BACKOFF_SECS: u64 = 2;
const DEGRADED_MAX_BACKOFF_SECS: u64 = 60;

#[derive(Debug, Default)]
struct FlushBackoffState {
    consecutive_failures: u32,
    retry_after: Option<Instant>,
}

impl FlushBackoffState {
    fn is_in_backoff(&self, now: Instant) -> bool {
        self.retry_after.is_some_and(|until| now < until)
    }

    fn on_success(&mut self) {
        self.consecutive_failures = 0;
        self.retry_after = None;
    }

    fn on_failure(&mut self, now: Instant) -> Duration {
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        let shift = self.consecutive_failures.saturating_sub(1).min(5);
        let secs = DEGRADED_BASE_BACKOFF_SECS
            .saturating_mul(1_u64 << shift)
            .min(DEGRADED_MAX_BACKOFF_SECS);
        let delay = Duration::from_secs(secs);
        self.retry_after = Some(now + delay);
        delay
    }
}

impl StorageEngine {
    pub(crate) fn apply_in_memory_stats_without_buckets(
        &self,
        events: &[QueryEvent],
        deltas: (u64, u64, u64, u64, u64),
    ) {
        let (delta_total, delta_blocked, delta_cached, delta_rewritten, delta_error) = deltas;
        self.total_queries.fetch_add(delta_total, Ordering::Relaxed);
        self.blocked_queries
            .fetch_add(delta_blocked, Ordering::Relaxed);
        self.cached_queries
            .fetch_add(delta_cached, Ordering::Relaxed);
        self.rewritten_queries
            .fetch_add(delta_rewritten, Ordering::Relaxed);
        self.error_queries.fetch_add(delta_error, Ordering::Relaxed);

        for event in events {
            if event.outcome == QueryOutcome::Blocked {
                self.blocked_counts.increment(&event.domain);
            }
            self.domain_counts.increment(&event.domain);
            self.client_counts.increment(&event.client_ip);
            self.client_stats.record(event);
        }
    }

    /// Updates in-memory counters, timeseries buckets, and client stats without touching disk.
    /// Used as a degraded fallback when disk writes fail or are backing off.
    pub fn record_in_memory_only(&self, events: &[QueryEvent]) {
        if events.is_empty() {
            return;
        }
        let mut delta_total = 0_u64;
        let mut delta_blocked = 0_u64;
        let mut delta_cached = 0_u64;
        let mut delta_rewritten = 0_u64;
        let mut delta_error = 0_u64;

        {
            let mut buckets = self
                .hourly_buckets
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut max_bucket_ms = 0_u64;
            for event in events {
                delta_total += 1;
                match event.outcome {
                    QueryOutcome::Blocked => delta_blocked += 1,
                    QueryOutcome::Cached => delta_cached += 1,
                    QueryOutcome::Rewritten => delta_rewritten += 1,
                    QueryOutcome::Error => delta_error += 1,
                    QueryOutcome::Forwarded => {}
                }
                let ts_ms = event.timestamp.timestamp_millis().max(0).cast_unsigned();
                let bucket_ms = (ts_ms / HOUR_MS) * HOUR_MS;
                max_bucket_ms = max_bucket_ms.max(bucket_ms);
                let point = buckets.entry(bucket_ms).or_insert_with(|| TimeSeriesPoint {
                    timestamp_ms: bucket_ms,
                    ..TimeSeriesPoint::default()
                });
                point.total = point.total.saturating_add(1);
                match event.outcome {
                    QueryOutcome::Blocked => point.blocked = point.blocked.saturating_add(1),
                    QueryOutcome::Cached => point.cached = point.cached.saturating_add(1),
                    QueryOutcome::Rewritten => {
                        point.rewritten = point.rewritten.saturating_add(1);
                    }
                    QueryOutcome::Error => point.error = point.error.saturating_add(1),
                    QueryOutcome::Forwarded => {}
                }
            }
            let cutoff_ms = max_bucket_ms.saturating_sub(TIMESERIES_RETENTION_MS);
            buckets.retain(|&k, _| k >= cutoff_ms);
        }

        self.apply_in_memory_stats_without_buckets(
            events,
            (
                delta_total,
                delta_blocked,
                delta_cached,
                delta_rewritten,
                delta_error,
            ),
        );
    }
}

pub fn spawn_log_sink(
    storage: Arc<StorageEngine>,
    mut rx: mpsc::Receiver<QueryEvent>,
    live_tx: broadcast::Sender<QueryEvent>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut buffer = Vec::with_capacity(FLUSH_BATCH_CAPACITY);
        let mut backoff = FlushBackoffState::default();
        let mut interval = tokio::time::interval(Duration::from_millis(250));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                maybe_event = rx.recv() => {
                    if let Some(event) = maybe_event {
                        let _ = live_tx.send(event.clone());
                        buffer.push(event);
                        if buffer.len() >= FLUSH_BATCH_CAPACITY {
                            flush_buffer(&storage, &mut buffer, &mut backoff).await;
                        }
                    } else {
                        flush_buffer(&storage, &mut buffer, &mut backoff).await;
                        break;
                    }
                }
                _ = interval.tick() => {
                    flush_buffer(&storage, &mut buffer, &mut backoff).await;
                }
            }
        }
    })
}

async fn attempt_flush(
    storage: &Arc<StorageEngine>,
    batch: Vec<QueryEvent>,
) -> Result<(), (Vec<QueryEvent>, String)> {
    let st = Arc::clone(storage);
    let start = Instant::now();
    let res = tokio::task::spawn_blocking(move || {
        let result = st.record_batch(&batch);
        (batch, result)
    })
    .await;
    let elapsed_us = u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX);
    storage
        .log_flush_total_us
        .fetch_add(elapsed_us, Ordering::Relaxed);
    match res {
        Ok((_, Ok(()))) => Ok(()),
        Ok((batch, Err(err))) => Err((batch, err.to_string())),
        Err(err) => Err((Vec::new(), format!("query log flush task panicked: {err}"))),
    }
}

async fn flush_buffer(
    storage: &Arc<StorageEngine>,
    buffer: &mut Vec<QueryEvent>,
    backoff: &mut FlushBackoffState,
) {
    if buffer.is_empty() {
        return;
    }
    let batch = std::mem::replace(buffer, Vec::with_capacity(FLUSH_BATCH_CAPACITY));

    if backoff.is_in_backoff(Instant::now()) || storage.is_disk_pressure_active() {
        storage.record_in_memory_only(&batch);
        storage
            .log_batches_degraded_dropped
            .fetch_add(1, Ordering::Relaxed);
        return;
    }

    let first_err = match attempt_flush(storage, batch).await {
        Ok(()) => {
            backoff.on_success();
            storage.log_disk_degraded.store(false, Ordering::Relaxed);
            storage.log_batches_written.fetch_add(1, Ordering::Relaxed);
            return;
        }
        Err(err) => err,
    };

    // Single fast retry for transient I/O errors when not already degraded.
    let final_err = if backoff.consecutive_failures == 0 && !first_err.0.is_empty() {
        storage.log_batches_retried.fetch_add(1, Ordering::Relaxed);
        tokio::time::sleep(FLUSH_RETRY_DELAY).await;
        match attempt_flush(storage, first_err.0).await {
            Ok(()) => {
                backoff.on_success();
                storage.log_disk_degraded.store(false, Ordering::Relaxed);
                storage.log_batches_written.fetch_add(1, Ordering::Relaxed);
                return;
            }
            Err(err) => err,
        }
    } else {
        first_err
    };

    storage.log_batch_failures.fetch_add(1, Ordering::Relaxed);
    storage.log_disk_degraded.store(true, Ordering::Relaxed);
    if !final_err.0.is_empty() {
        storage.record_in_memory_only(&final_err.0);
    }
    let delay = backoff.on_failure(Instant::now());
    tracing::error!(
        error = %final_err.1,
        consecutive_failures = backoff.consecutive_failures,
        backoff_secs = delay.as_secs(),
        "failed to flush query logs to fjall; degraded to in-memory stats during backoff"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use crabdns_core::QueryProtocol;

    #[test]
    fn test_flush_backoff_progression_and_reset() {
        let mut state = FlushBackoffState::default();
        let t0 = Instant::now();
        assert!(!state.is_in_backoff(t0));

        assert_eq!(state.on_failure(t0), Duration::from_secs(2));
        assert!(state.is_in_backoff(t0 + Duration::from_secs(1)));
        assert!(!state.is_in_backoff(t0 + Duration::from_secs(2)));

        assert_eq!(state.on_failure(t0), Duration::from_secs(4));
        assert_eq!(state.on_failure(t0), Duration::from_secs(8));
        assert_eq!(state.on_failure(t0), Duration::from_secs(16));
        assert_eq!(state.on_failure(t0), Duration::from_secs(32));
        assert_eq!(state.on_failure(t0), Duration::from_secs(60));
        assert_eq!(state.on_failure(t0), Duration::from_secs(60));

        state.on_success();
        assert_eq!(state.consecutive_failures, 0);
        assert!(!state.is_in_backoff(t0));
    }

    #[test]
    fn test_record_in_memory_only_updates_stats_without_disk_logs() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = StorageEngine::open(dir.path()).expect("open");
        let ev = QueryEvent {
            timestamp: Utc::now(),
            client_ip: "192.168.1.50".to_string(),
            client_name: None,
            client_id: None,
            profile_id: None,
            protocol: QueryProtocol::Udp,
            domain: "ads.example.com".to_string(),
            qtype: "A".to_string(),
            outcome: QueryOutcome::Blocked,
            rcode: "NOERROR".to_string(),
            matched_rule: Some("||ads.example.com^".to_string()),
            matched_list: None,
            upstream: None,
            answers: vec![],
            elapsed_us: 120,
        };

        storage.record_in_memory_only(&[ev]);
        let snap = storage.stats_snapshot();
        assert_eq!(snap.total_queries, 1);
        assert_eq!(snap.blocked_queries, 1);
        assert_eq!(storage.query_logs(10, None, None).unwrap().len(), 0);
    }
}
