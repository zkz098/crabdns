use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use crabdns_core::QueryEvent;
use tokio::sync::{broadcast, mpsc};

use crate::StorageEngine;

pub fn spawn_log_sink(
    storage: Arc<StorageEngine>,
    mut rx: mpsc::Receiver<QueryEvent>,
    live_tx: broadcast::Sender<QueryEvent>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut buffer = Vec::with_capacity(256);
        let mut interval = tokio::time::interval(Duration::from_millis(250));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                maybe_event = rx.recv() => {
                    if let Some(event) = maybe_event {
                        let _ = live_tx.send(event.clone());
                        buffer.push(event);
                        if buffer.len() >= 256 {
                            flush_buffer(&storage, &mut buffer).await;
                        }
                    } else {
                        flush_buffer(&storage, &mut buffer).await;
                        break;
                    }
                }
                _ = interval.tick() => {
                    flush_buffer(&storage, &mut buffer).await;
                }
            }
        }
    })
}

async fn flush_buffer(storage: &Arc<StorageEngine>, buffer: &mut Vec<QueryEvent>) {
    if buffer.is_empty() {
        return;
    }
    let batch = std::mem::replace(buffer, Vec::with_capacity(256));
    let st = Arc::clone(storage);
    let start = Instant::now();
    let res = tokio::task::spawn_blocking(move || st.record_batch(&batch)).await;
    let elapsed_us = u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX);
    storage
        .log_flush_total_us
        .fetch_add(elapsed_us, Ordering::Relaxed);
    match res {
        Ok(Ok(())) => {
            storage.log_batches_written.fetch_add(1, Ordering::Relaxed);
        }
        Ok(Err(err)) => {
            storage.log_batch_failures.fetch_add(1, Ordering::Relaxed);
            tracing::error!(error = %err, "failed to flush query logs to fjall");
        }
        Err(err) => {
            storage.log_batch_failures.fetch_add(1, Ordering::Relaxed);
            tracing::error!(error = %err, "query log flush task panicked");
        }
    }
}
