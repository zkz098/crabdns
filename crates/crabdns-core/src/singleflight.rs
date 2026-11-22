use std::hash::Hash;
use std::sync::Arc;

use dashmap::DashMap;
use dashmap::mapref::entry::Entry;
use foldhash::fast::RandomState;
use tokio::sync::watch;

pub type FlightResult<V> = std::result::Result<V, String>;
pub type FlightReceiver<V> = watch::Receiver<Option<FlightResult<V>>>;
type FlightMap<K, V> = DashMap<K, watch::Sender<Option<FlightResult<V>>>, RandomState>;

/// Deduplicates concurrent in-flight async operations sharing the same key.
pub struct Singleflight<K, V>
where
    K: Eq + Hash + Clone,
    V: Clone,
{
    flights: Arc<FlightMap<K, V>>,
}

impl<K, V> Default for Singleflight<K, V>
where
    K: Eq + Hash + Clone,
    V: Clone,
{
    fn default() -> Self {
        Self::new()
    }
}

pub enum FlightRole<K, V>
where
    K: Eq + Hash + Clone,
    V: Clone,
{
    Leader(FlightGuard<K, V>),
    Follower(watch::Receiver<Option<FlightResult<V>>>),
}

pub struct FlightGuard<K, V>
where
    K: Eq + Hash + Clone,
    V: Clone,
{
    flights: Arc<FlightMap<K, V>>,
    key: K,
    tx: watch::Sender<Option<FlightResult<V>>>,
    completed: bool,
}

impl<K, V> FlightGuard<K, V>
where
    K: Eq + Hash + Clone,
    V: Clone,
{
    pub fn complete(mut self, result: FlightResult<V>) {
        self.completed = true;
        self.flights.remove(&self.key);
        let _ = self.tx.send(Some(result));
    }
}

impl<K, V> Drop for FlightGuard<K, V>
where
    K: Eq + Hash + Clone,
    V: Clone,
{
    fn drop(&mut self) {
        if !self.completed {
            self.flights.remove(&self.key);
            let _ = self
                .tx
                .send(Some(Err("inflight leader cancelled".to_string())));
        }
    }
}

impl<K, V> Singleflight<K, V>
where
    K: Eq + Hash + Clone,
    V: Clone,
{
    pub fn new() -> Self {
        Self {
            flights: Arc::new(DashMap::with_hasher(RandomState::default())),
        }
    }

    pub fn inflight_count(&self) -> usize {
        self.flights.len()
    }

    pub fn acquire(&self, key: K) -> FlightRole<K, V> {
        match self.flights.entry(key.clone()) {
            Entry::Occupied(entry) => FlightRole::Follower(entry.get().subscribe()),
            Entry::Vacant(entry) => {
                let (tx, _rx) = watch::channel(None);
                entry.insert(tx.clone());
                FlightRole::Leader(FlightGuard {
                    flights: Arc::clone(&self.flights),
                    key,
                    tx,
                    completed: false,
                })
            }
        }
    }
}

pub async fn wait_follower<V: Clone>(
    mut rx: watch::Receiver<Option<FlightResult<V>>>,
) -> FlightResult<V> {
    loop {
        if let Some(res) = rx.borrow_and_update().clone() {
            return res;
        }
        if rx.changed().await.is_err() {
            return Err("inflight leader dropped".to_string());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test]
    async fn test_singleflight_coalesces_leader_and_followers() {
        let sf: Arc<Singleflight<String, Vec<u8>>> = Arc::new(Singleflight::new());
        let leader_runs = Arc::new(AtomicUsize::new(0));
        let gate = Arc::new(tokio::sync::Notify::new());

        let sf1 = Arc::clone(&sf);
        let leader_counter = Arc::clone(&leader_runs);
        let gate1 = Arc::clone(&gate);
        let t1 = tokio::spawn(async move {
            match sf1.acquire("example.com".to_string()) {
                FlightRole::Leader(guard) => {
                    leader_counter.fetch_add(1, Ordering::SeqCst);
                    gate1.notified().await;
                    let val = vec![1, 2, 3, 4];
                    guard.complete(Ok(val.clone()));
                    Ok(val)
                }
                FlightRole::Follower(rx) => wait_follower(rx).await,
            }
        });

        tokio::task::yield_now().await;

        let mut followers = Vec::new();
        for _ in 0..8 {
            let sfn = Arc::clone(&sf);
            let follower_counter = Arc::clone(&leader_runs);
            followers.push(tokio::spawn(async move {
                match sfn.acquire("example.com".to_string()) {
                    FlightRole::Leader(guard) => {
                        follower_counter.fetch_add(1, Ordering::SeqCst);
                        guard.complete(Ok(vec![9]));
                        Ok(vec![9])
                    }
                    FlightRole::Follower(rx) => wait_follower(rx).await,
                }
            }));
        }

        tokio::task::yield_now().await;
        gate.notify_one();

        assert_eq!(t1.await.unwrap().unwrap(), vec![1, 2, 3, 4]);
        for f in followers {
            assert_eq!(f.await.unwrap().unwrap(), vec![1, 2, 3, 4]);
        }
        assert_eq!(leader_runs.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_singleflight_leader_drop_wakes_follower() {
        let sf: Singleflight<String, u32> = Singleflight::new();
        let FlightRole::Leader(guard) = sf.acquire("dropped.test".to_string()) else {
            panic!("expected leader");
        };
        let FlightRole::Follower(rx) = sf.acquire("dropped.test".to_string()) else {
            panic!("expected follower");
        };
        drop(guard);
        let res = wait_follower(rx).await;
        assert!(res.is_err());

        // Subsequent acquire should become leader cleanly
        let FlightRole::Leader(guard2) = sf.acquire("dropped.test".to_string()) else {
            panic!("expected new leader after drop");
        };
        guard2.complete(Ok(42));
    }
}
