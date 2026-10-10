// SPDX-License-Identifier: Apache-2.0
//! Native-only, bounded complete-message admission. No wire QoS classification,
//! detached worker, Invoke retry or fragment reordering is introduced here.
use super::{
    encoded_message_len, NativeTxOutcome, QueryCapacity, RouteGate, ENCODED_MESSAGE_BYTES,
};
use std::{
    collections::VecDeque,
    sync::{Arc, Condvar, Mutex},
    time::{Duration, Instant},
};
use zenoh_buffers::{reader::HasReader, writer::HasWriter, ZSlice};
use zenoh_codec::{RCodec, WCodec, Zenoh080, Zenoh080Reliability};
use zenoh_protocol::network::{NetworkMessage, NetworkMessageExt, NetworkMessageMut};
use zenoh_transport::unicast::TransportUnicast;

const COUNTS: [usize; 2] = [32, 8];
const WAIT: Duration = Duration::from_millis(250);
#[derive(Default)]
pub(crate) struct TxBudget {
    used: Mutex<[(usize, usize); 2]>,
}
struct Permit {
    budget: Arc<TxBudget>,
    class: usize,
    bytes: usize,
}
impl TxBudget {
    fn reserve(self: &Arc<Self>, class: usize, bytes: usize) -> Result<Permit, NativeTxOutcome> {
        let mut used = self
            .used
            .lock()
            .map_err(|_| NativeTxOutcome::AllocationFailed)?;
        let (count, weight) = &mut used[class];
        if *count >= COUNTS[class] {
            return Err(NativeTxOutcome::CountExhausted);
        }
        if bytes > ENCODED_MESSAGE_BYTES.saturating_sub(*weight) {
            return Err(NativeTxOutcome::BytesExhausted);
        }
        *count += 1;
        *weight += bytes;
        Ok(Permit {
            budget: self.clone(),
            class,
            bytes,
        })
    }
}
impl Drop for Permit {
    fn drop(&mut self) {
        if let Ok(mut used) = self.budget.used.lock() {
            used[self.class].0 -= 1;
            used[self.class].1 -= self.bytes;
        }
    }
}
#[derive(Default)]
struct State {
    next: u64,
    queues: [VecDeque<u64>; 2],
    active: bool,
    controls: usize,
}
impl State {
    fn selected(&self) -> usize {
        if !self.queues[1].is_empty() && (self.controls < 4 || self.queues[0].is_empty()) {
            1
        } else {
            0
        }
    }
}
#[derive(Default)]
pub(crate) struct TxQueue {
    state: Mutex<State>,
    changed: Condvar,
}
struct Turn<'a> {
    queue: &'a TxQueue,
}
impl Drop for Turn<'_> {
    fn drop(&mut self) {
        if let Ok(mut state) = self.queue.state.lock() {
            state.active = false;
        }
        self.queue.changed.notify_all();
    }
}
impl TxQueue {
    fn enter(&self, class: usize, until: Instant) -> Option<Turn<'_>> {
        let mut state = self.state.lock().ok()?;
        let id = state.next;
        state.next = state.next.checked_add(1)?;
        state.queues[class].push_back(id);
        loop {
            if Instant::now() >= until {
                state.queues[class].retain(|ticket| *ticket != id);
                self.changed.notify_all();
                return None;
            }
            if !state.active
                && state.selected() == class
                && state.queues[class].front() == Some(&id)
            {
                state.queues[class].pop_front();
                state.active = true;
                state.controls = if class == 1 {
                    state.controls.saturating_add(1)
                } else {
                    0
                };
                return Some(Turn { queue: self });
            }
            let remaining = until.saturating_duration_since(Instant::now());
            state = self.changed.wait_timeout(state, remaining).ok()?.0;
        }
    }
    pub(crate) fn send(
        &self,
        budget: &Arc<TxBudget>,
        capacity: QueryCapacity,
        msg: NetworkMessageMut,
        transport: &TransportUnicast,
        gate: &dyn RouteGate,
    ) -> bool {
        let outcome = self.send_inner(budget, capacity, msg, transport);
        let observed = match outcome {
            Ok(true) => NativeTxOutcome::Scheduled,
            Ok(false) => NativeTxOutcome::TransportRejected,
            Err(reason) => reason,
        };
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            gate.observe_tx(capacity, observed)
        }));
        outcome.unwrap_or(false)
    }
    fn send_inner(
        &self,
        budget: &Arc<TxBudget>,
        capacity: QueryCapacity,
        msg: NetworkMessageMut,
        transport: &TransportUnicast,
    ) -> Result<bool, NativeTxOutcome> {
        let until = Instant::now() + WAIT;
        let Some(bytes) = encoded_message_len(&msg, ENCODED_MESSAGE_BYTES) else {
            return Err(NativeTxOutcome::InvalidEncoding);
        };
        let class = usize::from(capacity == QueryCapacity::Control);
        // Global per-Runtime permit is taken BEFORE allocating the compact copy,
        // and held through serialization/transport admission, including unwind.
        let _permit = budget.reserve(class, bytes)?;
        let mut encoded = Vec::new();
        if encoded.try_reserve_exact(bytes).is_err() {
            return Err(NativeTxOutcome::AllocationFailed);
        }
        if Zenoh080::new()
            .write(&mut encoded.writer(), msg.as_ref())
            .is_err()
            || encoded.len() != bytes
        {
            return Err(NativeTxOutcome::InvalidEncoding);
        }
        let reliability = msg.reliability;
        let Some(_turn) = self.enter(class, until) else {
            return Err(NativeTxOutcome::QueueDeadline);
        };
        // Decoding this trusted, just-encoded message severs every original
        // ZSlice backing reference. The compact owner lives through schedule.
        let mut encoded = ZSlice::from(encoded);
        let mut reader = encoded.reader();
        let Ok(mut owned): Result<NetworkMessage, _> =
            Zenoh080Reliability::new(reliability).read(&mut reader)
        else {
            return Err(NativeTxOutcome::InvalidEncoding);
        };
        Ok(transport
            .schedule_deadline(owned.as_mut(), until)
            .unwrap_or(false))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bytes_and_count_are_independent_and_held_until_drop() {
        let budget = Arc::new(TxBudget::default());
        let business = budget.reserve(0, ENCODED_MESSAGE_BYTES).unwrap();
        assert!(budget.reserve(0, 1).is_err());
        let control = budget.reserve(1, ENCODED_MESSAGE_BYTES).unwrap();
        assert!(budget.reserve(1, 1).is_err());
        drop(business);
        let permits: Vec<_> = (0..COUNTS[0])
            .map(|_| budget.reserve(0, 1).unwrap())
            .collect();
        assert!(budget.reserve(0, 1).is_err());
        drop(permits);
        drop(control);
        assert_eq!(*budget.used.lock().unwrap(), [(0, 0); 2]);
    }
    #[test]
    fn complete_message_turns_prioritize_control_without_starving_business() {
        let queue = Arc::new(TxQueue::default());
        let order = Arc::new(Mutex::new(Vec::new()));
        let active = queue.enter(0, Instant::now() + WAIT).unwrap();
        let until = Instant::now() + Duration::from_secs(2);
        let mut workers = Vec::new();
        for class in [0, 0, 1, 1, 1, 1, 1, 1] {
            let queue = queue.clone();
            let order = order.clone();
            workers.push(std::thread::spawn(move || {
                let _turn = queue.enter(class, until).unwrap();
                order.lock().unwrap().push(class);
            }));
        }
        loop {
            let state = queue.state.lock().unwrap();
            if state.queues[0].len() == 2 && state.queues[1].len() == 6 {
                break;
            }
            drop(state);
            assert!(Instant::now() < until);
            std::thread::yield_now();
        }
        drop(active);
        for worker in workers {
            worker.join().unwrap();
        }
        assert_eq!(*order.lock().unwrap(), [1, 1, 1, 1, 0, 1, 1, 0]);
    }
    #[test]
    fn waiting_timeout_removes_its_ticket_and_panic_releases_active_turn() {
        let queue = TxQueue::default();
        let active = queue.enter(0, Instant::now() + WAIT).unwrap();
        assert!(queue
            .enter(1, Instant::now() + Duration::from_millis(1))
            .is_none());
        assert!(queue
            .state
            .lock()
            .unwrap()
            .queues
            .iter()
            .all(VecDeque::is_empty));
        drop(active);
        assert!(std::panic::catch_unwind(|| {
            let _turn = queue.enter(1, Instant::now() + WAIT).unwrap();
            panic!("fixture");
        })
        .is_err());
        assert!(queue.enter(0, Instant::now() + WAIT).is_some());
    }

    // Actual routed Request/Reply/Final classification and native TX admission.
    // The fixture reserves bytes deterministically instead of relying on NIC speed.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn wire_control_reply_survives_business_bytes_pressure_and_business_recovers() {
        use super::super::{GateFactory, QueryCapacitySource, RouteRequest, RouteSubject};
        use std::sync::atomic::{AtomicUsize, Ordering};
        struct Gate {
            controls: AtomicUsize,
            refused: AtomicUsize,
        }
        impl RouteGate for Gate {
            fn authorize(&self, _: &RouteSubject, _: &RouteRequest<'_>) -> bool {
                true
            }
            fn query_capacity(
                &self,
                r: &RouteRequest<'_>,
                _: QueryCapacitySource,
            ) -> QueryCapacity {
                self.resource_capacity(r.key.unwrap_or(""))
            }
            fn resource_capacity(&self, key: &str) -> QueryCapacity {
                if key == "trusted/control" {
                    QueryCapacity::Control
                } else {
                    QueryCapacity::Business
                }
            }
            fn observe_tx(&self, capacity: QueryCapacity, outcome: NativeTxOutcome) {
                if capacity == QueryCapacity::Control
                    && matches!(outcome, NativeTxOutcome::Scheduled)
                {
                    self.controls.fetch_add(1, Ordering::SeqCst);
                }
                if capacity == QueryCapacity::Business
                    && matches!(outcome, NativeTxOutcome::BytesExhausted)
                {
                    self.refused.fetch_add(1, Ordering::SeqCst);
                }
            }
        }
        let gate = Arc::new(Gate {
            controls: AtomicUsize::new(0),
            refused: AtomicUsize::new(0),
        });
        let config = crate::Config::from_json5(r#"{mode:"router",listen:{endpoints:["tcp/127.0.0.1:0"]},scouting:{multicast:{enabled:false}},transport:{unicast:{qos:{enabled:false}}}}"#).unwrap();
        let mut router = crate::net::runtime::RuntimeBuilder::new(config)
            .build()
            .await
            .unwrap();
        router.install_route_gate(gate.clone()).unwrap();
        let factory = GateFactory::new(gate.clone());
        let budget = factory.tx_budget.clone();
        // Keep Runtime's native authorization state; replace only its factory
        // before the first Face exists so the test can hold the exact shared budget.
        router
            .router()
            .tables
            .tables
            .write()
            .unwrap()
            .data
            .interceptors = vec![Box::new(factory)];
        router.start().await.unwrap();
        let platform = crate::session::init(router.clone().into()).await.unwrap();
        let control = platform.declare_queryable("trusted/control").await.unwrap();
        let business = platform
            .declare_queryable("trusted/business")
            .await
            .unwrap();
        let config = crate::Config::from_json5(&format!(r#"{{mode:"client",connect:{{endpoints:["{}"]}},scouting:{{multicast:{{enabled:false}}}},transport:{{unicast:{{qos:{{enabled:false}}}}}}}}"#, router.get_locators()[0])).unwrap();
        let client = crate::open(config).await.unwrap();
        let occupied = budget.reserve(0, ENCODED_MESSAGE_BYTES).unwrap();
        for (key, handler, success) in [
            ("trusted/business", &business, false),
            ("trusted/control", &control, true),
        ] {
            let replies = client
                .get(key)
                .priority(crate::qos::Priority::RealTime)
                .timeout(Duration::from_millis(500))
                .await
                .unwrap();
            let query = tokio::time::timeout(Duration::from_secs(1), handler.recv_async())
                .await
                .unwrap()
                .unwrap();
            query.reply(key, "ok").await.unwrap();
            drop(query);
            let mut successes = 0;
            while let Ok(reply) = replies.recv_async().await {
                if let Ok(sample) = reply.result() {
                    assert_eq!(sample.payload().to_bytes().as_ref(), b"ok");
                    successes += 1;
                }
            }
            assert_eq!(successes, usize::from(success));
        }
        assert!(gate.refused.load(Ordering::SeqCst) >= 1);
        assert!(gate.controls.load(Ordering::SeqCst) >= 2); // Reply and Final inherit the request.
        drop(occupied);
        let replies = client.get("trusted/business").await.unwrap();
        let query = tokio::time::timeout(Duration::from_secs(1), business.recv_async())
            .await
            .unwrap()
            .unwrap();
        query.reply("trusted/business", "recovered").await.unwrap();
        drop(query);
        assert_eq!(
            replies
                .recv_async()
                .await
                .unwrap()
                .result()
                .unwrap()
                .payload()
                .to_bytes()
                .as_ref(),
            b"recovered"
        );
        drop(control);
        drop(business);
        client.close().await.unwrap();
        platform.close().await.unwrap();
        router.close().await.unwrap();
        assert_eq!(*budget.used.lock().unwrap(), [(0, 0); 2]);
    }
}
