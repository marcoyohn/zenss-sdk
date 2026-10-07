// SPDX-License-Identifier: Apache-2.0
// ZenSS extension to Zenoh 1.10.1. Network encoding and native ACLs are unchanged.
//! Version-pinned synchronous admission hook. Implementations must be bounded,
//! nonblocking, fail closed, and check current leases on every invocation.
use super::{
    EgressInterceptor, IngressInterceptor, InterceptorContext, InterceptorFactoryTrait,
    InterceptorTrait,
};
use std::{
    any::Any,
    collections::HashMap,
    num::NonZeroUsize,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex, Weak,
    },
    time::{Duration, Instant},
};
#[cfg(feature = "zenss-router-origin")]
use zenoh_buffers::buffer::Buffer;
use zenoh_buffers::writer::{DidntWrite, Writer};
use zenoh_codec::{WCodec, Zenoh080};
use zenoh_keyexpr::keyexpr;
use zenoh_link::LinkAuthId;
use zenoh_protocol::{
    core::{CongestionControl, WhatAmI},
    network::{
        interest::InterestMode, DeclareBody, NetworkBodyMut, NetworkMessageExt, NetworkMessageMut,
    },
    zenoh::{PushBody, ResponseBody},
};
use zenoh_result::ZResult;
use zenoh_transport::{multicast::TransportMulticast, unicast::TransportUnicast};

// Match the minimum RX frame; payload-only checks omit parameters, extensions,
// encodings and keys. This bounds logical encoded bytes, not backing allocations.
const ENCODED_MESSAGE_BYTES: usize = 20 * 1024 * 1024 + 64 * 1024;
pub(crate) mod tx_queue;

struct EncodedCounter {
    used: usize,
    limit: usize,
}
impl EncodedCounter {
    fn charge(&mut self, bytes: usize) -> Result<(), DidntWrite> {
        if bytes > self.remaining() {
            return Err(DidntWrite);
        }
        self.used += bytes; // bounded by limit, so cannot overflow
        Ok(())
    }
}
impl Writer for EncodedCounter {
    fn write(&mut self, bytes: &[u8]) -> Result<NonZeroUsize, DidntWrite> {
        let written = NonZeroUsize::new(bytes.len()).ok_or(DidntWrite)?;
        self.charge(bytes.len())?;
        Ok(written)
    }
    fn write_exact(&mut self, bytes: &[u8]) -> Result<(), DidntWrite> {
        self.charge(bytes.len())
    }
    fn remaining(&self) -> usize {
        self.limit - self.used
    }
    unsafe fn with_slot<F>(&mut self, len: usize, write: F) -> Result<NonZeroUsize, DidntWrite>
    where
        F: FnOnce(&mut [u8]) -> usize,
    {
        // Official Zenoh080 uses slots only for at-most-nine-byte VLEs. Refuse
        // a future codec that requires more scratch rather than allocate here.
        let mut scratch = [0u8; 9];
        if len > scratch.len() {
            return Err(DidntWrite);
        }
        let written = write(&mut scratch[..len]);
        if written > len {
            return Err(DidntWrite);
        }
        let written = NonZeroUsize::new(written).ok_or(DidntWrite)?;
        self.charge(written.get())?;
        Ok(written)
    }
}
pub(crate) fn encoded_message_len(msg: &NetworkMessageMut, limit: usize) -> Option<usize> {
    let mut counter = EncodedCounter { used: 0, limit };
    Zenoh080::new().write(&mut counter, msg.as_ref()).ok()?;
    Some(counter.used)
}

// BlockFirst clones a complete message into a transport-owned background
// task (one waiter per sender-selected priority), outside the one StageIn
// fragmentation envelope. Use finite synchronous Block on gated transports.
// Drop/Block and the caller's priority/express bits remain unchanged.
pub(crate) fn bound_encoded_message(msg: &mut NetworkMessageMut, limit: usize) -> bool {
    if msg.congestion_control() == CongestionControl::BlockFirst {
        match &mut msg.body {
            NetworkBodyMut::Push(m) => m.ext_qos.set_congestion_control(CongestionControl::Block),
            NetworkBodyMut::Request(m) => {
                m.ext_qos.set_congestion_control(CongestionControl::Block)
            }
            NetworkBodyMut::Response(m) => {
                m.ext_qos.set_congestion_control(CongestionControl::Block)
            }
            NetworkBodyMut::ResponseFinal(m) => {
                m.ext_qos.set_congestion_control(CongestionControl::Block)
            }
            NetworkBodyMut::Interest(m) => {
                m.ext_qos.set_congestion_control(CongestionControl::Block)
            }
            NetworkBodyMut::Declare(m) => {
                m.ext_qos.set_congestion_control(CongestionControl::Block)
            }
            NetworkBodyMut::OAM(m) => m.ext_qos.set_congestion_control(CongestionControl::Block),
        }
    }
    encoded_message_len(msg, limit).is_some()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteFlow {
    Ingress,
    Egress,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteAction {
    Query,
    Reply,
    Put,
    Delete,
    DeclareQueryable,
    DeclareSubscriber,
    LivelinessToken,
    Interest,
    Resource,
    Topology,
}
/// TLS common name is populated only when every current link is TLS-authenticated
/// with the same certificate identity. A claimed ZID is never authentication.
#[derive(Clone, Debug)]
pub struct RouteSubject {
    pub tls_common_name: Option<String>,
    /// Actual native RSA possession handshake, never a wire identity claim.
    pub public_key_der: Option<Vec<u8>>,
    pub role: WhatAmI,
}
#[derive(Clone, Debug)]
pub struct RouteRequest<'a> {
    pub action: RouteAction,
    pub flow: RouteFlow,
    pub key: Option<&'a str>,
    pub payload: Option<&'a [u8]>,
}
/// Internal classification context; never read from a wire extension or QoS.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QueryCapacitySource {
    /// A trusted native Session, not a remote sender.
    Local,
    /// Called by the interceptor only after current authorization succeeds.
    Admitted,
    /// Called by routing for a remote sender; implementations must check its receipt.
    Routed,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QueryCapacity {
    Business,
    Control,
}
/// Fixed native transport evidence. Scheduled is only local TX admission,
/// never a business result, center custody or completed remote consumption.
#[derive(Clone, Copy, Debug)]
#[repr(usize)]
pub enum NativeTxOutcome {
    Scheduled,
    CountExhausted,
    BytesExhausted,
    InvalidEncoding,
    AllocationFailed,
    QueueDeadline,
    TransportRejected,
}
pub trait RouteGate: Send + Sync {
    fn observe_tx(&self, _capacity: QueryCapacity, _outcome: NativeTxOutcome) {}
    /// Capacity for a shared, exact native resource identity. Never authorizes a
    /// sender or Query. Only trusted installed control policy may opt in; wire
    /// IDs, prefixes, QoS and payload claims cannot select this reserve.
    fn resource_capacity(&self, _key: &str) -> QueryCapacity {
        QueryCapacity::Business
    }

    /// Bounded, readonly classification. This grants capacity, never authorization.
    /// Existing gates receive no reserved capacity until they explicitly opt in.
    fn query_capacity(
        &self,
        _request: &RouteRequest<'_>,
        _source: QueryCapacitySource,
    ) -> QueryCapacity {
        QueryCapacity::Business
    }

    fn authorize(&self, subject: &RouteSubject, request: &RouteRequest<'_>) -> bool;
    /// Optional matched-host ABI: reserved Query attachment, never application payload.
    /// Returning an error denies admission. Implementations must bound input/output.
    #[cfg(feature = "zenss-router-origin")]
    fn query_origin(
        &self,
        subject: &RouteSubject,
        request: &RouteRequest<'_>,
        attachment: Option<&[u8]>,
    ) -> ZResult<Option<Vec<u8>>> {
        if attachment.is_some() || !self.authorize(subject, request) {
            return Err(zenoh_result::zerror!("query origin denied").into());
        }
        Ok(None)
    }
    /// Privileged native control only; never exposed as a remote Zenoh Queryable.
    fn command(&self, _command: &[u8]) -> ZResult<()> {
        Err(zenoh_result::zerror!("gate does not accept commands").into())
    }
    /// Native-only lookup of an admission receipt for the actual bytes and target.
    fn principal(&self, _digest: &[u8; 32], _key: &str) -> ZResult<Vec<u8>> {
        Err(zenoh_result::zerror!("no authenticated query receipt").into())
    }
    fn credential(&self, _request: &[u8]) -> ZResult<Vec<u8>> {
        Err(zenoh_result::zerror!("channel credential issuer unavailable").into())
    }
}

/// Shared exact-key capacity check; never authenticates a network operation.
pub(crate) fn resource_capacity(gate: &dyn RouteGate, key: &str) -> QueryCapacity {
    if key.len() > KEY_BYTES
        || key.split('/').count() > 64
        || keyexpr::new(key).is_err()
        || key.contains('*')
    {
        return QueryCapacity::Business;
    }
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| gate.resource_capacity(key)))
        .unwrap_or(QueryCapacity::Business)
}

pub(crate) fn transport_subject(transport: &TransportUnicast) -> Option<RouteSubject> {
    let auth = transport.get_auth_ids().ok()?;
    let mut names = auth.link_auth_ids().iter().map(|id| match id {
        LinkAuthId::Tls(Some(name)) => Some(name.as_str()),
        _ => None,
    });
    let first = names.next().flatten();
    let tls_common_name = first
        .filter(|name| names.all(|next| next == Some(*name)))
        .map(str::to_owned);
    Some(RouteSubject {
        public_key_der: auth.public_key_der().map(<[u8]>::to_vec),
        tls_common_name,
        role: transport.get_whatami().ok()?,
    })
}

/// Face-owned capacity also requires the actual peer's declaration permission.
/// Metadata Interests alone cannot opt into the reserve. Wire authorization is
/// still performed independently by the interceptors.
pub(crate) fn declaration_capacity(
    gate: &dyn RouteGate,
    face: &crate::net::routing::dispatcher::face::FaceState,
    key: &str,
    action: RouteAction,
    flow: RouteFlow,
) -> QueryCapacity {
    if resource_capacity(gate, key) != QueryCapacity::Control {
        return QueryCapacity::Business;
    }
    if face.is_local {
        return QueryCapacity::Control;
    }
    let Some(mux) = face
        .primitives
        .as_any()
        .downcast_ref::<crate::net::primitives::Mux>()
    else {
        return QueryCapacity::Business;
    };
    let Some(subject) = transport_subject(&mux.handler) else {
        return QueryCapacity::Business;
    };
    if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        gate.authorize(
            &subject,
            &RouteRequest {
                action,
                flow,
                key: Some(key),
                payload: None,
            },
        )
    }))
    .unwrap_or(false)
    {
        QueryCapacity::Control
    } else {
        QueryCapacity::Business
    }
}

/// Interest permission alone only permits metadata discovery. Reserved capacity
/// additionally requires every requested declaration in the return direction.
pub(crate) fn subject_interest_capacity(
    gate: &dyn RouteGate,
    subject: &RouteSubject,
    key: &str,
    options: zenoh_protocol::network::interest::InterestOptions,
    flow: RouteFlow,
) -> QueryCapacity {
    if resource_capacity(gate, key) != QueryCapacity::Control {
        return QueryCapacity::Business;
    }
    let reverse = match flow {
        RouteFlow::Ingress => RouteFlow::Egress,
        RouteFlow::Egress => RouteFlow::Ingress,
    };
    let kinds = [
        (options.keyexprs(), RouteAction::Resource),
        (options.queryables(), RouteAction::DeclareQueryable),
        (options.subscribers(), RouteAction::DeclareSubscriber),
        (options.tokens(), RouteAction::LivelinessToken),
    ];
    let permitted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        kinds.iter().any(|(selected, _)| *selected)
            && gate.authorize(
                subject,
                &RouteRequest {
                    action: RouteAction::Interest,
                    flow,
                    key: Some(key),
                    payload: None,
                },
            )
            && kinds
                .iter()
                .filter(|(selected, _)| *selected)
                .all(|(_, action)| {
                    gate.authorize(
                        subject,
                        &RouteRequest {
                            action: *action,
                            flow: reverse,
                            key: Some(key),
                            payload: None,
                        },
                    )
                })
    }))
    .unwrap_or(false);
    if permitted {
        QueryCapacity::Control
    } else {
        QueryCapacity::Business
    }
}

pub(crate) fn interest_capacity(
    gate: &dyn RouteGate,
    face: &crate::net::routing::dispatcher::face::FaceState,
    key: &str,
    options: zenoh_protocol::network::interest::InterestOptions,
    flow: RouteFlow,
) -> QueryCapacity {
    if face.is_local {
        return if options.keyexprs()
            || options.queryables()
            || options.subscribers()
            || options.tokens()
        {
            resource_capacity(gate, key)
        } else {
            QueryCapacity::Business
        };
    }
    let Some(mux) = face
        .primitives
        .as_any()
        .downcast_ref::<crate::net::primitives::Mux>()
    else {
        return QueryCapacity::Business;
    };
    let Some(subject) = transport_subject(&mux.handler) else {
        return QueryCapacity::Business;
    };
    subject_interest_capacity(gate, &subject, key, options, flow)
}

// Accounting is a bound on retained key/ID metadata, not total Router RSS.
const STATE_BYTES: usize = 32 * 1024 * 1024;
const FLOW_BYTES: usize = 4 * 1024 * 1024;
const KEY_BYTES: usize = 2048;
const QUERY_LIMIT: usize = 1024;
const CONTROL_QUERY_LIMIT: usize = 64;
const CONTROL_STATE_BYTES: usize = 2 * 1024 * 1024;
const QUERY_TIMEOUT: Duration = Duration::from_secs(60);

struct Reservation {
    budget: Arc<AtomicUsize>,
    bytes: usize,
}
impl Reservation {
    fn new(budget: &Arc<AtomicUsize>, bytes: usize) -> Option<Self> {
        Self::for_query(budget, bytes, QueryCapacity::Business)
    }
    fn for_query(budget: &Arc<AtomicUsize>, bytes: usize, capacity: QueryCapacity) -> Option<Self> {
        let limit = if capacity == QueryCapacity::Control {
            STATE_BYTES
        } else {
            STATE_BYTES - CONTROL_STATE_BYTES
        };
        Self::with_limit(budget, bytes, limit)
    }
    fn for_declaration(
        budget: &Arc<AtomicUsize>,
        bytes: usize,
        capacity: QueryCapacity,
    ) -> Option<Self> {
        let limit = if capacity == QueryCapacity::Control {
            STATE_BYTES - 512 * 1024
        } else {
            STATE_BYTES - CONTROL_STATE_BYTES
        };
        Self::with_limit(budget, bytes, limit)
    }
    fn with_limit(budget: &Arc<AtomicUsize>, bytes: usize, limit: usize) -> Option<Self> {
        budget
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                used.checked_add(bytes).filter(|next| *next <= limit)
            })
            .ok()?;
        Some(Self {
            budget: budget.clone(),
            bytes,
        })
    }
}
impl Drop for Reservation {
    fn drop(&mut self) {
        self.budget.fetch_sub(self.bytes, Ordering::AcqRel);
    }
}
#[derive(Clone, Copy, Hash, Eq, PartialEq)]
enum IdKind {
    Resource,
    Queryable,
    Subscriber,
    Token,
    Interest,
    CurrentInterest,
}
impl IdKind {
    fn limit(self) -> usize {
        match self {
            Self::Resource => 4096,
            Self::Queryable => 2048,
            Self::Interest | Self::CurrentInterest => 128,
            _ => 1024,
        }
    }
    fn business_limit(self) -> usize {
        self.limit()
            - match self {
                Self::Resource => 128,
                Self::Queryable => 64,
                Self::Subscriber | Self::Token => 32,
                Self::Interest | Self::CurrentInterest => 16,
            }
    }
    fn capacity_limit(self, capacity: QueryCapacity) -> usize {
        if capacity == QueryCapacity::Control {
            self.limit()
        } else {
            self.business_limit()
        }
    }
}
struct Entry {
    key: String,
    _reservation: Reservation,
}
#[derive(Default)]
struct Declarations {
    ids: HashMap<(IdKind, u32), Entry>,
    // Router sourced declarations ignore wire IDs; native identity is (node, exact key).
    sourced: HashMap<(IdKind, u16, String), Reservation>,
    bytes: usize,
}
impl Declarations {
    #[cfg(test)]
    fn admit(&mut self, kind: IdKind, id: u32, key: &str, budget: &Arc<AtomicUsize>) -> bool {
        self.admit_with_capacity(kind, id, key, budget, QueryCapacity::Business)
    }
    fn admit_with_capacity(
        &mut self,
        kind: IdKind,
        id: u32,
        key: &str,
        budget: &Arc<AtomicUsize>,
        capacity: QueryCapacity,
    ) -> bool {
        if key.len() > KEY_BYTES {
            return false;
        }
        if matches!(kind, IdKind::Interest | IdKind::CurrentInterest)
            && self.ids.contains_key(&(
                if kind == IdKind::Interest {
                    IdKind::CurrentInterest
                } else {
                    IdKind::Interest
                },
                id,
            ))
        {
            return false;
        }
        if let Some(old) = self.ids.get(&(kind, id)) {
            return old.key == key;
        }
        let bytes = key.len() + 128;
        let flow_limit = if capacity == QueryCapacity::Control {
            FLOW_BYTES
        } else {
            FLOW_BYTES - 128 * 1024
        };
        if self.bytes + bytes > flow_limit
            || self
                .ids
                .keys()
                .filter(|(k, _)| {
                    *k == kind
                        || (matches!(kind, IdKind::Interest | IdKind::CurrentInterest)
                            && matches!(k, IdKind::Interest | IdKind::CurrentInterest))
                })
                .count()
                >= kind.capacity_limit(capacity)
        {
            return false;
        }
        let Some(reservation) = Reservation::for_declaration(budget, bytes, capacity) else {
            return false;
        };
        self.ids.insert(
            (kind, id),
            Entry {
                key: key.to_owned(),
                _reservation: reservation,
            },
        );
        self.bytes += bytes;
        true
    }
    #[cfg(test)]
    fn admit_sourced(
        &mut self,
        kind: IdKind,
        node: u16,
        key: &str,
        budget: &Arc<AtomicUsize>,
    ) -> bool {
        self.admit_sourced_with_capacity(kind, node, key, budget, QueryCapacity::Business)
    }
    fn admit_sourced_with_capacity(
        &mut self,
        kind: IdKind,
        node: u16,
        key: &str,
        budget: &Arc<AtomicUsize>,
        capacity: QueryCapacity,
    ) -> bool {
        if key.len() > KEY_BYTES {
            return false;
        }
        let identity = (kind, node, key.to_owned());
        if self.sourced.contains_key(&identity) {
            return true;
        }
        let bytes = key.len() + 128;
        let flow_limit = if capacity == QueryCapacity::Control {
            FLOW_BYTES
        } else {
            FLOW_BYTES - 128 * 1024
        };
        if self.bytes + bytes > flow_limit
            || self.sourced.keys().filter(|(k, _, _)| *k == kind).count()
                >= kind.capacity_limit(capacity)
        {
            return false;
        }
        let Some(reservation) = Reservation::for_declaration(budget, bytes, capacity) else {
            return false;
        };
        self.sourced.insert(identity, reservation);
        self.bytes += bytes;
        true
    }
    fn remove_sourced(&mut self, kind: IdKind, node: u16, key: &str) {
        if let Some(reservation) = self.sourced.remove(&(kind, node, key.to_owned())) {
            self.bytes -= reservation.bytes;
        }
    }
    fn remove(&mut self, kind: IdKind, id: u32) {
        if let Some(entry) = self.ids.remove(&(kind, id)) {
            self.bytes -= entry._reservation.bytes;
        }
    }
}
struct Claim {
    owner: Weak<FaceResources>,
    id: u32,
    _reservation: Reservation,
}
type Claims = Arc<Mutex<HashMap<String, Claim>>>;
pub(crate) struct GateFactory {
    gate: Arc<dyn RouteGate>,
    claims: Claims,
    budget: Arc<AtomicUsize>,
    tx_budget: Arc<tx_queue::TxBudget>,
    // Use native transport identity, not a remotely claimed ZID. Retain only weak Owners.
    faces: Mutex<Vec<(TransportUnicast, Weak<FaceResources>)>>,
}
impl GateFactory {
    pub(crate) fn new(gate: Arc<dyn RouteGate>) -> Self {
        Self {
            gate,
            claims: Arc::default(),
            budget: Arc::default(),
            tx_budget: Arc::default(),
            faces: Mutex::default(),
        }
    }
    fn resources(&self, transport: &TransportUnicast) -> Option<Arc<FaceResources>> {
        let mut faces = self.faces.lock().ok()?;
        faces.retain(|(_, owner)| owner.strong_count() > 0);
        if let Some(owner) = faces
            .iter()
            .find(|(t, _)| t == transport)
            .and_then(|(_, o)| o.upgrade())
        {
            return Some(owner);
        }
        if faces.len() >= 1024 {
            return None;
        }
        let owner = Arc::new(FaceResources::default());
        faces.push((transport.clone(), Arc::downgrade(&owner)));
        Some(owner)
    }
}
struct Pending {
    capacity: QueryCapacity,
    key: String,
    until: Instant,
    _reservation: Reservation,
}
#[derive(Default)]
struct Correlations {
    incoming: HashMap<u32, Pending>,
    outgoing: HashMap<u32, Pending>,
}
#[derive(Default)]
struct FaceResources {
    tx: tx_queue::TxQueue,
    pending: Mutex<Correlations>,
    incoming: Mutex<Declarations>,
    outgoing: Mutex<Declarations>,
}
struct GateInterceptor {
    gate: Arc<dyn RouteGate>,
    transport: Option<TransportUnicast>,
    flow: RouteFlow,
    claims: Claims,
    owner: Arc<FaceResources>,
    budget: Arc<AtomicUsize>,
    tx_budget: Arc<tx_queue::TxBudget>,
}
impl GateInterceptor {
    fn ids(&self) -> &Mutex<Declarations> {
        match self.flow {
            RouteFlow::Ingress => &self.owner.incoming,
            RouteFlow::Egress => &self.owner.outgoing,
        }
    }
    // Called only after declaration authorization; Interests always remain business.
    fn id_capacity(&self, kind: IdKind, key: &str) -> QueryCapacity {
        if matches!(kind, IdKind::Interest | IdKind::CurrentInterest) {
            QueryCapacity::Business
        } else {
            resource_capacity(self.gate.as_ref(), key)
        }
    }
    fn admit_id(&self, kind: IdKind, id: u32, key: &str) -> bool {
        self.ids().lock().is_ok_and(|mut ids| {
            ids.admit_with_capacity(kind, id, key, &self.budget, self.id_capacity(kind, key))
        })
    }
    fn remove_id(&self, kind: IdKind, id: u32) {
        if let Ok(mut ids) = self.ids().lock() {
            ids.remove(kind, id);
        }
    }

    fn subject(&self) -> Option<RouteSubject> {
        let transport = self.transport.as_ref()?;
        transport_subject(transport)
    }
    fn allowed(&self, subject: &RouteSubject, action: RouteAction, key: Option<&str>) -> bool {
        self.allowed_payload(subject, action, key, None)
    }
    fn allowed_payload(
        &self,
        subject: &RouteSubject,
        action: RouteAction,
        key: Option<&str>,
        payload: Option<&[u8]>,
    ) -> bool {
        if key.is_some_and(|k| k.len() > 2048 || k.split('/').count() > 64) {
            return false;
        }
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.gate.authorize(
                subject,
                &RouteRequest {
                    action,
                    flow: self.flow,
                    key,
                    payload,
                },
            )
        }))
        .unwrap_or(false)
    }
}
impl InterceptorTrait for GateInterceptor {
    fn tx_queue(&self) -> Option<(&tx_queue::TxQueue, &Arc<tx_queue::TxBudget>, &dyn RouteGate)> {
        (self.flow == RouteFlow::Egress).then_some((
            &self.owner.tx,
            &self.tx_budget,
            self.gate.as_ref(),
        ))
    }
    fn encoded_message_limit(&self) -> Option<usize> {
        Some(ENCODED_MESSAGE_BYTES)
    }

    fn compute_keyexpr_cache(&self, _: &keyexpr) -> Option<Box<dyn Any + Send + Sync>> {
        None
    }
    fn intercept(&self, msg: &mut NetworkMessageMut, ctx: &mut dyn InterceptorContext) -> bool {
        // Both directions and all families, before authorization, coalescing,
        // ID mutation or forwarding. Counting neither copies nor retains data.
        if !bound_encoded_message(msg, ENCODED_MESSAGE_BYTES) {
            return false;
        }
        let Some(subject) = self.subject() else {
            return false;
        };
        let key = ctx.full_expr(msg).map(str::to_owned);
        match &mut msg.body {
            NetworkBodyMut::Request(request) => {
                let Some(key) = key else {
                    return false;
                };
                // Limit before coalescing a fragmented network buffer.
                if request.payload_size() > 20 * 1024 * 1024 + 32 * 1024 {
                    return false;
                }
                let zenoh_protocol::zenoh::RequestBody::Query(query) = &mut request.payload;
                let body = query
                    .ext_body
                    .as_ref()
                    .map(|body| crate::bytes::ZBytes::from(body.payload.clone()));
                let bytes = body.as_ref().map(|body| body.to_bytes());
                #[cfg(not(feature = "zenss-router-origin"))]
                if !self.allowed_payload(&subject, RouteAction::Query, Some(&key), bytes.as_deref())
                {
                    return false;
                }
                #[cfg(feature = "zenss-router-origin")]
                {
                    if key.len() > 2048
                        || key.split('/').count() > 64
                        || query
                            .ext_attachment
                            .as_ref()
                            .is_some_and(|a| a.buffer.len() > 8192)
                    {
                        return false;
                    }
                    let attachment = query
                        .ext_attachment
                        .as_ref()
                        .map(|a| crate::bytes::ZBytes::from(a.buffer.clone()));
                    let attachment = attachment.as_ref().map(|a| a.to_bytes());
                    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        self.gate.query_origin(
                            &subject,
                            &RouteRequest {
                                action: RouteAction::Query,
                                flow: self.flow,
                                key: Some(&key),
                                payload: bytes.as_deref(),
                            },
                            attachment.as_deref(),
                        )
                    }));
                    let Ok(Ok(origin)) = result else {
                        return false;
                    };
                    if origin.as_ref().is_some_and(|a| a.len() > 8192) {
                        return false;
                    }
                    query.ext_attachment =
                        origin.map(|buffer| zenoh_protocol::zenoh::query::ext::AttachmentType {
                            buffer: buffer.into(),
                        });
                }
                let timeout = request
                    .ext_timeout
                    .unwrap_or(Duration::from_secs(10))
                    .min(QUERY_TIMEOUT);
                request.ext_timeout = Some(timeout);
                // Origin and timeout may change the encoding after initial preflight.
                // Measure again before the Query ID and its reservation are committed.
                if encoded_message_len(
                    &NetworkMessageMut {
                        body: NetworkBodyMut::Request(request),
                        reliability: msg.reliability,
                    },
                    ENCODED_MESSAGE_BYTES,
                )
                .is_none()
                {
                    return false;
                }
                let capacity = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    self.gate.query_capacity(
                        &RouteRequest {
                            action: RouteAction::Query,
                            flow: self.flow,
                            key: Some(&key),
                            payload: bytes.as_deref(),
                        },
                        QueryCapacitySource::Admitted,
                    )
                }))
                .unwrap_or(QueryCapacity::Business);
                let Ok(mut all) = self.owner.pending.lock() else {
                    return false;
                };
                let map = match self.flow {
                    RouteFlow::Ingress => &mut all.incoming,
                    RouteFlow::Egress => &mut all.outgoing,
                };
                let now = Instant::now();
                map.retain(|_, p| p.until > now);
                // Duplicate IDs cannot overwrite the request to which a Reply is bound.
                let limit = if capacity == QueryCapacity::Control {
                    CONTROL_QUERY_LIMIT
                } else {
                    QUERY_LIMIT
                };
                if map.values().filter(|p| p.capacity == capacity).count() >= limit
                    || map.contains_key(&request.id)
                {
                    return false;
                }
                let Some(reservation) =
                    Reservation::for_query(&self.budget, key.len() + 128, capacity)
                else {
                    return false;
                };
                map.insert(
                    request.id,
                    Pending {
                        capacity,
                        key,
                        until: now + timeout,
                        _reservation: reservation,
                    },
                );
                if self.flow == RouteFlow::Egress {
                    ctx.set_tx_capacity(capacity);
                }
                true
            }
            NetworkBodyMut::Response(response) => {
                let Ok(all) = self.owner.pending.lock() else {
                    return false;
                };
                let map = match self.flow {
                    RouteFlow::Ingress => &all.outgoing,
                    RouteFlow::Egress => &all.incoming,
                };
                let Some(p) = map.get(&response.rid).filter(|p| p.until > Instant::now()) else {
                    return false;
                };
                // Error replies have no result key. Data replies must match the exact request.
                if !matches!(response.payload, ResponseBody::Err(_))
                    && key.as_deref() != Some(p.key.as_str())
                {
                    return false;
                }
                let allowed = self.allowed(&subject, RouteAction::Reply, Some(&p.key));
                if allowed && self.flow == RouteFlow::Egress {
                    ctx.set_tx_capacity(p.capacity);
                }
                allowed
            }
            NetworkBodyMut::ResponseFinal(final_) => {
                let Ok(mut all) = self.owner.pending.lock() else {
                    return false;
                };
                let map = match self.flow {
                    RouteFlow::Ingress => &mut all.outgoing,
                    RouteFlow::Egress => &mut all.incoming,
                };
                map.remove(&final_.rid).is_some_and(|p| {
                    let allowed = p.until > Instant::now()
                        && self.allowed(&subject, RouteAction::Reply, Some(&p.key));
                    if allowed && self.flow == RouteFlow::Egress {
                        ctx.set_tx_capacity(p.capacity);
                    }
                    allowed
                })
            }
            NetworkBodyMut::Push(push) => self.allowed(
                &subject,
                match push.payload {
                    PushBody::Put(_) => RouteAction::Put,
                    PushBody::Del(_) => RouteAction::Delete,
                },
                key.as_deref(),
            ),
            NetworkBodyMut::Declare(declare) => {
                let kind_id = match &declare.body {
                    DeclareBody::DeclareQueryable(d) => Some((IdKind::Queryable, d.id)),
                    DeclareBody::DeclareSubscriber(d) => Some((IdKind::Subscriber, d.id)),
                    DeclareBody::DeclareToken(d) => Some((IdKind::Token, d.id)),
                    DeclareBody::DeclareKeyExpr(d) => Some((IdKind::Resource, u32::from(d.id))),
                    _ => None,
                };
                // Snapshot id 0 is not a persistent declaration; no uniqueness claim.
                let snapshot = self.flow == RouteFlow::Egress
                    && declare.interest_id.is_some_and(|id| {
                        self.owner
                            .incoming
                            .lock()
                            .is_ok_and(|ids| ids.ids.contains_key(&(IdKind::CurrentInterest, id)))
                    })
                    && kind_id.is_some_and(|(k, id)| k != IdKind::Resource && id == 0);
                let sourced = subject.role == WhatAmI::Router;
                let node = declare.ext_nodeid.node_id;
                if !snapshot && !matches!(declare.body, DeclareBody::DeclareQueryable(_)) {
                    if let Some((kind, id)) = kind_id {
                        let Some(key) = key.as_deref() else {
                            return false;
                        };
                        let action = match kind {
                            IdKind::Queryable => RouteAction::DeclareQueryable,
                            IdKind::Subscriber => RouteAction::DeclareSubscriber,
                            IdKind::Token => RouteAction::LivelinessToken,
                            IdKind::Resource => RouteAction::Resource,
                            IdKind::Interest | IdKind::CurrentInterest => unreachable!(),
                        };
                        if !self.allowed(&subject, action, Some(key))
                            || if sourced && kind != IdKind::Resource {
                                !self.ids().lock().is_ok_and(|mut ids| {
                                    ids.admit_sourced_with_capacity(
                                        kind,
                                        node,
                                        key,
                                        &self.budget,
                                        self.id_capacity(kind, key),
                                    )
                                })
                            } else {
                                !self.admit_id(kind, id, key)
                            }
                        {
                            return false;
                        }
                    }
                }
                match &declare.body {
                    DeclareBody::DeclareQueryable(declaration) => {
                        if !self.allowed(&subject, RouteAction::DeclareQueryable, key.as_deref()) {
                            return false;
                        }
                        if self.flow == RouteFlow::Egress {
                            ctx.set_tx_capacity(
                                key.as_deref()
                                    .map(|key| resource_capacity(self.gate.as_ref(), key))
                                    .unwrap_or(QueryCapacity::Business),
                            );
                        }
                        if snapshot {
                            return true;
                        }
                        if sourced {
                            return key.as_deref().is_some_and(|key| {
                                self.ids().lock().is_ok_and(|mut ids| {
                                    ids.admit_sourced_with_capacity(
                                        IdKind::Queryable,
                                        node,
                                        key,
                                        &self.budget,
                                        self.id_capacity(IdKind::Queryable, key),
                                    )
                                })
                            });
                        }
                        if self.flow == RouteFlow::Egress {
                            return key.as_deref().is_some_and(|key| {
                                self.admit_id(IdKind::Queryable, declaration.id, key)
                            });
                        }
                        let Some(key) = key else {
                            return false;
                        };
                        let Ok(mut claims) = self.claims.lock() else {
                            return false;
                        };
                        claims.retain(|_, claim| claim.owner.strong_count() > 0);
                        if let Some(claim) = claims.get(&key) {
                            return claim
                                .owner
                                .upgrade()
                                .is_some_and(|owner| Arc::ptr_eq(&owner, &self.owner))
                                && claim.id == declaration.id
                                && self.admit_id(IdKind::Queryable, declaration.id, &key);
                        }
                        let capacity = self.id_capacity(IdKind::Queryable, &key);
                        let claim_limit = if capacity == QueryCapacity::Control {
                            4096
                        } else {
                            4096 - 128
                        };
                        if claims.len() >= claim_limit {
                            return false;
                        }
                        let Some(reservation) =
                            Reservation::for_declaration(&self.budget, key.len() + 128, capacity)
                        else {
                            return false;
                        };
                        if !self.admit_id(IdKind::Queryable, declaration.id, &key) {
                            return false;
                        }
                        claims.insert(
                            key,
                            Claim {
                                owner: Arc::downgrade(&self.owner),
                                id: declaration.id,
                                _reservation: reservation,
                            },
                        );
                        true
                    }
                    DeclareBody::DeclareSubscriber(_) => {
                        self.allowed(&subject, RouteAction::DeclareSubscriber, key.as_deref())
                    }
                    DeclareBody::DeclareToken(_) => {
                        self.allowed(&subject, RouteAction::LivelinessToken, key.as_deref())
                    }
                    // Authorization and no-remap admission have already succeeded above.
                    DeclareBody::DeclareKeyExpr(_) => true,
                    DeclareBody::UndeclareKeyExpr(declaration) => {
                        self.remove_id(IdKind::Resource, u32::from(declaration.id));
                        true
                    }
                    DeclareBody::UndeclareQueryable(declaration) => {
                        if sourced {
                            if let Some(key) = key.as_deref() {
                                if let Ok(mut ids) = self.ids().lock() {
                                    ids.remove_sourced(IdKind::Queryable, node, key);
                                }
                            }
                            return true;
                        }
                        self.remove_id(IdKind::Queryable, declaration.id);
                        if self.flow == RouteFlow::Ingress {
                            if let Ok(mut claims) = self.claims.lock() {
                                claims.retain(|_, claim| {
                                    !(claim.id == declaration.id
                                        && claim
                                            .owner
                                            .upgrade()
                                            .is_some_and(|owner| Arc::ptr_eq(&owner, &self.owner)))
                                });
                            }
                        }
                        true
                    }
                    // Cleanup changes only this face's own IDs and never adds authority.
                    DeclareBody::UndeclareSubscriber(d) => {
                        if sourced {
                            if let Some(key) = key.as_deref() {
                                if let Ok(mut ids) = self.ids().lock() {
                                    ids.remove_sourced(IdKind::Subscriber, node, key);
                                }
                            }
                            return true;
                        }
                        self.remove_id(IdKind::Subscriber, d.id);
                        true
                    }
                    DeclareBody::UndeclareToken(d) => {
                        if sourced {
                            if let Some(key) = key.as_deref() {
                                if let Ok(mut ids) = self.ids().lock() {
                                    ids.remove_sourced(IdKind::Token, node, key);
                                }
                            }
                            return true;
                        }
                        self.remove_id(IdKind::Token, d.id);
                        true
                    }
                    DeclareBody::DeclareFinal(_) => {
                        if let Some(id) = declare.interest_id {
                            let ids = match self.flow {
                                RouteFlow::Ingress => &self.owner.outgoing,
                                RouteFlow::Egress => &self.owner.incoming,
                            };
                            if let Ok(mut ids) = ids.lock() {
                                ids.remove(IdKind::CurrentInterest, id);
                            }
                        }
                        true
                    }
                }
            }
            NetworkBodyMut::Interest(interest) => {
                if matches!(interest.mode, InterestMode::Final) {
                    self.remove_id(IdKind::Interest, interest.id);
                    self.remove_id(IdKind::CurrentInterest, interest.id);
                    true
                } else {
                    self.allowed(&subject, RouteAction::Interest, key.as_deref())
                        && self.ids().lock().is_ok_and(|mut ids| {
                            ids.admit_with_capacity(
                                if interest.mode.is_future() {
                                    IdKind::Interest
                                } else {
                                    IdKind::CurrentInterest
                                },
                                interest.id,
                                key.as_deref().unwrap_or(""),
                                &self.budget,
                                subject_interest_capacity(
                                    self.gate.as_ref(),
                                    &subject,
                                    key.as_deref().unwrap_or(""),
                                    interest.options,
                                    self.flow,
                                ),
                            )
                        })
                }
            }
            NetworkBodyMut::OAM(_) => self.allowed(&subject, RouteAction::Topology, key.as_deref()),
        }
    }
}
impl InterceptorFactoryTrait for GateFactory {
    fn new_transport_unicast(
        &self,
        transport: &TransportUnicast,
    ) -> (Option<IngressInterceptor>, Option<EgressInterceptor>) {
        let resources = self.resources(transport);
        let admitted = resources.is_some();
        let owner = resources.unwrap_or_default();
        (
            Some(Box::new(GateInterceptor {
                gate: self.gate.clone(),
                transport: admitted.then(|| transport.clone()),
                flow: RouteFlow::Ingress,
                claims: self.claims.clone(),
                owner: owner.clone(),
                budget: self.budget.clone(),
                tx_budget: self.tx_budget.clone(),
            })),
            Some(Box::new(GateInterceptor {
                gate: self.gate.clone(),
                transport: admitted.then(|| transport.clone()),
                flow: RouteFlow::Egress,
                claims: self.claims.clone(),
                owner,
                budget: self.budget.clone(),
                tx_budget: self.tx_budget.clone(),
            })),
        )
    }
    fn new_transport_multicast(&self, _: &TransportMulticast) -> Option<EgressInterceptor> {
        Some(Box::new(GateInterceptor {
            gate: self.gate.clone(),
            transport: None,
            flow: RouteFlow::Egress,
            claims: self.claims.clone(),
            owner: Arc::default(),
            budget: self.budget.clone(),
            tx_budget: self.tx_budget.clone(),
        }))
    }
    fn new_peer_multicast(&self, _: &TransportMulticast) -> Option<IngressInterceptor> {
        Some(Box::new(GateInterceptor {
            gate: self.gate.clone(),
            transport: None,
            flow: RouteFlow::Ingress,
            claims: self.claims.clone(),
            owner: Arc::default(),
            budget: self.budget.clone(),
            tx_budget: self.tx_budget.clone(),
        }))
    }
}

#[cfg(test)]
mod tests;
