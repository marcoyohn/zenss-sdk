//
// Copyright (c) 2024 ZettaScale Technology
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0, or the Apache License, Version 2.0
// which is available at https://www.apache.org/licenses/LICENSE-2.0.
//
// SPDX-License-Identifier: EPL-2.0 OR Apache-2.0
//
// Contributors:
//   ZettaScale Zenoh Team, <zenoh@zettascale.tech>
//

use std::{
    collections::{HashMap, HashSet},
    fmt::{self, Debug},
    sync::{Arc, Weak},
    time::Duration,
};

use async_trait::async_trait;
use tokio_util::sync::CancellationToken;
use zenoh_protocol::{
    core::Region,
    network::{
        declare::{self},
        interest::{InterestId, InterestMode, InterestOptions},
        Declare, DeclareBody, DeclareFinal, Interest,
    },
};
use zenoh_sync::get_mut_unchecked;
use zenoh_util::Timed;

use super::{face::FaceState, tables::TablesLock};
use crate::net::routing::{
    dispatcher::{face::Face, tables::Tables},
    gateway::{register_expr_interest, NodeId, Resource},
    hat::{DispatcherContext, Remote, RouteCurrentDeclareResult, RouteInterestResult, SendDeclare},
    RoutingContext,
};

// ZenSS: actual retained Interest records and cleanup futures, not ingress IDs.
#[cfg(feature = "zenss-route-gate")]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct NativeInterestUsage {
    pub(crate) future: usize,
    pub(crate) pending: usize,
    pub(crate) keys: usize,
    pub(crate) initial: usize,
}
#[cfg(feature = "zenss-route-gate")]
impl NativeInterestUsage {
    fn add(self, other: Self) -> Option<Self> {
        Some(Self {
            future: self.future.checked_add(other.future)?,
            pending: self.pending.checked_add(other.pending)?,
            keys: self.keys.checked_add(other.keys)?,
            initial: self.initial.checked_add(other.initial)?,
        })
    }
    fn subtract(&mut self, other: Self) {
        self.future -= other.future;
        self.pending -= other.pending;
        self.keys -= other.keys;
        self.initial -= other.initial;
    }
    fn bytes(self) -> Option<usize> {
        self.future
            .checked_mul(128)?
            .checked_add(self.pending.checked_mul(512)?)?
            .checked_add(self.keys.checked_mul(64)?)
    }
}
#[cfg(feature = "zenss-route-gate")]
#[derive(Clone, Copy)]
struct NativeInterestLimits {
    counts: NativeInterestUsage,
    bytes: usize,
}
#[cfg(feature = "zenss-route-gate")]
impl NativeInterestLimits {
    fn business(self, reserve: Self) -> Self {
        Self {
            counts: NativeInterestUsage {
                future: self.counts.future - reserve.counts.future,
                pending: self.counts.pending - reserve.counts.pending,
                keys: self.counts.keys - reserve.counts.keys,
                initial: self.counts.initial - reserve.counts.initial,
            },
            bytes: self.bytes - reserve.bytes,
        }
    }
    fn admits(self, next: NativeInterestUsage, delta: NativeInterestUsage) -> bool {
        (delta.future == 0 || next.future <= self.counts.future)
            && (delta.pending == 0 || next.pending <= self.counts.pending)
            && (delta.keys == 0 || next.keys <= self.counts.keys)
            && (delta.initial == 0 || next.initial <= self.counts.initial)
            && delta
                .bytes()
                .is_some_and(|b| b == 0 || next.bytes().is_some_and(|n| n <= self.bytes))
    }
    fn fits(self, usage: NativeInterestUsage) -> bool {
        usage.future <= self.counts.future
            && usage.pending <= self.counts.pending
            && usage.keys <= self.counts.keys
            && usage.initial <= self.counts.initial
            && usage.bytes().is_some_and(|b| b <= self.bytes)
    }
}
#[cfg(feature = "zenss-route-gate")]
#[derive(Default)]
struct NativeInterestLedger {
    enabled: bool,
    total: NativeInterestUsage,
    faces: HashMap<super::face::FaceId, NativeInterestUsage>,
}
#[cfg(feature = "zenss-route-gate")]
pub(crate) struct NativeInterestBudget {
    ledger: std::sync::Mutex<NativeInterestLedger>,
    global: NativeInterestLimits,
    face: NativeInterestLimits,
    reserved_global: NativeInterestLimits,
    reserved_face: NativeInterestLimits,
    gate: std::sync::OnceLock<Arc<dyn crate::net::routing::interceptor::route_gate::RouteGate>>,
}
#[cfg(feature = "zenss-route-gate")]
impl Default for NativeInterestBudget {
    fn default() -> Self {
        Self {
            ledger: Default::default(),
            global: NativeInterestLimits {
                counts: NativeInterestUsage {
                    future: 8192,
                    pending: 1024,
                    keys: 4096,
                    initial: 64,
                },
                bytes: 1024 * 1024,
            },
            face: NativeInterestLimits {
                counts: NativeInterestUsage {
                    future: 512,
                    pending: 128,
                    keys: 256,
                    initial: 1,
                },
                bytes: 128 * 1024,
            },
            reserved_global: NativeInterestLimits {
                counts: NativeInterestUsage {
                    future: 256,
                    pending: 64,
                    keys: 128,
                    initial: 0,
                },
                bytes: 64 * 1024,
            },
            reserved_face: NativeInterestLimits {
                counts: NativeInterestUsage {
                    future: 16,
                    pending: 8,
                    keys: 8,
                    initial: 0,
                },
                bytes: 8 * 1024,
            },
            gate: Default::default(),
        }
    }
}
#[cfg(feature = "zenss-route-gate")]
pub(crate) struct NativeInterestReservation {
    budget: Arc<NativeInterestBudget>,
    face: super::face::FaceId,
    usage: NativeInterestUsage,
}
#[cfg(feature = "zenss-route-gate")]
impl fmt::Debug for NativeInterestReservation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeInterestReservation")
            .field("face", &self.face)
            .field("usage", &self.usage)
            .finish()
    }
}
#[cfg(feature = "zenss-route-gate")]
impl NativeInterestBudget {
    pub(crate) fn reserve(
        self: &Arc<Self>,
        face: super::face::FaceId,
        usage: NativeInterestUsage,
    ) -> Option<NativeInterestReservation> {
        self.reserve_for(
            face,
            usage,
            crate::net::routing::interceptor::route_gate::QueryCapacity::Business,
        )
    }
    pub(crate) fn reserve_for(
        self: &Arc<Self>,
        face: super::face::FaceId,
        usage: NativeInterestUsage,
        capacity: crate::net::routing::interceptor::route_gate::QueryCapacity,
    ) -> Option<NativeInterestReservation> {
        let mut ledger = self.ledger.lock().ok()?;
        let global = ledger.total.add(usage)?;
        let local = ledger
            .faces
            .get(&face)
            .copied()
            .unwrap_or_default()
            .add(usage)?;
        let (global_limit, face_limit) =
            if capacity == crate::net::routing::interceptor::route_gate::QueryCapacity::Control {
                (self.global, self.face)
            } else {
                (
                    self.global.business(self.reserved_global),
                    self.face.business(self.reserved_face),
                )
            };
        if ledger.enabled
            && (!self.global.fits(global)
                || !self.face.fits(local)
                || !global_limit.admits(global, usage)
                || !face_limit.admits(local, usage))
        {
            tracing::debug!("native Interest state capacity refused");
            return None;
        }
        ledger.total = global;
        if usage != NativeInterestUsage::default() {
            ledger.faces.insert(face, local);
        }
        Some(NativeInterestReservation {
            budget: self.clone(),
            face,
            usage,
        })
    }
    pub(crate) fn bind_gate(
        &self,
        gate: Arc<dyn crate::net::routing::interceptor::route_gate::RouteGate>,
    ) {
        assert!(
            self.gate.set(gate).is_ok(),
            "native Interest gate installs once"
        );
    }
    pub(crate) fn can_enable(&self) -> bool {
        self.ledger.lock().is_ok_and(|ledger| {
            self.global
                .business(self.reserved_global)
                .fits(ledger.total)
                && ledger
                    .faces
                    .values()
                    .all(|u| self.face.business(self.reserved_face).fits(*u))
        })
    }
    pub(crate) fn enable(&self) {
        let mut ledger = self.ledger.lock().unwrap_or_else(|e| e.into_inner());
        // Installation holds control/Tables locks: only releases can race preflight.
        assert!(
            self.global
                .business(self.reserved_global)
                .fits(ledger.total)
                && ledger
                    .faces
                    .values()
                    .all(|u| self.face.business(self.reserved_face).fits(*u))
        );
        ledger.faces.shrink_to_fit();
        ledger.enabled = true;
    }
    #[cfg(test)]
    pub(crate) fn usage(&self) -> NativeInterestUsage {
        self.ledger.lock().unwrap().total
    }
}
#[cfg(feature = "zenss-route-gate")]
impl NativeInterestReservation {
    fn split(&mut self, usage: NativeInterestUsage) -> Self {
        self.usage.subtract(usage);
        Self {
            budget: self.budget.clone(),
            face: self.face,
            usage,
        }
    }
}
#[cfg(feature = "zenss-route-gate")]
impl Drop for NativeInterestReservation {
    fn drop(&mut self) {
        if self.usage == NativeInterestUsage::default() {
            return;
        }
        let mut ledger = self.budget.ledger.lock().unwrap_or_else(|e| e.into_inner());
        ledger.total.subtract(self.usage);
        let local = ledger
            .faces
            .get_mut(&self.face)
            .expect("owned Interest face usage");
        local.subtract(self.usage);
        if *local == NativeInterestUsage::default() {
            ledger.faces.remove(&self.face);
        }
    }
}

pub(crate) struct PreparedInterest {
    #[cfg(feature = "zenss-route-gate")]
    future: Option<NativeInterestReservation>,
    #[cfg(feature = "zenss-route-gate")]
    pub(crate) pending: Option<Arc<NativeInterestReservation>>,
}
impl PreparedInterest {
    pub(crate) fn state(
        self,
        face: super::face::FaceId,
        options: InterestOptions,
        res: Option<Arc<Resource>>,
        finalized: bool,
    ) -> super::face::InterestState {
        super::face::InterestState::new(
            face,
            options,
            res,
            finalized,
            #[cfg(feature = "zenss-route-gate")]
            self.future,
        )
    }
}

pub(crate) struct KeyInterestState {
    pub(crate) res: Option<Arc<Resource>>,
    #[cfg(feature = "zenss-route-gate")]
    _native_reservation: Option<NativeInterestReservation>,
}
impl std::ops::Deref for KeyInterestState {
    type Target = Option<Arc<Resource>>;
    fn deref(&self) -> &Self::Target {
        &self.res
    }
}
impl KeyInterestState {
    pub(crate) fn reserve(
        face: &FaceState,
        _expr: Option<&zenoh_protocol::core::WireExpr<'_>>,
        _options: InterestOptions,
    ) -> Option<Self> {
        Some(Self {
            res: None,
            #[cfg(feature = "zenss-route-gate")]
            _native_reservation: Some(face.native_interest_budget.reserve_for(
                face.id,
                NativeInterestUsage {
                    keys: 1,
                    ..Default::default()
                },
                face.native_interest_capacity(
                    face.mapped_interest_key(_expr).as_deref(),
                    _options,
                    true,
                ),
            )?),
        })
    }
}

impl FaceState {
    /// Resolve without mutating mappings/tree or allocating unbounded wire strings.
    #[cfg(feature = "zenss-route-gate")]
    pub(crate) fn mapped_interest_key(
        &self,
        expr: Option<&zenoh_protocol::core::WireExpr<'_>>,
    ) -> Option<String> {
        let expr = expr?;
        let prefix = if expr.scope == 0 {
            ""
        } else {
            self.get_mapping(&expr.scope, expr.mapping)?.expr()
        };
        if prefix.len().checked_add(expr.suffix.len())? > 2048 {
            return None;
        }
        Some(format!("{}{}", prefix, expr.suffix))
    }
    #[cfg(feature = "zenss-route-gate")]
    pub(crate) fn native_interest_capacity(
        &self,
        key: Option<&str>,
        options: InterestOptions,
        ingress: bool,
    ) -> crate::net::routing::interceptor::route_gate::QueryCapacity {
        use crate::net::routing::interceptor::route_gate::{
            interest_capacity, QueryCapacity, RouteFlow,
        };
        match (self.native_interest_budget.gate.get(), key) {
            (Some(gate), Some(key)) => interest_capacity(
                gate.as_ref(),
                self,
                key,
                options,
                if ingress {
                    RouteFlow::Ingress
                } else {
                    RouteFlow::Egress
                },
            ),
            _ => QueryCapacity::Business,
        }
    }
    pub(crate) fn prepare_interest_for(
        &self,
        mode: InterestMode,
        initial: bool,
        _res: Option<&Arc<Resource>>,
        _options: InterestOptions,
    ) -> Option<PreparedInterest> {
        let capacity = {
            #[cfg(feature = "zenss-route-gate")]
            {
                if initial {
                    crate::net::routing::interceptor::route_gate::QueryCapacity::Business
                } else {
                    self.native_interest_capacity(_res.map(|r| r.expr()), _options, false)
                }
            }
            #[cfg(not(feature = "zenss-route-gate"))]
            {
                super::local_resources::NativeDeclarationCapacity::Business
            }
        };
        self.prepare_interest_with_capacity(mode, initial, capacity)
    }
    pub(crate) fn prepare_interest(
        &self,
        _mode: InterestMode,
        _initial: bool,
    ) -> Option<PreparedInterest> {
        self.prepare_interest_with_capacity(
            _mode,
            _initial,
            super::local_resources::NativeDeclarationCapacity::Business,
        )
    }
    fn prepare_interest_with_capacity(
        &self,
        _mode: InterestMode,
        _initial: bool,
        _capacity: super::local_resources::NativeDeclarationCapacity,
    ) -> Option<PreparedInterest> {
        #[cfg(feature = "zenss-route-gate")]
        {
            let future = usize::from(_mode.is_future() && !_initial);
            let initial = usize::from(_initial);
            let pending = usize::from(_mode.is_current() && !_initial);
            let mut all = self.native_interest_budget.reserve_for(
                self.id,
                NativeInterestUsage {
                    future,
                    pending,
                    initial,
                    keys: 0,
                },
                _capacity,
            )?;
            let future = (future + initial > 0).then(|| {
                all.split(NativeInterestUsage {
                    future,
                    initial,
                    ..Default::default()
                })
            });
            let pending = (pending > 0).then(|| {
                Arc::new(all.split(NativeInterestUsage {
                    pending,
                    ..Default::default()
                }))
            });
            Some(PreparedInterest { future, pending })
        }
        #[cfg(not(feature = "zenss-route-gate"))]
        Some(PreparedInterest {})
    }
    pub(crate) fn new_interest_id(
        &self,
        _fallback: &std::sync::atomic::AtomicU32,
    ) -> Option<InterestId> {
        #[cfg(feature = "zenss-route-gate")]
        {
            self.next_native_interest_id
                .fetch_update(
                    std::sync::atomic::Ordering::SeqCst,
                    std::sync::atomic::Ordering::SeqCst,
                    |id| id.checked_add(1),
                )
                .ok()
        }
        #[cfg(not(feature = "zenss-route-gate"))]
        {
            Some(_fallback.fetch_add(1, std::sync::atomic::Ordering::SeqCst))
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct CurrentInterest {
    pub(crate) src: Remote,
    pub(crate) src_region: Region,
    pub(crate) src_interest_id: InterestId,
    pub(crate) mode: InterestMode,
}

pub(crate) struct PendingCurrentInterest {
    pub(crate) interest: Arc<CurrentInterest>,
    pub(crate) cancellation_token: CancellationToken,
    pub(crate) rejection_token: CancellationToken,
    #[cfg(feature = "zenss-route-gate")]
    pub(crate) native_reservation: Option<Arc<NativeInterestReservation>>,
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub(crate) struct RemoteInterest {
    pub(crate) res: Option<Arc<Resource>>,
    pub(crate) options: InterestOptions,
    pub(crate) mode: InterestMode,
}

impl fmt::Debug for RemoteInterest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RemoteInterest")
            .field("res", &self.res.as_ref().map(|res| res.expr()))
            .field("opts", &self.options)
            .field("mode", &self.mode)
            .finish()
    }
}

impl RemoteInterest {
    pub(crate) fn matches(&self, res: &Arc<Resource>) -> bool {
        self.res.as_ref().map(|r| r.matches(res)).unwrap_or(true)
    }
}

pub(crate) fn finalize_pending_interests(
    _tables_ref: &TablesLock,
    face: &mut Arc<FaceState>,
    send_declare: &mut SendDeclare,
) {
    for (_, interest) in get_mut_unchecked(face).pending_current_interests.drain() {
        finalize_pending_interest(interest, send_declare);
    }
}

pub(crate) fn finalize_pending_interest(
    pending_interest: PendingCurrentInterest,
    send_declare: &mut SendDeclare,
) {
    let interest = pending_interest.interest;
    pending_interest.cancellation_token.cancel();
    if let Some(interest) = Arc::into_inner(interest) {
        // FIXME(regions): this is only safe as long as router interests remain unimplemented
        let src_face = interest
            .src
            .downcast_ref_to_face()
            .expect("interest source remote should be a face");

        tracing::debug!(
            "{}:{} Propagate DeclareFinal",
            src_face,
            interest.src_interest_id
        );

        send_declare(
            &src_face.primitives,
            RoutingContext::new(Declare {
                interest_id: Some(interest.src_interest_id),
                ext_qos: declare::ext::QoSType::DECLARE,
                ext_tstamp: None,
                ext_nodeid: declare::ext::NodeIdType::DEFAULT,
                body: DeclareBody::DeclareFinal(DeclareFinal),
            }),
        );
    }
}

#[derive(Clone)]
pub(crate) struct CurrentInterestCleanup {
    tables: Arc<TablesLock>,
    face: Weak<FaceState>,
    id: InterestId,
    interests_timeout: Duration,
}

impl CurrentInterestCleanup {
    pub(crate) fn spawn_interest_clean_up_task(
        face: &Arc<FaceState>,
        tables_ref: &Arc<TablesLock>,
        id: u32,
        interests_timeout: Duration,
    ) {
        let mut cleanup = CurrentInterestCleanup {
            tables: tables_ref.clone(),
            face: Arc::downgrade(face),
            id,
            interests_timeout,
        };
        if let Some(pending_interest) = face.pending_current_interests.get(&id) {
            let cancellation_token = pending_interest.cancellation_token.clone();
            let rejection_token = pending_interest.rejection_token.clone();
            #[cfg(feature = "zenss-route-gate")]
            let native_reservation = pending_interest.native_reservation.clone();
            face.task_controller
                .spawn_with_rt(zenoh_runtime::ZRuntime::Net, async move {
                    #[cfg(feature = "zenss-route-gate")]
                    let _native_keepalive = native_reservation;
                    tokio::select! {
                        _ = tokio::time::sleep(cleanup.interests_timeout) => { cleanup.run().await }
                        _ = cancellation_token.cancelled() => {}
                        _ = rejection_token.cancelled() => { cleanup.execute(false).await }
                    }
                });
        }
    }

    async fn execute(&mut self, print_warning: bool) {
        if let Some(mut face) = self.face.upgrade() {
            let ctrl_lock = zlock!(self.tables.ctrl_lock);
            if let Some(interest) = get_mut_unchecked(&mut face)
                .pending_current_interests
                .remove(&self.id)
            {
                drop(ctrl_lock);
                if print_warning {
                    tracing::warn!(
                        "{}:{} Didn't receive DeclareFinal for interest {:?}:{}: Timeout({:#?})!",
                        face,
                        self.id,
                        interest.interest.src.downcast_ref_to_face(),
                        interest.interest.src_interest_id,
                        self.interests_timeout,
                    );
                }
                finalize_pending_interest(interest, &mut |p, m| {
                    m.with_mut(|m| {
                        p.send_declare(m);
                    })
                });
            }
        }
    }
}

#[async_trait]
impl Timed for CurrentInterestCleanup {
    async fn run(&mut self) {
        self.execute(true).await;
    }
}

impl Face {
    #[tracing::instrument(
        level = "debug", 
        skip(self, msg, send_declare),
        fields(
            id = msg.id,
            mode = ?msg.mode,
            opts = %msg.options,
            expr = msg.wire_expr.as_ref().map(|we| we.to_string())
        ),
        ret
    )]
    pub(crate) fn interest(&self, msg: &mut Interest, send_declare: &mut SendDeclare) {
        let region = self.state.region;

        if region.bound().is_north() && !self.state.whatami.is_peer() {
            tracing::error!(
                src = %self.state,
                "Ignoring interest from non-peer north-bound face (illegal)"
            );
            return;
        }

        if self.state.whatami.is_router() {
            tracing::warn!("Ignoring interest from router (unsupported)");
            return;
        }

        if msg.options.aggregate() && self.state.whatami.is_peer() {
            tracing::warn!("Ignoring aggregate interest option from peer (unsupported)");
            msg.options -= InterestOptions::AGGREGATE;
        }

        if msg.options.aggregate() && msg.options.tokens() {
            tracing::error!("Ignoring aggregate interest option for tokens (illegal)");
            msg.options -= InterestOptions::AGGREGATE;
        }

        if msg.mode == InterestMode::Current
            && (msg.options.subscribers() || msg.options.queryables() || !msg.options.tokens())
        {
            tracing::error!("Current interests may only refer to tokens (illegal)");
            return;
        }

        let msg = &*msg;

        let Interest {
            id,
            mode,
            options,
            wire_expr,
            ..
        } = msg;

        // Reserve before keyexpr registration, resource creation or forwarding.
        // The control lock serializes the reservation/commit across Tables locks.
        let mut prepared = if mode.is_future() {
            let tables = zread!(self.tables.tables);
            match tables.hats[region].prepare_remote_interest(&self.state, msg) {
                Some(prepared) => prepared,
                None => return,
            }
        } else {
            None
        };

        if options.keyexprs() && mode != &InterestMode::Current {
            if !super::resource::register_expr_interest_for(
                &self.tables,
                &mut self.state.clone(),
                *id,
                wire_expr.as_ref(),
                *options,
            ) {
                return;
            }
        }

        self.with_mapped_optional_expr(wire_expr.as_ref(), |tables, res| {
            let hats = &mut tables.hats;

            let mut ctx = DispatcherContext {
                tables_lock: &self.tables,
                tables: &mut tables.data,
                src_face: &mut self.state.clone(),
                send_declare,
            };

            let Some(src) = hats[region].new_remote(ctx.src_face, msg.ext_nodeid.node_id) else {
                return;
            };

            let route_interest_res =
                hats[Region::North].route_interest(ctx.reborrow(), msg, res.clone(), &src);

            if msg.mode.is_current() {
                if msg.options.subscribers() {
                    let other_sub_matches = hats
                        .values()
                        .filter(|hat| hat.region() != region)
                        .flat_map(|hat| {
                            hat.remote_subscribers_matching(ctx.tables, res.as_deref())
                                .into_iter()
                        })
                        .collect::<HashMap<_, _>>();

                    hats[region].send_current_subscribers(
                        ctx.reborrow(),
                        msg,
                        res.clone(),
                        other_sub_matches,
                    );
                }

                if msg.options.queryables() {
                    let other_qabl_matches = hats
                        .values()
                        .filter(|hat| hat.region() != region)
                        .flat_map(|hat| {
                            hat.remote_queryables_matching(ctx.tables, res.as_deref())
                                .into_iter()
                        })
                        .collect::<HashMap<_, _>>();
                    hats[region].send_current_queryables(
                        ctx.reborrow(),
                        msg,
                        res.clone(),
                        other_qabl_matches,
                    );
                }

                if msg.options.tokens() {
                    let other_token_matches = hats
                        .values()
                        .filter(|hat| hat.region() != region)
                        .flat_map(|hat| {
                            hat.remote_tokens_matching(ctx.tables, res.as_deref())
                                .into_iter()
                        })
                        .collect::<HashSet<_>>();
                    hats[region].send_current_tokens(
                        ctx.reborrow(),
                        msg,
                        res.clone(),
                        other_token_matches,
                    );
                }
            }

            if msg.mode.is_future() {
                hats[region].register_interest(ctx.reborrow(), msg, res, prepared.take());
            }

            if let RouteInterestResult::ResolvedCurrentInterest = route_interest_res {
                hats[region].send_declare_final(ctx.reborrow(), msg.id, &src);
            }
        });
    }

    #[tracing::instrument(
        level = "debug",
        name = "interest",
        skip(self, msg),
        fields(
            id = msg.id,
            mode = ?InterestMode::Final,
            opts = %msg.options,
            expr = msg.wire_expr.as_ref().map(|we| we.to_string())
        ),
        ret
    )]
    pub(crate) fn interest_final(&self, msg: &Interest) {
        let mut wtables = zwrite!(self.tables.tables);
        let tables = &mut *wtables;

        let mut ctx = DispatcherContext {
            tables_lock: &self.tables,
            tables: &mut tables.data,
            src_face: &mut self.state.clone(),
            send_declare: &mut |_, _| unreachable!(),
        };

        // Unregister keyexpr interest
        let key_interest = get_mut_unchecked(ctx.src_face)
            .remote_key_interests
            .remove(&msg.id);

        let hats = &mut tables.hats;
        let region = ctx.src_face.region;

        if let Some(remote_interest) = hats[region].unregister_interest(ctx.reborrow(), msg) {
            hats[Region::North].route_interest_final(ctx, msg, &remote_interest);
        }
        // Clean after hat projections relinquish their resource references, including
        // a key-only Interest with no registered hat projection.
        if let Some(mut res) = key_interest.and_then(|mut state| state.res.take()) {
            Resource::clean(&mut res);
        }
    }

    #[tracing::instrument(level = "debug", skip(self, wtables, _node_id, send_declare), ret)]
    pub(crate) fn declare_final(
        &self,
        wtables: &mut Tables,
        interest_id: InterestId,
        _node_id: NodeId,
        send_declare: &mut SendDeclare,
    ) {
        let tables = &mut *wtables;

        let mut ctx = DispatcherContext {
            tables_lock: &self.tables,
            tables: &mut tables.data,
            src_face: &mut self.state.clone(),
            send_declare,
        };

        let hats = &mut tables.hats;
        let region = ctx.src_face.region;

        if region.bound().is_south() {
            tracing::error!("Received DeclareFinal from south-bound face");
            return;
        }

        // TODO(regions): this is too conservative, the north hat should be able to decide what
        // keyexpr(s)—if not all—are affected and whether this finalization concerns subscribers
        // or queryables or borth.
        hats[region].disable_all_routes(ctx.tables);

        match hats[region].route_declare_final(ctx.reborrow(), interest_id) {
            RouteCurrentDeclareResult::Noop | RouteCurrentDeclareResult::NoBreadcrumb => {} // ¯\_(ツ)_/¯
            RouteCurrentDeclareResult::Breadcrumb { interest } => {
                debug_assert!(interest.mode.is_current());

                hats[interest.src_region].send_declare_final(
                    ctx,
                    interest.src_interest_id,
                    &interest.src,
                );
            }
        }
    }
}

#[cfg(all(test, feature = "zenss-route-gate"))]
mod native_interest_tests {
    use super::*;
    use crate::net::{
        routing::interceptor::route_gate::{RouteGate, RouteRequest, RouteSubject},
        runtime::{Runtime, RuntimeBuilder},
    };
    use std::sync::atomic::{AtomicU32, Ordering};
    struct Allow;
    impl RouteGate for Allow {
        fn authorize(&self, _: &RouteSubject, _: &RouteRequest<'_>) -> bool {
            true
        }
    }
    async fn local() -> (Runtime, crate::Session, Arc<FaceState>) {
        let config =
            crate::Config::from_json5(r#"{mode:"router",scouting:{multicast:{enabled:false}}}"#)
                .unwrap();
        let runtime = RuntimeBuilder::new(config).build().await.unwrap();
        let session = crate::session::init(runtime.clone().into()).await.unwrap();
        let face = runtime
            .router()
            .tables
            .tables
            .read()
            .unwrap()
            .data
            .faces
            .values()
            .find(|f| f.is_local)
            .unwrap()
            .clone();
        (runtime, session, face)
    }
    fn unit(future: usize, pending: usize, keys: usize, initial: usize) -> NativeInterestUsage {
        NativeInterestUsage {
            future,
            pending,
            keys,
            initial,
        }
    }
    #[test]
    fn shared_counts_and_per_face_limits_return_exact_ownership() {
        for (all, cap, per_face) in [
            (unit(1, 0, 0, 0), 7680, 496),
            (unit(0, 1, 0, 0), 960, 120),
            (unit(0, 0, 1, 0), 3968, 248),
            (unit(0, 0, 0, 1), 64, 1),
        ] {
            let budget = Arc::new(NativeInterestBudget::default());
            budget.enable();
            let mut owned = Vec::new();
            for i in 0..cap {
                owned.push(budget.reserve(i / per_face, all).unwrap());
            }
            assert!(budget.reserve(0, all).is_none());
            assert!(budget.reserve(1000, all).is_none());
            drop(owned.pop());
            let replacement = budget.reserve(1000, all).unwrap();
            drop((replacement, owned));
            assert_eq!(budget.usage(), Default::default());
            assert!(budget.ledger.lock().unwrap().faces.is_empty());
        }
    }
    #[test]
    fn weighted_metadata_and_initial_reserve_are_independent() {
        let budget = Arc::new(NativeInterestBudget::default());
        budget.enable();
        let mut owned = Vec::new();
        // 16 faces each retain 496 futures: exactly the global 1MiB weight.
        for face in 0..16 {
            owned.push(budget.reserve(face, unit(480, 0, 0, 0)).unwrap());
        }
        assert!(budget.reserve(20, unit(0, 1, 0, 0)).is_none());
        assert!(budget.reserve(20, unit(0, 0, 1, 0)).is_none());
        let initial = budget.reserve(20, unit(0, 0, 0, 1)).unwrap();
        assert!(budget.reserve(20, unit(0, 0, 0, 1)).is_none());
        drop((owned, initial));
        // Per-face weight 64KiB + 64KiB; counts still allow key records.
        let future = budget.reserve(30, unit(496, 0, 0, 0)).unwrap();
        let pending = budget.reserve(30, unit(0, 116, 0, 0)).unwrap();
        assert!(budget.reserve(30, unit(0, 0, 1, 0)).is_none());
        let another = budget.reserve(31, unit(0, 0, 1, 0)).unwrap();
        drop((future, pending, another));
        assert_eq!(budget.usage(), Default::default());
    }
    #[test]
    fn pending_split_stays_owned_until_both_record_and_future_drop() {
        let budget = Arc::new(NativeInterestBudget::default());
        budget.enable();
        let mut both = budget.reserve(0, unit(1, 1, 0, 0)).unwrap();
        let future = both.split(unit(1, 0, 0, 0));
        let record = Arc::new(both.split(unit(0, 1, 0, 0)));
        let task = record.clone();
        drop(both);
        drop(record);
        assert_eq!(budget.usage(), unit(1, 1, 0, 0));
        drop(task);
        assert_eq!(budget.usage(), unit(1, 0, 0, 0));
        drop(future);
        assert_eq!(budget.usage(), Default::default());
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn current_future_refusal_is_atomic_and_ids_never_wrap() {
        let (runtime, session, face) = local().await;
        runtime.install_route_gate(Arc::new(Allow)).unwrap();
        let budget = face.native_interest_budget.clone();
        let held = budget.reserve(face.id, unit(0, 120, 0, 0)).unwrap();
        let next = face.next_native_interest_id.load(Ordering::SeqCst);
        assert!(face
            .prepare_interest(InterestMode::CurrentFuture, false)
            .is_none());
        assert_eq!(face.next_native_interest_id.load(Ordering::SeqCst), next);
        assert_eq!(budget.usage(), unit(0, 120, 0, 0));
        assert!(face.local_interests.is_empty());
        assert!(face.pending_current_interests.is_empty());
        drop(held);
        let prepared = face
            .prepare_interest(InterestMode::CurrentFuture, false)
            .unwrap();
        assert_eq!(budget.usage(), unit(1, 1, 0, 0));
        drop(prepared);
        let fallback = AtomicU32::new(100);
        assert_eq!(face.new_interest_id(&fallback), Some(next));
        assert_eq!(face.new_interest_id(&fallback), Some(next + 1));
        assert_eq!(fallback.load(Ordering::SeqCst), 100);
        face.next_native_interest_id
            .store(u32::MAX - 1, Ordering::SeqCst);
        assert_eq!(face.new_interest_id(&fallback), Some(u32::MAX - 1));
        assert_eq!(face.new_interest_id(&fallback), None);
        assert_eq!(face.new_interest_id(&fallback), None);
        session.close().await.unwrap();
        runtime.close().await.unwrap();
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn duplicate_keyexpr_at_capacity_preserves_permit_and_failed_update() {
        let (runtime, session, mut face) = local().await;
        runtime.install_route_gate(Arc::new(Allow)).unwrap();
        let gateway = runtime.router();
        let budget = face.native_interest_budget.clone();
        {
            let _ctrl = gateway.tables.ctrl_lock.lock().unwrap();
            for id in 0..248 {
                assert!(register_expr_interest(&gateway.tables, &mut face, id, None));
            }
            assert!(!register_expr_interest(
                &gateway.tables,
                &mut face,
                248,
                Some(&"must/not/create".into())
            ));
            assert!(Resource::get_resource(
                &gateway.tables.tables.read().unwrap().data.root_res,
                "must/not/create"
            )
            .is_none());
            assert!(register_expr_interest(
                &gateway.tables,
                &mut face,
                0,
                Some(&"old/key".into())
            ));
            let old = face.remote_key_interests[&0].res.clone().unwrap();
            let invalid = zenoh_protocol::core::WireExpr {
                scope: u16::MAX,
                suffix: "bad".into(),
                mapping: zenoh_protocol::network::Mapping::Sender,
            };
            assert!(!register_expr_interest(
                &gateway.tables,
                &mut face,
                0,
                Some(&invalid)
            ));
            assert!(Arc::ptr_eq(
                face.remote_key_interests[&0].res.as_ref().unwrap(),
                &old
            ));
            assert_eq!(budget.usage().keys, 248);
            assert!(register_expr_interest(
                &gateway.tables,
                &mut face,
                0,
                Some(&"new/key".into())
            ));
            drop(old);
            assert!(register_expr_interest(&gateway.tables, &mut face, 0, None));
            assert!(Resource::get_resource(
                &gateway.tables.tables.read().unwrap().data.root_res,
                "new/key"
            )
            .is_none());
            get_mut_unchecked(&mut face).remote_key_interests.remove(&1);
            assert!(register_expr_interest(
                &gateway.tables,
                &mut face,
                248,
                None
            ));
            get_mut_unchecked(&mut face).remote_key_interests.clear();
            assert!(register_expr_interest(
                &gateway.tables,
                &mut face,
                300,
                Some(&"final/key".into())
            ));
            let dispatcher = Face {
                state: face.clone(),
                tables: gateway.tables.clone(),
            };
            dispatcher.interest_final(&Interest {
                id: 300,
                mode: InterestMode::Final,
                options: InterestOptions::ALL,
                wire_expr: None,
                ext_qos: zenoh_protocol::network::interest::ext::QoSType::INTEREST,
                ext_tstamp: None,
                ext_nodeid: zenoh_protocol::network::interest::ext::NodeIdType::DEFAULT,
            });
            assert!(Resource::get_resource(
                &gateway.tables.tables.read().unwrap().data.root_res,
                "final/key"
            )
            .is_none());
        }
        assert_eq!(budget.usage(), Default::default());
        session.close().await.unwrap();
        runtime.close().await.unwrap();
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn gate_preflights_local_records_and_still_live_cleanup_before_mutation() {
        for pending in [false, true] {
            let (runtime, session, mut face) = local().await;
            let gateway = runtime.router();
            let budget = face.native_interest_budget.clone();
            let mut active = Vec::new();
            {
                let _ctrl = gateway.tables.ctrl_lock.lock().unwrap();
                for id in 0..if pending { 121 } else { 497 } {
                    let mut p = face
                        .prepare_interest(
                            if pending {
                                InterestMode::Current
                            } else {
                                InterestMode::Future
                            },
                            false,
                        )
                        .unwrap();
                    if pending {
                        let cancellation_token = face.task_controller.get_cancellation_token();
                        let rejection_token = face.task_controller.get_cancellation_token();
                        let src = gateway.tables.tables.read().unwrap().hats[face.region]
                            .new_remote(&face, 0)
                            .unwrap();
                        let interest = Arc::new(CurrentInterest {
                            src,
                            src_region: face.region,
                            src_interest_id: id,
                            mode: InterestMode::Current,
                        });
                        get_mut_unchecked(&mut face)
                            .pending_current_interests
                            .insert(
                                id,
                                PendingCurrentInterest {
                                    interest,
                                    cancellation_token: cancellation_token.clone(),
                                    rejection_token,
                                    native_reservation: p.pending.take(),
                                },
                            );
                        CurrentInterestCleanup::spawn_interest_clean_up_task(
                            &face,
                            &gateway.tables,
                            id,
                            Duration::from_secs(5),
                        );
                        active.push(cancellation_token);
                    } else {
                        let state = p.state(face.id, InterestOptions::ALL, None, false);
                        get_mut_unchecked(&mut face)
                            .local_interests
                            .insert(id, state);
                    }
                }
            }
            assert!(runtime.install_route_gate(Arc::new(Allow)).is_err());
            {
                let tables = gateway.tables.tables.read().unwrap();
                assert!(tables.data.route_gate.is_none());
                assert!(tables.data.native_resource_budget.is_none());
                assert!(tables.data.native_aggregation_budget.is_none());
            }
            assert!(!budget.ledger.lock().unwrap().enabled);
            assert!(budget.gate.get().is_none());
            {
                let _ctrl = gateway.tables.ctrl_lock.lock().unwrap();
                get_mut_unchecked(&mut face).local_interests.clear();
                // Drop the records without cancelling: only the real futures own the permits.
                get_mut_unchecked(&mut face)
                    .pending_current_interests
                    .clear();
            }
            if pending {
                assert!(runtime.install_route_gate(Arc::new(Allow)).is_err());
            }
            for token in active {
                token.cancel();
            }
            tokio::time::timeout(Duration::from_secs(2), async {
                while budget.usage() != Default::default() {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .unwrap();
            runtime.install_route_gate(Arc::new(Allow)).unwrap();
            assert!(budget.ledger.lock().unwrap().enabled);
            session.close().await.unwrap();
            runtime.close().await.unwrap();
        }
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn actual_cleanup_permit_survives_removal_until_task_exit() {
        let (runtime, session, mut face) = local().await;
        runtime.install_route_gate(Arc::new(Allow)).unwrap();
        let gateway = runtime.router();
        let budget = face.native_interest_budget.clone();
        for scenario in ["timeout", "rejection", "final", "shutdown"] {
            let id = face.new_interest_id(&AtomicU32::new(1)).unwrap();
            let mut p = face.prepare_interest(InterestMode::Current, false).unwrap();
            let cancellation_token = face.task_controller.get_cancellation_token();
            let rejection_token = face.task_controller.get_cancellation_token();
            {
                let _ctrl = gateway.tables.ctrl_lock.lock().unwrap();
                let interest = Arc::new(CurrentInterest {
                    src: gateway.tables.tables.read().unwrap().hats[face.region]
                        .new_remote(&face, 0)
                        .unwrap(),
                    src_region: face.region,
                    src_interest_id: id,
                    mode: InterestMode::Current,
                });
                get_mut_unchecked(&mut face)
                    .pending_current_interests
                    .insert(
                        id,
                        PendingCurrentInterest {
                            interest,
                            cancellation_token: cancellation_token.clone(),
                            rejection_token: rejection_token.clone(),
                            native_reservation: p.pending.take(),
                        },
                    );
                CurrentInterestCleanup::spawn_interest_clean_up_task(
                    &face,
                    &gateway.tables,
                    id,
                    Duration::from_millis(if scenario == "timeout" { 10 } else { 1000 }),
                );
                if scenario == "rejection" {
                    rejection_token.cancel();
                }
                // Force timeout/rejection cleanup to wait for the real ctrl lock.
                if scenario == "timeout" || scenario == "rejection" {
                    tokio::time::sleep(Duration::from_millis(40)).await;
                    let record = get_mut_unchecked(&mut face)
                        .pending_current_interests
                        .remove(&id)
                        .unwrap();
                    drop(record);
                    assert_eq!(budget.usage().pending, 1);
                } else if scenario == "final" {
                    let record = get_mut_unchecked(&mut face)
                        .pending_current_interests
                        .remove(&id)
                        .unwrap();
                    finalize_pending_interest(record, &mut |_, _| {});
                }
            }
            if scenario == "shutdown" {
                face.task_controller.terminate_all_async().await;
                let _ctrl = gateway.tables.ctrl_lock.lock().unwrap();
                get_mut_unchecked(&mut face)
                    .pending_current_interests
                    .clear();
            }
            tokio::time::timeout(Duration::from_secs(2), async {
                while budget.usage().pending != 0 {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .unwrap();
            assert!(face.pending_current_interests.is_empty());
        }
        session.close().await.unwrap();
        runtime.close().await.unwrap();
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn actual_synthesized_interest_pressure_preserves_tcp_routes_and_disconnect() {
        for mode in ["router", "peer"] {
            let config=crate::Config::from_json5(&format!(r#"{{mode:"{mode}",listen:{{endpoints:["tcp/127.0.0.1:0"]}},scouting:{{multicast:{{enabled:false}}}}}}"#)).unwrap();
            let mut center = RuntimeBuilder::new(config).build().await.unwrap();
            center.install_route_gate(Arc::new(Allow)).unwrap();
            center.start().await.unwrap();
            let platform = crate::session::init(center.clone().into()).await.unwrap();
            let control = platform.declare_queryable("control").await.unwrap();
            let subscriber = platform.declare_subscriber("data").await.unwrap();
            let config=crate::Config::from_json5(&format!(r#"{{mode:"client",connect:{{endpoints:["{}"]}},scouting:{{multicast:{{enabled:false}}}}}}"#,center.get_locators()[0])).unwrap();
            let mut edge = RuntimeBuilder::new(config).build().await.unwrap();
            edge.install_route_gate(Arc::new(Allow)).unwrap();
            edge.start().await.unwrap();
            let client = crate::session::init(edge.clone().into()).await.unwrap();
            let querier = client.declare_querier("**").await.unwrap();
            let listener = querier.matching_listener().await.unwrap();
            let publisher = client.declare_publisher("data").await.unwrap();
            let pub_listener = publisher.matching_listener().await.unwrap();
            let gateway = edge.router();
            let budget = gateway
                .tables
                .tables
                .read()
                .unwrap()
                .data
                .native_interest_budget
                .clone();
            let snapshot = || {
                let _ctrl = gateway.tables.ctrl_lock.lock().unwrap();
                let tables = gateway.tables.tables.read().unwrap();
                let face = tables.data.faces.values().find(|f| !f.is_local).unwrap();
                (
                    face.id,
                    face.local_interests.len(),
                    face.pending_current_interests.len(),
                    face.next_native_interest_id.load(Ordering::SeqCst),
                )
            };
            tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    let s = snapshot();
                    if s.1 >= 2 && s.2 == 0 {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .unwrap();
            let initial = snapshot();
            let held = budget
                .reserve(initial.0, unit(496 - initial.1, 0, 0, 0))
                .unwrap();
            gateway
                .tables
                .update_config(&edge.config().lock().clone())
                .unwrap();
            assert!(Arc::ptr_eq(
                &budget,
                &gateway
                    .tables
                    .tables
                    .read()
                    .unwrap()
                    .data
                    .native_interest_budget
            ));
            let refused = client.declare_querier("refused/**").await.unwrap();
            let refused_listener = refused.matching_listener().await.unwrap();
            tokio::time::sleep(Duration::from_millis(30)).await;
            assert_eq!(
                snapshot(),
                initial,
                "{mode}: refused projection used an ID or partial state"
            );
            let replies = client
                .get("control")
                .timeout(Duration::from_secs(1))
                .await
                .unwrap();
            let query = tokio::time::timeout(Duration::from_millis(500), control.recv_async())
                .await
                .unwrap()
                .unwrap();
            query.reply("control", "still-running").await.unwrap();
            drop(query);
            assert!(replies.recv_async().await.unwrap().result().is_ok());
            client.put("data", "still-running").await.unwrap();
            assert!(
                tokio::time::timeout(Duration::from_millis(500), subscriber.recv_async())
                    .await
                    .unwrap()
                    .is_ok()
            );
            drop(refused_listener);
            refused.undeclare().await.unwrap();
            drop(held);
            let recovered = client.declare_querier("recovered/**").await.unwrap();
            let recovered_listener = recovered.matching_listener().await.unwrap();
            tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    let s = snapshot();
                    if s.1 > initial.1 && s.2 == 0 {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .unwrap();
            assert!(snapshot().3 > initial.3);
            client.close().await.unwrap();
            edge.close().await.unwrap();
            drop((
                querier,
                listener,
                publisher,
                pub_listener,
                recovered,
                recovered_listener,
            ));
            tokio::time::timeout(Duration::from_secs(2), async {
                while budget.usage() != Default::default() {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .unwrap();
            assert!(budget.ledger.lock().unwrap().faces.is_empty());
            platform.close().await.unwrap();
            drop((control, subscriber));
            center.close().await.unwrap();
            let center_budget = center
                .router()
                .tables
                .tables
                .read()
                .unwrap()
                .data
                .native_interest_budget
                .clone();
            assert_eq!(center_budget.usage(), Default::default());
        }
    }
    #[test]
    fn interest_reserved_counts_keep_global_and_face_absolute_caps() {
        use crate::net::routing::interceptor::route_gate::QueryCapacity as C;
        for (axis, global, local, reserved_global, reserved_local) in [
            (0, 8192, 512, 256, 16),
            (1, 1024, 128, 64, 8),
            (2, 4096, 256, 128, 8),
            (3, 64, 1, 0, 0),
        ] {
            let unit = |n| match axis {
                0 => unit(n, 0, 0, 0),
                1 => unit(0, n, 0, 0),
                2 => unit(0, 0, n, 0),
                _ => unit(0, 0, 0, n),
            };
            // Isolate count constraints from the separately tested byte reserve.
            let mut raw = NativeInterestBudget::default();
            raw.reserved_global.bytes = 0;
            raw.reserved_face.bytes = 0;
            let b = Arc::new(raw);
            b.enable();
            let mut held = Vec::new();
            for i in 0..global - reserved_global {
                held.push(b.reserve(i / (local - reserved_local), unit(1)).unwrap());
            }
            assert!(b.reserve(99999, unit(1)).is_none());
            for i in 0..reserved_global {
                held.push(b.reserve_for(99999 + i, unit(1), C::Control).unwrap());
            }
            assert!(b.reserve_for(199999, unit(1), C::Control).is_none());
            assert!(b
                .reserve_for(199999, unit(usize::MAX), C::Control)
                .is_none());
            assert!(b.reserve(0, Default::default()).is_some());
            drop(held);
            assert_eq!(b.usage(), Default::default());
            let ordinary = b.reserve(4, unit(local - reserved_local)).unwrap();
            assert!(b.reserve(4, unit(1)).is_none());
            let control = b.reserve_for(4, unit(reserved_local), C::Control).unwrap();
            assert!(b.reserve_for(4, unit(1), C::Control).is_none());
            drop((ordinary, control));
            assert!(b.ledger.lock().unwrap().faces.is_empty());
        }
    }
    #[test]
    fn interest_weight_floor_keeps_initial_and_empty_owners_without_promotion() {
        use crate::net::routing::interceptor::route_gate::QueryCapacity as C;
        let b = Arc::new(NativeInterestBudget::default());
        b.enable();
        let held = (0..16)
            .map(|face| b.reserve(face, unit(480, 0, 0, 0)).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(b.usage().bytes(), Some(960 * 1024));
        assert!(b.reserve(9000, unit(1, 0, 0, 0)).is_none());
        let control = b.reserve_for(9000, unit(512, 0, 0, 0), C::Control).unwrap();
        assert_eq!(b.usage().bytes(), Some(1024 * 1024));
        let initial = b.reserve(9001, unit(0, 0, 0, 1)).unwrap();
        let empty = b.reserve(9002, Default::default()).unwrap();
        assert!(!b.ledger.lock().unwrap().faces.contains_key(&9002));
        assert!(b.reserve_for(9001, unit(0, 1, 0, 0), C::Control).is_none());
        drop((control, initial, empty));
        assert!(b.reserve(9000, unit(1, 0, 0, 0)).is_none());
        drop(held);
        assert_eq!(b.usage(), Default::default());
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn controlled_current_future_cleanup_keeps_reserved_task_after_record_removal() {
        use crate::net::routing::interceptor::route_gate::{
            QueryCapacity, RouteGate, RouteRequest, RouteSubject,
        };
        struct Control;
        impl RouteGate for Control {
            fn resource_capacity(&self, key: &str) -> QueryCapacity {
                if key == "control/exact" {
                    QueryCapacity::Control
                } else {
                    QueryCapacity::Business
                }
            }
            fn authorize(&self, _: &RouteSubject, _: &RouteRequest<'_>) -> bool {
                true
            }
        }
        let (runtime, session, mut face) = local().await;
        runtime.install_route_gate(Arc::new(Control)).unwrap();
        let gateway = runtime.router();
        let b = face.native_interest_budget.clone();
        let held = b.reserve(face.id, unit(0, 120, 0, 0)).unwrap();
        assert!(face
            .prepare_interest(InterestMode::CurrentFuture, false)
            .is_none());
        let future;
        {
            let _ctrl = gateway.tables.ctrl_lock.lock().unwrap();
            let res = {
                let mut t = gateway.tables.tables.write().unwrap();
                let mut root = t.data.root_res.clone();
                Resource::make_resource(&mut t, &mut root, "control/exact").unwrap()
            };
            let next = face.next_native_interest_id.load(Ordering::SeqCst);
            let mut p = face
                .prepare_interest_for(
                    InterestMode::CurrentFuture,
                    false,
                    Some(&res),
                    InterestOptions::QUERYABLES,
                )
                .unwrap();
            assert_eq!(b.usage(), unit(1, 121, 0, 0));
            assert_eq!(face.next_native_interest_id.load(Ordering::SeqCst), next);
            let id = face.new_interest_id(&AtomicU32::new(1)).unwrap();
            let interest = Arc::new(CurrentInterest {
                src: gateway.tables.tables.read().unwrap().hats[face.region]
                    .new_remote(&face, 0)
                    .unwrap(),
                src_region: face.region,
                src_interest_id: id,
                mode: InterestMode::CurrentFuture,
            });
            let cancellation_token = face.task_controller.get_cancellation_token();
            let rejection_token = face.task_controller.get_cancellation_token();
            let pending = p.pending.take();
            future = p.state(face.id, InterestOptions::QUERYABLES, Some(res), false);
            get_mut_unchecked(&mut face)
                .pending_current_interests
                .insert(
                    id,
                    PendingCurrentInterest {
                        interest,
                        cancellation_token,
                        rejection_token,
                        native_reservation: pending,
                    },
                );
            CurrentInterestCleanup::spawn_interest_clean_up_task(
                &face,
                &gateway.tables,
                id,
                Duration::from_millis(10),
            );
            tokio::time::sleep(Duration::from_millis(40)).await;
            drop(
                get_mut_unchecked(&mut face)
                    .pending_current_interests
                    .remove(&id),
            );
            assert_eq!(b.usage(), unit(1, 121, 0, 0));
        }
        tokio::time::timeout(Duration::from_secs(2), async {
            while b.usage().pending != 120 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(b.usage(), unit(1, 120, 0, 0));
        drop(future);
        drop(held);
        assert_eq!(b.usage(), Default::default());
        session.close().await.unwrap();
        runtime.close().await.unwrap();
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn real_tcp_scoped_interest_survives_projection_and_hat_pressure_and_permission_changes()
    {
        use crate::net::routing::{
            dispatcher::local_resources::{NativeHatKind, NativeHatMap},
            interceptor::route_gate::{QueryCapacity, RouteAction, RouteRequest, RouteSubject},
        };
        use std::sync::atomic::AtomicBool;
        const KEY: &str = "control/exact";
        struct Policy(AtomicBool);
        impl RouteGate for Policy {
            fn resource_capacity(&self, key: &str) -> QueryCapacity {
                if key == KEY {
                    QueryCapacity::Control
                } else {
                    QueryCapacity::Business
                }
            }
            fn authorize(&self, _: &RouteSubject, r: &RouteRequest<'_>) -> bool {
                !matches!(
                    r.action,
                    RouteAction::DeclareQueryable
                        | RouteAction::DeclareSubscriber
                        | RouteAction::LivelinessToken
                ) || self.0.load(Ordering::Acquire)
            }
        }
        for mode in ["router", "peer"] {
            let gate = Arc::new(Policy(AtomicBool::new(true)));
            let c=crate::Config::from_json5(&format!(r#"{{mode:"{mode}",listen:{{endpoints:["tcp/127.0.0.1:0"]}},scouting:{{multicast:{{enabled:false}}}}}}"#)).unwrap();
            let mut center = RuntimeBuilder::new(c).build().await.unwrap();
            center.install_route_gate(gate.clone()).unwrap();
            center.start().await.unwrap();
            let platform = crate::session::init(center.clone().into()).await.unwrap();
            let control = platform.declare_queryable(KEY).await.unwrap();
            let c=crate::Config::from_json5(&format!(r#"{{mode:"client",connect:{{endpoints:["{}"]}},scouting:{{multicast:{{enabled:false}}}}}}"#,center.get_locators()[0])).unwrap();
            let mut edge = RuntimeBuilder::new(c).build().await.unwrap();
            edge.install_route_gate(gate.clone()).unwrap();
            edge.start().await.unwrap();
            let client = crate::session::init(edge.clone().into()).await.unwrap();
            let broad = client.declare_querier("**").await.unwrap();
            let broad_listener = broad.matching_listener().await.unwrap();
            let eg = edge.router();
            let eb = eg
                .tables
                .tables
                .read()
                .unwrap()
                .data
                .native_interest_budget
                .clone();
            let snapshot = || {
                let _ctrl = eg.tables.ctrl_lock.lock().unwrap();
                let t = eg.tables.tables.read().unwrap();
                let f = t.data.faces.values().find(|f| !f.is_local).unwrap();
                (
                    f.id,
                    f.local_interests.len(),
                    f.pending_current_interests.len(),
                    f.next_native_interest_id.load(Ordering::SeqCst),
                )
            };
            tokio::time::timeout(Duration::from_secs(2), async {
                while {
                    let x = snapshot();
                    x.1 < 1 || x.2 != 0
                } {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .unwrap();
            let before = snapshot();
            let held = eb.reserve(before.0, unit(496 - before.1, 0, 0, 0)).unwrap();
            // Fill the center's shared native hat Interest ledger with retained
            // dummy maps. Real wire traffic and permissions still execute normally.
            let cg = center.router();
            {
                let t = cg.tables.tables.read().unwrap();
                let face = t.data.faces.values().find(|f| !f.is_local).unwrap();
                let budget = face.native_interest_budget.clone();
                let existing = budget
                    .ledger
                    .lock()
                    .unwrap()
                    .faces
                    .get(&face.id)
                    .map_or(0, |u| u.keys);
                let held_keys = budget
                    .reserve(face.id, unit(0, 0, 248 - existing, 0))
                    .unwrap();
                let expr = KEY.into();
                gate.0.store(false, Ordering::Release);
                assert!(
                    KeyInterestState::reserve(
                        face,
                        Some(&expr),
                        InterestOptions::KEYEXPRS + InterestOptions::QUERYABLES
                    )
                    .is_none(),
                    "mixed option cannot borrow key-only reserve"
                );
                gate.0.store(true, Ordering::Release);
                let key = KeyInterestState::reserve(
                    face,
                    Some(&expr),
                    InterestOptions::KEYEXPRS + InterestOptions::QUERYABLES,
                )
                .unwrap();
                assert_eq!(budget.usage().keys, 249);
                drop((key, held_keys));
            }
            let mut maps = Vec::new();
            {
                let t = cg.tables.tables.read().unwrap();
                let mut left: usize = 3968; // subtract actual live Interest entries below via map owners
                                            // Actual broad registration contributes one remote Interest per face.
                while left > 0 {
                    let mut m = NativeHatMap::<u32, u32>::new(&t.data, NativeHatKind::Interest);
                    let mut count = 0;
                    for id in 0..248 {
                        if let Some(p) = m.prepare_insert(id) {
                            m.insert_prepared(p, id);
                            count += 1;
                        } else {
                            break;
                        }
                    }
                    if count == 0 {
                        break;
                    }
                    left = left.saturating_sub(count);
                    maps.push(m);
                }
            }
            gate.0.store(false, Ordering::Release);
            let refused = client.declare_querier(KEY).await.unwrap();
            let refused_listener = refused.matching_listener().await.unwrap();
            tokio::time::sleep(Duration::from_millis(100)).await;
            assert_eq!(
                snapshot(),
                before,
                "metadata-only permission used reserve: {mode}"
            );
            drop(refused_listener);
            refused.undeclare().await.unwrap();
            gate.0.store(true, Ordering::Release);
            let exact = client.declare_querier(KEY).await.unwrap();
            let exact_listener = exact.matching_listener().await.unwrap();
            tokio::time::timeout(Duration::from_secs(2), async {
                while {
                    let x = snapshot();
                    x.1 != before.1 + 1 || x.2 != 0
                } {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .unwrap();
            assert!(snapshot().3 > before.3);
            let replies = client
                .get(KEY)
                .timeout(Duration::from_secs(2))
                .await
                .unwrap();
            let q = tokio::time::timeout(Duration::from_secs(2), control.recv_async())
                .await
                .unwrap()
                .unwrap();
            q.reply(KEY, "control Interest reserved").await.unwrap();
            drop(q);
            assert!(replies.recv_async().await.unwrap().result().is_ok());
            eg.tables
                .update_config(&edge.config().lock().clone())
                .unwrap();
            cg.tables
                .update_config(&center.config().lock().clone())
                .unwrap();
            gate.0.store(false, Ordering::Release);
            drop(exact_listener);
            exact.undeclare().await.unwrap();
            tokio::time::timeout(Duration::from_secs(2), async {
                while snapshot().1 != before.1 {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .unwrap();
            let withdrawn = snapshot();
            let again = client.declare_querier(KEY).await.unwrap();
            let again_listener = again.matching_listener().await.unwrap();
            tokio::time::sleep(Duration::from_millis(100)).await;
            assert_eq!(snapshot(), withdrawn);
            drop((again_listener, broad_listener));
            again.undeclare().await.unwrap();
            broad.undeclare().await.unwrap();
            drop(held);
            drop(maps);
            client.close().await.unwrap();
            edge.close().await.unwrap();
            assert_eq!(eb.usage(), Default::default());
            platform.close().await.unwrap();
            drop(control);
            center.close().await.unwrap();
        }
    }
}
