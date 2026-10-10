//
// Copyright (c) 2023 ZettaScale Technology
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
    any::Any,
    borrow::{Borrow, Cow},
    collections::VecDeque,
    convert::TryInto,
    fmt::Debug,
    hash::{Hash, Hasher},
    ops::{Deref, DerefMut},
    sync::{Arc, RwLock, Weak},
};

use zenoh_collections::{IntHashMap, IntHashSet, SingleOrBoxHashSet};
use zenoh_protocol::{
    core::{key_expr::keyexpr, ExprId, Region, WireExpr},
    network::{
        self,
        declare::{self, queryable::ext::QueryableInfoType, Declare, DeclareBody, DeclareKeyExpr},
        interest::{InterestId, InterestOptions},
        Mapping, RequestId,
    },
};
use zenoh_sync::{get_mut_unchecked, Cache, CacheValueType};

use super::{
    face::FaceState,
    pubsub::SubscriberInfo,
    tables::{TablesData, TablesLock},
};
use crate::net::routing::{
    dispatcher::{
        face::{Face, FaceId},
        region::RegionMap,
        tables::{RoutingExpr, Tables},
    },
    interceptor::{InterceptorTrait, InterceptorsChain},
    RoutingContext,
};

pub(crate) type NodeId = u16;

/// [`NodeId`] value of [`network::ext::NodeIdType::DEFAULT`].
pub(crate) const DEFAULT_NODE_ID: NodeId = network::ext::NodeIdType::<0>::DEFAULT.node_id;

/// Returns `Some(node_id)` if it represents a router region source, `None` if default.
///
/// Useful for tracing instrumentation to omit default/uninteresting [`NodeId`]s from spans.
#[inline]
pub(crate) const fn node_id_as_source(node_id: NodeId) -> Option<NodeId> {
    if node_id != DEFAULT_NODE_ID {
        Some(node_id)
    } else {
        None
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Direction {
    pub(crate) dst_face: Arc<FaceState>,
    pub(crate) wire_expr: WireExpr<'static>,
    pub(crate) node_id: NodeId,
}

#[derive(Clone, Debug)]
pub(crate) struct QueryDirection {
    pub(crate) dir: Direction,
    pub(crate) rid: RequestId,
}

pub(crate) type Route = Vec<Direction>;

#[derive(Clone, Debug)]
pub(crate) struct QueryTargetQabl {
    pub(crate) dir: Direction,
    pub(crate) info: Option<QueryableInfoType>,
    pub(crate) region: Region,
}

impl QueryTargetQabl {
    pub(crate) fn new(
        ctx: &FaceContext,
        expr: &RoutingExpr,
        complete: bool,
        region: &Region,
    ) -> Option<Self> {
        let qabl = ctx.qabl?;
        let wire_expr = expr.get_best_key(ctx.face.id);
        Some(Self {
            dir: Direction {
                dst_face: ctx.face.clone(),
                wire_expr: wire_expr.to_owned(),
                node_id: DEFAULT_NODE_ID,
            },
            info: Some(QueryableInfoType {
                complete: complete && qabl.complete,
                // NOTE: local client faces are nearer than remote client faces
                distance: if ctx.face.is_local { 0 } else { 1 },
            }),
            region: *region,
        })
    }
}

pub(crate) type QueryTargetQablSet = Vec<QueryTargetQabl>;

/// Helper struct to build route, handling face deduplication.
pub(crate) struct RouteBuilder<T> {
    /// The route built.
    route: Vec<T>,
    /// The faces' id already inserted.
    faces: IntHashSet<usize>,
}

impl<T> RouteBuilder<T> {
    /// Creates a new empty builder.
    pub(crate) fn new() -> Self {
        Self {
            route: Vec::new(),
            faces: IntHashSet::new(),
        }
    }

    /// Insert a new direction if it has not been registered for the given face.
    pub(crate) fn insert(&mut self, face_id: FaceId, direction: impl FnOnce() -> T) {
        if self.faces.insert(face_id) {
            self.route.push(direction());
        }
    }

    pub(crate) fn try_insert(&mut self, face_id: usize, direction: impl FnOnce() -> Option<T>) {
        if !self.faces.contains(&face_id) {
            if let Some(direction) = direction() {
                self.faces.insert(face_id);
                self.route.push(direction);
            }
        }
    }

    /// Build the route, consuming the builder.
    pub(crate) fn build(self) -> Vec<T> {
        self.route
    }
}

pub(crate) struct InterceptorCache(Cache<Option<Box<dyn Any + Send + Sync>>>);
pub(crate) type InterceptorCacheValueType = CacheValueType<Option<Box<dyn Any + Send + Sync>>>;

impl InterceptorCache {
    pub(crate) fn new(value: Option<Box<dyn Any + Send + Sync>>, version: usize) -> Self {
        Self(Cache::<Option<Box<dyn Any + Send + Sync>>>::new(
            value, version,
        ))
    }

    pub(crate) fn empty() -> Self {
        InterceptorCache::new(None, 0)
    }

    #[inline]
    fn value(
        &self,
        interceptor: &InterceptorsChain,
        resource: &Resource,
    ) -> Option<InterceptorCacheValueType> {
        self.0
            .value(interceptor.version, || {
                interceptor.compute_keyexpr_cache(resource.keyexpr()?)
            })
            .ok()
    }
}

pub(crate) struct FaceContext {
    pub(crate) face: Arc<FaceState>,
    pub(crate) local_expr_id: Option<ExprId>,
    pub(crate) remote_expr_id: Option<ExprId>,
    pub(crate) subs: Option<SubscriberInfo>,
    pub(crate) qabl: Option<QueryableInfoType>,
    pub(crate) token: bool,
    pub(crate) subscriber_interest_finalized: bool,
    pub(crate) queryable_interest_finalized: bool,
    pub(crate) in_interceptor_cache: InterceptorCache,
    pub(crate) e_interceptor_cache: InterceptorCache,
}

impl FaceContext {
    pub(crate) fn new(face: Arc<FaceState>) -> Self {
        Self {
            face,
            local_expr_id: None,
            remote_expr_id: None,
            subs: None,
            qabl: None,
            token: false,
            subscriber_interest_finalized: false,
            queryable_interest_finalized: false,
            in_interceptor_cache: InterceptorCache::empty(),
            e_interceptor_cache: InterceptorCache::empty(),
        }
    }
}

/// Global version number for route computation.
/// Use 64bit to not care about rollover.
pub type RoutesVersion = u64;

/// Per-hat data/query routes.
///
/// 1. Routes depend on the source region of a message.
///
///   + For instance, a north peer hat N may route a message in its region only if said message
///     arrives from a south-bound face, otherwise N would not route messages within its region.
///     Thus routes depend on the source bound of a message.
///
///   + Given two south peer sub-regions, say S1 and S2, S1 may route a message to peers in its
///     region only said the message originates in S2 and vice-versa. Thus routes not only depend
///     on the source bound of a message but on its source region more generally.
///
/// 2. Routes depend on the source node id for router hats. In a `R1 - R - R2` topology, R would
///    route a message to R1 only if it originates in R2 and vice-versa.
pub(crate) struct Routes<T> {
    /// Mapping from **source** [`Region`] and [`NodeId`] to data/query routes.
    #[cfg(not(feature = "zenss-route-gate"))]
    mapping: RegionMap<NodeIdMap<T>>,
    #[cfg(feature = "zenss-route-gate")]
    mapping: std::collections::BTreeMap<(Region, NodeId), CachedRoute<T>>,
    version: u64,
}

#[cfg(not(feature = "zenss-route-gate"))]
pub(crate) type NodeIdMap<T> = Vec<Option<T>>;

#[cfg(feature = "zenss-route-gate")]
struct CachedRoute<T> {
    route: T,
    _reservation: Option<NativeResourceReservation>,
}

// Cache ownership only: in-flight clones, allocator metadata and FaceState
// memory have separate owners. Charge each retained cache reference conservatively.
pub(crate) trait RouteCacheWeight {
    fn retained_bytes(&self) -> usize;
}
impl RouteCacheWeight for Arc<Route> {
    fn retained_bytes(&self) -> usize {
        self.capacity()
            .saturating_mul(std::mem::size_of::<Direction>())
            .saturating_add(
                self.iter()
                    .fold(0usize, |n, d| n.saturating_add(d.wire_expr.suffix.len())),
            )
    }
}
impl RouteCacheWeight for Arc<QueryTargetQablSet> {
    fn retained_bytes(&self) -> usize {
        self.capacity()
            .saturating_mul(std::mem::size_of::<QueryTargetQabl>())
            .saturating_add(self.iter().fold(0usize, |n, d| {
                n.saturating_add(d.dir.wire_expr.suffix.len())
            }))
    }
}

impl<T> Default for Routes<T> {
    fn default() -> Self {
        Self {
            mapping: Default::default(),
            version: 0,
        }
    }
}

impl<T> Routes<T> {
    pub(crate) fn clear(&mut self) {
        self.mapping.clear();
    }

    #[inline]
    pub(crate) fn get_route(
        &self,
        version: RoutesVersion,
        region: &Region,
        node_id: NodeId,
    ) -> Option<&T> {
        if version != self.version {
            return None;
        }

        #[cfg(not(feature = "zenss-route-gate"))]
        {
            self.mapping
                .get(region)
                .and_then(|rs| rs.get(node_id as usize))
                .and_then(|r| r.as_ref())
        }
        #[cfg(feature = "zenss-route-gate")]
        {
            self.mapping.get(&(*region, node_id)).map(|r| &r.route)
        }
    }

    #[cfg(not(feature = "zenss-route-gate"))]
    #[inline]
    pub(crate) fn set_route(
        &mut self,
        version: RoutesVersion,
        region: &Region,
        node_id: NodeId,
        route: T,
    ) {
        if self.version != version {
            self.clear();
            self.version = version;
        }

        let aux = |routes: &mut NodeIdMap<T>| {
            routes.resize_with(node_id as usize + 1, || None);
            routes[node_id as usize] = Some(route);
        };

        if let Some(routes) = self.mapping.get_mut(region) {
            aux(routes);
        } else {
            let mut routes = NodeIdMap::default();
            aux(&mut routes);
            self.mapping.insert(*region, routes);
        }
    }
}

#[cfg(feature = "zenss-route-gate")]
impl<T: RouteCacheWeight> Routes<T> {
    fn set_route(
        &mut self,
        version: RoutesVersion,
        region: &Region,
        node_id: NodeId,
        route: T,
        budget: Option<&Arc<NativeResourceBudget>>,
    ) {
        if self.version != version {
            self.clear();
            self.version = version;
        }
        // Replacement drops the old reservation before admitting the new one.
        self.mapping.remove(&(*region, node_id));
        let reservation = if let Some(budget) = budget {
            if self.mapping.len() >= ROUTE_CACHE_PER_MAP {
                return;
            }
            let Some(bytes) = route.retained_bytes().checked_add(
                std::mem::size_of::<CachedRoute<T>>() + std::mem::size_of::<(Region, NodeId)>(),
            ) else {
                return;
            };
            let Some(reservation) = budget.reserve(NativeResourceUsage {
                cache_entries: 1,
                cache_bytes: bytes,
                ..Default::default()
            }) else {
                return;
            };
            Some(reservation)
        } else {
            None
        };
        self.mapping.insert(
            (*region, node_id),
            CachedRoute {
                route,
                _reservation: reservation,
            },
        );
    }
}

pub(crate) fn get_or_set_route<T: Clone + RouteCacheWeight>(
    routes: &RwLock<Routes<T>>,
    version: RoutesVersion,
    region: &Region,
    node_id: NodeId,
    compute_route: impl FnOnce() -> T,
    #[cfg(feature = "zenss-route-gate")] budget: Option<&Arc<NativeResourceBudget>>,
) -> T {
    if let Some(route) = routes.read().unwrap().get_route(version, region, node_id) {
        return route.clone();
    }
    let mut routes = routes.write().unwrap();
    // NOTE(regions): we supposedly re-read the routes here because they might've changed, but I'm
    // not sure this is true given that all callers would've acquired `TablesLock::tables`.
    if let Some(route) = routes.get_route(version, region, node_id) {
        return route.clone();
    }
    let route = compute_route();
    routes.set_route(
        version,
        region,
        node_id,
        route.clone(),
        #[cfg(feature = "zenss-route-gate")]
        budget,
    );
    route
}

pub(crate) type DataRoutes = Routes<Arc<Route>>;
pub(crate) type QueryRoutes = Routes<Arc<QueryTargetQablSet>>;

// ZenSS: actual retained tree allocations, separate from wire ID accounting.
#[cfg(feature = "zenss-route-gate")]
const RESOURCE_NODES: usize = 8192;
#[cfg(feature = "zenss-route-gate")]
const RESOURCE_CONTEXTS: usize = 4096;
#[cfg(feature = "zenss-route-gate")]
const RESOURCE_EXPR_BYTES: usize = 8 * 1024 * 1024;
#[cfg(feature = "zenss-route-gate")]
const RESOURCE_MATCH_EDGES: usize = 128 * 1024;
#[cfg(feature = "zenss-route-gate")]
const BUSINESS_RESOURCE_NODES: usize = RESOURCE_NODES - 256;
#[cfg(feature = "zenss-route-gate")]
const BUSINESS_RESOURCE_CONTEXTS: usize = RESOURCE_CONTEXTS - 128;
#[cfg(feature = "zenss-route-gate")]
const BUSINESS_RESOURCE_EXPR_BYTES: usize = RESOURCE_EXPR_BYTES - 256 * 1024;
#[cfg(feature = "zenss-route-gate")]
const BUSINESS_RESOURCE_MATCH_EDGES: usize = RESOURCE_MATCH_EDGES - 8192;

#[cfg(feature = "zenss-route-gate")]
fn resource_capacity(
    tables: &TablesData,
    key: &str,
) -> super::super::interceptor::route_gate::QueryCapacity {
    use super::super::interceptor::route_gate::QueryCapacity;
    tables
        .route_gate
        .as_ref()
        .map_or(QueryCapacity::Business, |gate| {
            super::super::interceptor::route_gate::resource_capacity(gate.as_ref(), key)
        })
}
#[cfg(feature = "zenss-route-gate")]
const ROUTE_CACHE_PER_MAP: usize = 256;
#[cfg(feature = "zenss-route-gate")]
const ROUTE_CACHE_ENTRIES: usize = 16 * 1024;
#[cfg(feature = "zenss-route-gate")]
const ROUTE_CACHE_BYTES: usize = 32 * 1024 * 1024;
#[cfg(feature = "zenss-route-gate")]
#[derive(Clone, Copy, Default)]
struct NativeResourceUsage {
    nodes: usize,
    bytes: usize,
    contexts: usize,
    matches: usize,
    cache_entries: usize,
    cache_bytes: usize,
}
#[cfg(feature = "zenss-route-gate")]
#[derive(Default)]
pub(crate) struct NativeResourceBudget(std::sync::Mutex<NativeResourceUsage>);
#[cfg(feature = "zenss-route-gate")]
struct NativeResourceReservation {
    budget: Arc<NativeResourceBudget>,
    usage: NativeResourceUsage,
}
#[cfg(feature = "zenss-route-gate")]
impl NativeResourceBudget {
    fn reserve(self: &Arc<Self>, usage: NativeResourceUsage) -> Option<NativeResourceReservation> {
        self.reserve_for(
            usage,
            super::super::interceptor::route_gate::QueryCapacity::Business,
        )
    }
    fn reserve_for(
        self: &Arc<Self>,
        usage: NativeResourceUsage,
        capacity: super::super::interceptor::route_gate::QueryCapacity,
    ) -> Option<NativeResourceReservation> {
        use super::super::interceptor::route_gate::QueryCapacity;
        let mut current = self.0.lock().ok()?;
        let next = NativeResourceUsage {
            nodes: current.nodes.checked_add(usage.nodes)?,
            bytes: current.bytes.checked_add(usage.bytes)?,
            contexts: current.contexts.checked_add(usage.contexts)?,
            matches: current.matches.checked_add(usage.matches)?,
            cache_entries: current.cache_entries.checked_add(usage.cache_entries)?,
            cache_bytes: current.cache_bytes.checked_add(usage.cache_bytes)?,
        };
        let control = capacity == QueryCapacity::Control;
        if next.nodes
            > if control {
                RESOURCE_NODES
            } else {
                BUSINESS_RESOURCE_NODES
            }
            || next.bytes
                > if control {
                    RESOURCE_EXPR_BYTES
                } else {
                    BUSINESS_RESOURCE_EXPR_BYTES
                }
            || next.contexts
                > if control {
                    RESOURCE_CONTEXTS
                } else {
                    BUSINESS_RESOURCE_CONTEXTS
                }
            || next.matches
                > if control {
                    RESOURCE_MATCH_EDGES
                } else {
                    BUSINESS_RESOURCE_MATCH_EDGES
                }
            || next.cache_entries > ROUTE_CACHE_ENTRIES
            || next.cache_bytes > ROUTE_CACHE_BYTES
        {
            return None;
        }
        *current = next;
        Some(NativeResourceReservation {
            budget: self.clone(),
            usage,
        })
    }
}
#[cfg(feature = "zenss-route-gate")]
impl Drop for NativeResourceReservation {
    fn drop(&mut self) {
        let mut current = self.budget.0.lock().unwrap_or_else(|e| e.into_inner());
        current.nodes -= self.usage.nodes;
        current.bytes -= self.usage.bytes;
        current.contexts -= self.usage.contexts;
        current.matches -= self.usage.matches;
        current.cache_entries -= self.usage.cache_entries;
        current.cache_bytes -= self.usage.cache_bytes;
    }
}

#[cfg(feature = "zenss-route-gate")]
impl NativeResourceReservation {
    fn release_matches(&mut self, count: usize) {
        self.budget
            .0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .matches -= count;
        self.usage.matches -= count;
    }
    fn merge_matches(&mut self, mut other: Self) {
        debug_assert!(Arc::ptr_eq(&self.budget, &other.budget));
        self.usage.matches += other.usage.matches;
        other.usage.matches = 0;
    }
}

pub(crate) struct ResourceContext {
    #[cfg(feature = "zenss-route-gate")]
    native_reservation: Option<NativeResourceReservation>,
    #[cfg(feature = "zenss-route-gate")]
    native_match_reservation: Option<NativeResourceReservation>,
    pub(crate) matches: Vec<Weak<Resource>>,
    pub(crate) hats: RegionMap<HatResourceContext>,
    pub(crate) data_routes: RwLock<DataRoutes>,
    #[cfg(feature = "stats")]
    pub(crate) stats_keys: zenoh_stats::StatsKeyCache,
}

impl ResourceContext {
    pub(crate) fn new(hat: RegionMap<HatResourceContext>) -> ResourceContext {
        ResourceContext {
            #[cfg(feature = "zenss-route-gate")]
            native_reservation: None,
            #[cfg(feature = "zenss-route-gate")]
            native_match_reservation: None,
            matches: Vec::new(),
            hats: hat,
            data_routes: Default::default(),
            #[cfg(feature = "stats")]
            stats_keys: Default::default(),
        }
    }

    pub(crate) fn disable_data_routes(&mut self) {
        self.data_routes.get_mut().unwrap().clear();
    }
}

pub(crate) struct HatResourceContext {
    /// Map from `Region` to `HatContext`.
    pub(crate) ctx: Box<dyn Any + Send + Sync>,
    pub(crate) data_routes: RwLock<DataRoutes>,
    pub(crate) query_routes: RwLock<QueryRoutes>,
}

impl HatResourceContext {
    pub(crate) fn new(ctx: Box<dyn Any + Send + Sync>) -> Self {
        HatResourceContext {
            ctx,
            data_routes: Default::default(),
            query_routes: Default::default(),
        }
    }

    pub(crate) fn disable_data_routes(&mut self) {
        self.data_routes.get_mut().unwrap().clear();
    }

    pub(crate) fn disable_query_routes(&mut self) {
        self.query_routes.get_mut().unwrap().clear();
    }
}

pub struct Resource {
    #[cfg(feature = "zenss-route-gate")]
    native_reservation: Option<NativeResourceReservation>,
    pub(crate) parent: Option<Arc<Resource>>,
    pub(crate) expr: String,
    pub(crate) suffix: usize,
    pub(crate) nonwild_prefix: Option<Arc<Resource>>,
    pub(crate) children: SingleOrBoxHashSet<Child>,
    pub(crate) ctx: Option<Box<ResourceContext>>,
    pub(crate) face_ctxs: IntHashMap<FaceId, Arc<FaceContext>>,
}

impl PartialEq for Resource {
    fn eq(&self, other: &Self) -> bool {
        self.expr() == other.expr()
    }
}
impl Eq for Resource {}

// NOTE: The `clippy::mutable_key_type` lint takes issue with the fact that `Resource` contains
// interior mutable data. A configuration option is used to assert that the accessed fields are
// not interior mutable in clippy.toml. Thus care should be taken to ensure soundness of this impl
// as Clippy will not warn about its usage in sets/maps.
impl Hash for Resource {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.expr().hash(state);
    }
}

impl Debug for Resource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.expr())
    }
}

#[derive(Clone)]
pub(crate) struct Child(Arc<Resource>);

impl Deref for Child {
    type Target = Arc<Resource>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Child {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl PartialEq for Child {
    fn eq(&self, other: &Self) -> bool {
        self.0.suffix() == other.0.suffix()
    }
}

impl Eq for Child {}

impl Hash for Child {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.suffix().hash(state);
    }
}

impl Borrow<str> for Child {
    fn borrow(&self) -> &str {
        self.0.suffix()
    }
}

impl Resource {
    fn new(parent: &Arc<Resource>, suffix: &str, context: Option<ResourceContext>) -> Resource {
        let nonwild_prefix = match &parent.nonwild_prefix {
            None => {
                if suffix.contains('*') {
                    Some(parent.clone())
                } else {
                    None
                }
            }
            Some(prefix) => Some(prefix.clone()),
        };

        Resource {
            #[cfg(feature = "zenss-route-gate")]
            native_reservation: None,
            parent: Some(parent.clone()),
            expr: parent.expr.clone() + suffix,
            suffix: parent.expr.len(),
            nonwild_prefix,
            children: SingleOrBoxHashSet::new(),
            ctx: context.map(Box::new),
            face_ctxs: IntHashMap::new(),
        }
    }

    pub fn expr(&self) -> &str {
        &self.expr
    }

    pub fn keyexpr(&self) -> Option<&keyexpr> {
        if self.parent.is_none() {
            None
        } else {
            // SAFETY: non-root resources are valid keyexprs
            unsafe { Some(keyexpr::from_str_unchecked(&self.expr)) }
        }
    }

    pub fn suffix(&self) -> &str {
        &self.expr[self.suffix..]
    }

    #[inline(always)]
    pub(crate) fn context(&self) -> &ResourceContext {
        self.ctx.as_ref().unwrap()
    }

    #[inline(always)]
    pub(crate) fn context_mut(&mut self) -> &mut ResourceContext {
        self.ctx.as_mut().unwrap()
    }

    pub(crate) fn matches(&self, other: &Resource) -> bool {
        // NOTE: we expect matched resources to always have a context; i.e. correspond to a declared entity.
        // For now, this is an invariant worth checking in debug mode, until we are confident it always holds.
        debug_assert!(self.ctx.is_some());

        self.ctx.as_ref().is_some_and(|ctx| {
            ctx.matches
                .iter()
                .any(|m| m.upgrade().is_some_and(|m| &*m == other))
        })
    }

    pub fn nonwild_prefix(res: &Arc<Resource>) -> (Option<Arc<Resource>>, String) {
        match &res.nonwild_prefix {
            None => (Some(res.clone()), "".to_string()),
            Some(nonwild_prefix) => {
                if !nonwild_prefix.expr().is_empty() {
                    (
                        Some(nonwild_prefix.clone()),
                        res.expr[nonwild_prefix.expr.len()..].to_string(),
                    )
                } else {
                    (None, res.expr().to_string())
                }
            }
        }
    }

    pub fn root() -> Arc<Resource> {
        Arc::new(Resource {
            #[cfg(feature = "zenss-route-gate")]
            native_reservation: None,
            parent: None,
            expr: String::from(""),
            suffix: 0,
            nonwild_prefix: None,
            children: SingleOrBoxHashSet::new(),
            ctx: None,
            face_ctxs: IntHashMap::new(),
        })
    }

    #[tracing::instrument(level = "trace")]
    pub fn clean(res: &mut Arc<Resource>) {
        let mut resclone = res.clone();
        let mutres = get_mut_unchecked(&mut resclone);
        if let Some(ref mut parent) = mutres.parent {
            tracing::trace!(strong_count = Arc::strong_count(res));
            if Arc::strong_count(res) <= 3 && res.children.is_empty() {
                // consider only childless resource held by only one external object (+ 1 strong count for resclone, + 1 strong count for res.parent to a total of 3 )
                tracing::debug!("Unregister resource {}", res.expr());
                if let Some(context) = mutres.ctx.as_mut() {
                    for match_ in &mut context.matches {
                        let Some(mut match_) = match_.upgrade() else {
                            continue;
                        };
                        if !Arc::ptr_eq(&match_, res) {
                            let mutmatch = get_mut_unchecked(&mut match_);
                            if let Some(ctx) = mutmatch.ctx.as_mut() {
                                #[cfg(feature = "zenss-route-gate")]
                                let before = ctx.matches.len();
                                ctx.matches
                                    .retain(|x| x.upgrade().is_some_and(|r| !Arc::ptr_eq(&r, res)));
                                #[cfg(feature = "zenss-route-gate")]
                                if let Some(reservation) = &mut ctx.native_match_reservation {
                                    reservation.release_matches(before - ctx.matches.len());
                                }
                            }
                        }
                    }
                }
                mutres.nonwild_prefix.take();
                {
                    get_mut_unchecked(parent).children.remove(res.suffix());
                }
                Resource::clean(parent);
            }
        }
    }

    pub fn close(self: &mut Arc<Resource>) {
        let r = get_mut_unchecked(self);
        for mut c in r.children.drain() {
            Self::close(&mut c);
        }
        r.parent.take();
        r.nonwild_prefix.take();
        r.ctx.take();
        r.face_ctxs.clear();
    }

    #[cfg(test)]
    pub fn print_tree(from: &Arc<Resource>) -> String {
        let mut result = from.expr().to_string();
        result.push('\n');
        for child in from.children.iter() {
            result.push_str(&Resource::print_tree(child));
        }
        result
    }

    // Capture pre-existing trusted local declarations before network admission starts.
    #[cfg(feature = "zenss-route-gate")]
    pub(crate) fn install_native_budget(root: &Arc<Resource>) -> Option<Arc<NativeResourceBudget>> {
        let budget = Arc::new(NativeResourceBudget::default());
        let mut queue = vec![root.clone()];
        let mut reserved = Vec::new();
        while let Some(res) = queue.pop() {
            if !res.expr.is_empty() && (res.expr.len() > 2048 || res.expr.split('/').count() > 64) {
                return None;
            }
            let node = budget.reserve(NativeResourceUsage {
                nodes: usize::from(res.parent.is_some()),
                bytes: res.expr.len(),
                ..Default::default()
            })?;
            let context = if res.ctx.is_some() {
                Some(budget.reserve(NativeResourceUsage {
                    contexts: 1,
                    ..Default::default()
                })?)
            } else {
                None
            };
            let matches = if let Some(ctx) = &res.ctx {
                Some(budget.reserve(NativeResourceUsage {
                    matches: ctx.matches.len(),
                    ..Default::default()
                })?)
            } else {
                None
            };
            queue.extend(res.children.iter().map(|child| child.0.clone()));
            reserved.push((res, node, context, matches));
        }
        // Nothing is mutated until the entire existing tree fits.
        for (mut res, node, context, matches) in reserved {
            let res = get_mut_unchecked(&mut res);
            res.native_reservation = Some(node);
            if let Some(ctx) = &mut res.ctx {
                ctx.native_reservation = context;
                ctx.native_match_reservation = matches;
                // Existing local caches are disposable optimizations. Clear only
                // after successful whole-tree admission, before gate/network start.
                ctx.disable_data_routes();
                for hat in ctx.hats.values_mut() {
                    hat.disable_data_routes();
                    hat.disable_query_routes();
                }
            }
        }
        Some(budget)
    }

    pub fn make_resource(
        tables: &mut Tables,
        from: &mut Arc<Resource>,
        suffix: &str,
    ) -> Option<Arc<Resource>> {
        #[cfg(feature = "zenss-route-gate")]
        if let Some(budget) = tables.data.native_resource_budget.clone() {
            if from
                .expr
                .len()
                .checked_add(suffix.len())
                .is_none_or(|length| length > 2048)
            {
                return None;
            }
            let full = from.expr.clone() + suffix;
            if full.len() > 2048 || full.split('/').count() > 64 || keyexpr::new(&full).is_err() {
                return None;
            }
            let capacity = resource_capacity(&tables.data, &full);
            // Plan every missing prefix under the caller's Tables write lock. Reserve
            // the entire path/context before changing the tree, including partial chunks.
            let mut existing = Some(tables.data.root_res.clone());
            let mut rest = full.as_str();
            let mut length = 0;
            let mut nodes = Vec::new();
            while let Some((chunk, next)) = Self::split_first_chunk(rest) {
                length += chunk.len();
                existing = existing.and_then(|res| res.children.get(chunk).map(|c| c.0.clone()));
                if existing.is_none() {
                    nodes.push(budget.reserve_for(
                        NativeResourceUsage {
                            nodes: 1,
                            bytes: length,
                            ..Default::default()
                        },
                        capacity,
                    )?);
                }
                rest = next;
            }
            let context = if existing.as_ref().is_some_and(|r| r.ctx.is_some()) {
                None
            } else {
                Some(budget.reserve_for(
                    NativeResourceUsage {
                        contexts: 1,
                        ..Default::default()
                    },
                    capacity,
                )?)
            };
            let mut nodes = nodes.into_iter();
            let mut res = tables.data.root_res.clone();
            let mut rest = full.as_str();
            while let Some((chunk, next)) = Self::split_first_chunk(rest) {
                let child = res.children.get(chunk).map(|c| c.0.clone());
                res = if let Some(child) = child {
                    child
                } else {
                    let mut child = Resource::new(&res, chunk, None);
                    child.native_reservation = nodes.next();
                    let child = Arc::new(child);
                    get_mut_unchecked(&mut res)
                        .children
                        .insert(Child(child.clone()));
                    child
                };
                rest = next;
            }
            if res.ctx.is_none() {
                let hat = tables
                    .hats
                    .map_ref(|d| HatResourceContext::new(d.new_resource()));
                Resource::upgrade_resource(&mut res, hat);
                get_mut_unchecked(&mut res)
                    .ctx
                    .as_mut()
                    .unwrap()
                    .native_reservation = context;
            }
            return Some(res);
        }
        Some(Self::make_resource_unbounded(tables, from, suffix))
    }

    #[tracing::instrument(level = "debug", skip(tables), ret)]
    fn make_resource_unbounded(
        tables: &mut Tables,
        from: &mut Arc<Resource>,
        mut suffix: &str,
    ) -> Arc<Resource> {
        if !suffix.is_empty() && !suffix.starts_with('/') {
            if let Some(parent) = &mut from.parent.clone() {
                return Resource::make_resource_unbounded(
                    tables,
                    parent,
                    &[from.suffix(), suffix].concat(),
                );
            }
        }
        let mut from = from.clone();
        // do not use recursion as the tree may have arbitrary depth
        while let Some((chunk, rest)) = Self::split_first_chunk(suffix) {
            if let Some(child) = get_mut_unchecked(&mut from).children.get(chunk) {
                from = child.0.clone();
            } else {
                let new = Arc::new(Resource::new(&from, chunk, None));
                if rest.is_empty() {
                    tracing::debug!("Register resource {}", new.expr());
                }
                get_mut_unchecked(&mut from)
                    .children
                    .insert(Child(new.clone()));
                from = new;
            };
            suffix = rest;
        }
        let hat = tables
            .hats
            .map_ref(|d| HatResourceContext::new(d.new_resource()));
        Resource::upgrade_resource(&mut from, hat);
        from
    }

    #[inline]
    pub fn get_resource_ref<'a>(
        mut from: &'a Arc<Resource>,
        mut suffix: &str,
    ) -> Option<&'a Arc<Resource>> {
        if !suffix.is_empty() && !suffix.starts_with('/') {
            if let Some(parent) = &from.parent {
                return Resource::get_resource_ref(parent, &[from.suffix(), suffix].concat());
            }
        }
        // do not use recursion as the tree may have arbitrary depth
        while let Some((chunk, rest)) = Self::split_first_chunk(suffix) {
            (from, suffix) = (from.children.get(chunk)?, rest);
        }
        Some(from)
    }

    #[inline]
    pub fn get_resource(from: &Arc<Resource>, suffix: &str) -> Option<Arc<Resource>> {
        Self::get_resource_ref(from, suffix).cloned()
    }

    /// Split the suffix at the next '/' (after leading one), returning None if the suffix is empty.
    ///
    /// Suffix usually starts with '/', so this first slash is kept as part of the split chunk.
    /// The rest will contain the slash of the split.
    /// For example `split_first_chunk("/a/b") == Some(("/a", "/b"))`.
    #[inline(always)]
    fn split_first_chunk(suffix: &str) -> Option<(&str, &str)> {
        if suffix.is_empty() {
            return None;
        }
        // Skip the first character (possibly '/'), at a UTF-8 boundary.
        let first_len = suffix.chars().next()?.len_utf8();
        Some(match suffix[first_len..].find('/') {
            Some(idx) => suffix.split_at(idx + first_len),
            None => (suffix, ""),
        })
    }

    #[inline]
    pub fn decl_key(res: &Arc<Resource>, face: &mut Arc<FaceState>) -> WireExpr<'static> {
        if face.is_local {
            return res.expr().to_string().into();
        }

        let (nonwild_prefix, wildsuffix) = Resource::nonwild_prefix(res);
        match nonwild_prefix {
            Some(mut nonwild_prefix) => {
                if let Some(ctx) = get_mut_unchecked(&mut nonwild_prefix)
                    .face_ctxs
                    .get(&face.id)
                {
                    if let Some(expr_id) = ctx.remote_expr_id {
                        return WireExpr {
                            scope: expr_id,
                            suffix: wildsuffix.into(),
                            mapping: Mapping::Receiver,
                        };
                    }
                    if let Some(expr_id) = ctx.local_expr_id {
                        return WireExpr {
                            scope: expr_id,
                            suffix: wildsuffix.into(),
                            mapping: Mapping::Sender,
                        };
                    }
                }
                if face.region.bound().is_north()
                    || face.remote_key_interests.values().any(|res| {
                        res.as_ref()
                            .map(|res| res.matches(&nonwild_prefix))
                            .unwrap_or(true)
                    })
                {
                    let ctx = get_mut_unchecked(&mut nonwild_prefix)
                        .face_ctxs
                        .entry(face.id)
                        .or_insert_with(|| Arc::new(FaceContext::new(face.clone())));
                    let expr_id = face.get_next_local_id();
                    get_mut_unchecked(ctx).local_expr_id = Some(expr_id);
                    get_mut_unchecked(face)
                        .local_mappings
                        .insert(expr_id, nonwild_prefix.clone());
                    face.primitives.send_declare(RoutingContext::with_expr(
                        &mut Declare {
                            interest_id: None,
                            ext_qos: declare::ext::QoSType::DECLARE,
                            ext_tstamp: None,
                            ext_nodeid: declare::ext::NodeIdType::DEFAULT,
                            body: DeclareBody::DeclareKeyExpr(DeclareKeyExpr {
                                id: expr_id,
                                wire_expr: nonwild_prefix.expr().to_string().into(),
                            }),
                        },
                        nonwild_prefix.expr().to_string(),
                    ));
                    face.update_interceptors_caches(&mut nonwild_prefix);
                    WireExpr {
                        scope: expr_id,
                        suffix: wildsuffix.into(),
                        mapping: Mapping::Sender,
                    }
                } else {
                    res.expr().to_string().into()
                }
            }
            None => wildsuffix.into(),
        }
    }

    /// Return the best locally/remotely declared keyexpr, i.e. with the smallest suffix, matching
    /// the given suffix and session id.
    ///
    /// The goal is to save bandwidth by using the shortest keyexpr on the wire. It works by
    /// recursively walk through the children tree, looking for an already declared keyexpr for the
    /// session.
    /// If none is found, and if the tested resource itself doesn't have a declared keyexpr,
    /// then the parent tree is walked through. If there is still no declared keyexpr, the whole
    /// prefix+suffix string is used.
    pub fn get_best_key<'a>(&self, suffix: &'a str, sid: usize) -> WireExpr<'a> {
        /// Retrieve a declared keyexpr, either local or remote.
        fn get_wire_expr<'a>(
            prefix: &Resource,
            suffix: impl FnOnce() -> Cow<'a, str>,
            sid: usize,
        ) -> Option<WireExpr<'a>> {
            let ctx = prefix.face_ctxs.get(&sid)?;
            let (scope, mapping) = match (ctx.remote_expr_id, ctx.local_expr_id) {
                (Some(expr_id), _) => (expr_id, Mapping::Receiver),
                (_, Some(expr_id)) => (expr_id, Mapping::Sender),
                _ => return None,
            };
            Some(WireExpr {
                scope,
                suffix: suffix(),
                mapping,
            })
        }
        /// Walk through the children tree, looking for a declared keyexpr.
        fn get_best_child_key<'a>(
            mut prefix: &Resource,
            suffix: &'a str,
            sid: usize,
        ) -> Option<WireExpr<'a>> {
            let mut suffix_rest = suffix;
            // do not use recursion as the tree may have arbitrary depth
            // first we get the closest matching child
            while let Some((chunk, rest)) = Resource::split_first_chunk(suffix_rest) {
                match prefix.children.get(chunk) {
                    Some(child) => prefix = child,
                    None => break,
                }
                suffix_rest = rest;
            }
            // then we go backward checking the child and its parents
            while suffix_rest != suffix {
                if let Some(wire_expr) = get_wire_expr(prefix, || suffix_rest.into(), sid) {
                    return Some(wire_expr);
                }
                suffix_rest = &suffix[suffix.len() - suffix_rest.len() - prefix.suffix().len()..];
                prefix = prefix.parent.as_ref().unwrap();
            }
            None
        }
        /// Walk through the parent tree, looking for a declared keyexpr.
        fn get_best_parent_key<'a>(
            prefix: &Resource,
            suffix: &'a str,
            sid: usize,
            mut parent: &Resource,
        ) -> Option<WireExpr<'a>> {
            // do not use recursion as the tree may have arbitrary depth
            loop {
                let parent_suffix = || [&prefix.expr[parent.expr.len()..], suffix].concat().into();
                if let Some(wire_expr) = get_wire_expr(parent, parent_suffix, sid) {
                    return Some(wire_expr);
                }
                {
                    let p = parent.parent.as_ref()?;
                    parent = p
                }
            }
        }
        get_best_child_key(self, suffix, sid)
            .or_else(|| get_wire_expr(self, || suffix.into(), sid))
            .or_else(|| get_best_parent_key(self, suffix, sid, self.parent.as_ref()?))
            .unwrap_or_else(|| [&self.expr, suffix].concat().into())
    }

    pub fn get_matches(tables: &TablesData, key_expr: &keyexpr) -> Vec<Weak<Resource>> {
        pub fn visit_nodes<T>(node: T, mut visit: impl FnMut(T, &mut VecDeque<T>)) {
            let mut nodes = VecDeque::from([node]);
            while let Some(node) = nodes.pop_front() {
                visit(node, &mut nodes);
            }
        }
        fn get_matches_from(
            key_expr: &keyexpr,
            from: &Arc<Resource>,
            matches: &mut Vec<Weak<Resource>>,
        ) {
            visit_nodes((key_expr, from), |(key_expr, from), nodes| {
                if from.parent.is_none() || from.suffix() == "/" {
                    for child in from.children.iter() {
                        nodes.push_back((key_expr, child));
                    }
                    return;
                }
                let suffix: &keyexpr = from
                    .suffix()
                    .strip_prefix('/')
                    .unwrap_or(from.suffix())
                    .try_into()
                    .unwrap();
                let (ke_chunk, ke_rest) = match key_expr.split_once('/') {
                    // SAFETY: chunks of keyexpr are valid keyexprs
                    Some((chunk, rest)) => unsafe {
                        (
                            keyexpr::from_str_unchecked(chunk),
                            Some(keyexpr::from_str_unchecked(rest)),
                        )
                    },
                    None => (key_expr, None),
                };
                let ke_chunk_intersects_suffix = ke_chunk.intersects(suffix);
                let ke_chunk_is_wild = ke_chunk.as_bytes() == b"**";
                let suffix_is_wild = suffix.as_bytes() == b"**";
                match ke_rest {
                    None => {
                        if ke_chunk_intersects_suffix {
                            if from.ctx.is_some() {
                                matches.push(Arc::downgrade(from));
                            }
                            if let Some(child) =
                                from.children.get("/**").or_else(|| from.children.get("**"))
                            {
                                if child.ctx.is_some() {
                                    matches.push(Arc::downgrade(child))
                                }
                            }
                        }
                        if (ke_chunk_is_wild && ke_chunk_intersects_suffix) || suffix_is_wild {
                            for child in from.children.iter() {
                                nodes.push_back((key_expr, child));
                            }
                        }
                    }
                    Some(rest) => {
                        if ke_chunk_intersects_suffix
                            && rest.as_bytes() == b"**"
                            && from.ctx.is_some()
                        {
                            matches.push(Arc::downgrade(from));
                        }
                        for child in from.children.iter() {
                            if (ke_chunk_is_wild && ke_chunk_intersects_suffix) || suffix_is_wild {
                                nodes.push_back((key_expr, child));
                            } else if ke_chunk_intersects_suffix {
                                nodes.push_back((rest, child));
                            }
                        }
                        if (suffix_is_wild && ke_chunk_intersects_suffix) || ke_chunk_is_wild {
                            nodes.push_back((rest, from));
                        }
                    }
                };
            })
        }
        let mut matches = Vec::new();
        get_matches_from(key_expr, &tables.root_res, &mut matches);
        matches.sort_unstable_by_key(Weak::as_ptr);
        matches.dedup_by_key(|res| Weak::as_ptr(res));
        matches
    }

    pub fn match_resource(
        _tables: &TablesData,
        res: &mut Arc<Resource>,
        mut matches: Vec<Weak<Resource>>,
    ) -> bool {
        if res.ctx.is_none() {
            tracing::error!("Call match_resource() on context less res {}", res.expr());
            return false;
        }
        matches.retain(|r| r.strong_count() > 0);
        matches.sort_unstable_by_key(Weak::as_ptr);
        matches.dedup_by_key(|r| Weak::as_ptr(r));
        #[cfg(feature = "zenss-route-gate")]
        let reservations = if let Some(budget) = &_tables.native_resource_budget {
            // Both directions are one allocation caused by this exact resource.
            // Existing wildcard resources do not become control identities.
            let capacity = resource_capacity(_tables, res.expr());
            let Some(own) = budget.reserve_for(
                NativeResourceUsage {
                    matches: matches.len(),
                    ..Default::default()
                },
                capacity,
            ) else {
                return false;
            };
            let mut backlinks = Vec::new();
            for _ in &matches {
                let Some(backlink) = budget.reserve_for(
                    NativeResourceUsage {
                        matches: 1,
                        ..Default::default()
                    },
                    capacity,
                ) else {
                    return false;
                };
                backlinks.push(backlink);
            }
            Some((own, backlinks))
        } else {
            None
        };
        #[cfg(feature = "zenss-route-gate")]
        let (own, mut backlinks) = match reservations {
            Some((own, backlinks)) => (Some(own), backlinks.into_iter()),
            None => (None, Vec::new().into_iter()),
        };
        for match_ in &matches {
            let mut match_ = match_.upgrade().unwrap();
            let ctx = get_mut_unchecked(&mut match_).context_mut();
            ctx.matches.push(Arc::downgrade(res));
            #[cfg(feature = "zenss-route-gate")]
            if let Some(backlink) = backlinks.next() {
                if let Some(reservation) = &mut ctx.native_match_reservation {
                    reservation.merge_matches(backlink);
                } else {
                    ctx.native_match_reservation = Some(backlink);
                }
            }
        }
        let ctx = get_mut_unchecked(res).context_mut();
        ctx.matches = matches;
        #[cfg(feature = "zenss-route-gate")]
        {
            ctx.native_match_reservation = own;
        }
        true
    }

    pub fn upgrade_resource(res: &mut Arc<Resource>, hat: RegionMap<HatResourceContext>) {
        if res.ctx.is_none() {
            get_mut_unchecked(res).ctx = Some(Box::new(ResourceContext::new(hat)));
        }
    }

    pub(crate) fn get_ingress_cache(
        &self,
        face: &Face,
        interceptor: &InterceptorsChain,
    ) -> Option<InterceptorCacheValueType> {
        self.face_ctxs
            .get(&face.state.id)
            .and_then(|ctx| ctx.in_interceptor_cache.value(interceptor, self))
    }

    pub(crate) fn get_egress_cache(
        &self,
        face: &Face,
        interceptor: &InterceptorsChain,
    ) -> Option<InterceptorCacheValueType> {
        self.face_ctxs
            .get(&face.state.id)
            .and_then(|ctx| ctx.e_interceptor_cache.value(interceptor, self))
    }
}

pub(crate) fn register_expr(
    tables: &TablesLock,
    face: &mut Arc<FaceState>,
    expr_id: ExprId,
    expr: &WireExpr,
) {
    let rtables = zread!(tables.tables);
    match rtables
        .data
        .get_mapping(face, &expr.scope, expr.mapping)
        .cloned()
    {
        Some(mut prefix) => match face.remote_mappings.get(&expr_id) {
            Some(res) => {
                let mut fullexpr = prefix.expr().to_string();
                fullexpr.push_str(expr.suffix.as_ref());
                if res.expr() != fullexpr {
                    tracing::error!(
                        "{} Resource {} remapped. Remapping unsupported!",
                        face,
                        expr_id
                    );
                }
            }
            None => {
                let res = Resource::get_resource(&prefix, &expr.suffix);
                let (mut res, mut wtables) =
                    if res.as_ref().map(|r| r.ctx.is_some()).unwrap_or(false) {
                        drop(rtables);
                        let wtables = zwrite!(tables.tables);
                        (res.unwrap(), wtables)
                    } else {
                        let mut fullexpr = prefix.expr().to_string();
                        fullexpr.push_str(expr.suffix.as_ref());
                        let mut matches = keyexpr::new(fullexpr.as_str())
                            .map(|ke| Resource::get_matches(&rtables.data, ke))
                            .unwrap_or_default();
                        drop(rtables);
                        let mut wtables = zwrite!(tables.tables);
                        let Some(mut res) = Resource::make_resource(
                            &mut wtables,
                            &mut prefix,
                            expr.suffix.as_ref(),
                        ) else {
                            return;
                        };
                        matches.push(Arc::downgrade(&res));
                        if !Resource::match_resource(&wtables.data, &mut res, matches) {
                            Resource::clean(&mut res);
                            return;
                        }
                        (res, wtables)
                    };
                let ctx = get_mut_unchecked(&mut res)
                    .face_ctxs
                    .entry(face.id)
                    .or_insert_with(|| Arc::new(FaceContext::new(face.clone())));

                get_mut_unchecked(ctx).remote_expr_id = Some(expr_id);

                get_mut_unchecked(face)
                    .remote_mappings
                    .insert(expr_id, res.clone());

                let tables = &mut *wtables;
                let hats = &mut tables.hats;
                let region = face.region;

                hats[region].disable_data_routes(&mut res);
                hats[region].disable_query_routes(&mut res);

                face.update_interceptors_caches(&mut res);
                drop(wtables);
            }
        },
        None => tracing::error!(
            "{} Declare resource with unknown scope {}!",
            face,
            expr.scope
        ),
    }
}

pub(crate) fn unregister_expr(tables: &TablesLock, face: &mut Arc<FaceState>, expr_id: ExprId) {
    let mut wtables = zwrite!(tables.tables);

    let tables = &mut *wtables;
    let hats = &mut tables.hats;
    let region = face.region;

    match get_mut_unchecked(face).remote_mappings.remove(&expr_id) {
        Some(mut res) => {
            if let Some(ctx) = get_mut_unchecked(&mut res).face_ctxs.get_mut(&face.id) {
                get_mut_unchecked(ctx).remote_expr_id = None;
            }
            hats[region].disable_data_routes(&mut res);
            hats[region].disable_query_routes(&mut res);
            face.update_interceptors_caches(&mut res);
            Resource::clean(&mut res);
        }
        None => tracing::error!("{} Undeclare unknown resource!", face),
    }

    drop(wtables);
}

pub(crate) fn register_expr_interest(
    tables: &TablesLock,
    face: &mut Arc<FaceState>,
    id: InterestId,
    expr: Option<&WireExpr>,
) -> bool {
    register_expr_interest_for(tables, face, id, expr, InterestOptions::KEYEXPRS)
}

pub(crate) fn register_expr_interest_for(
    tables: &TablesLock,
    face: &mut Arc<FaceState>,
    id: InterestId,
    expr: Option<&WireExpr>,
    options: InterestOptions,
) -> bool {
    // Caller holds ctrl_lock. Reserve a new slot before touching the resource tree;
    // duplicates keep their existing permit, including when the budget is full.
    let mut reserved = if face.remote_key_interests.contains_key(&id) {
        None
    } else {
        let Some(state) = super::interests::KeyInterestState::reserve(face, expr, options) else {
            return false;
        };
        Some(state)
    };
    let rtables = zread!(tables.tables);
    let (res, _wtables) = if let Some(expr) = expr {
        let Some(mut prefix) = rtables
            .data
            .get_mapping(face, &expr.scope, expr.mapping)
            .cloned()
        else {
            tracing::error!(
                "{} Declare keyexpr interest with unknown scope {}!",
                face,
                expr.scope
            );
            return false;
        };
        let res = Resource::get_resource(&prefix, &expr.suffix);
        if res.as_ref().is_some_and(|r| r.ctx.is_some()) {
            drop(rtables);
            (res, zwrite!(tables.tables))
        } else {
            let mut fullexpr = prefix.expr().to_string();
            fullexpr.push_str(expr.suffix.as_ref());
            let Ok(ke) = keyexpr::new(fullexpr.as_str()) else {
                return false;
            };
            let mut matches = Resource::get_matches(&rtables.data, ke);
            drop(rtables);
            let mut wtables = zwrite!(tables.tables);
            let Some(mut res) =
                Resource::make_resource(&mut wtables, &mut prefix, expr.suffix.as_ref())
            else {
                return false;
            };
            matches.push(Arc::downgrade(&res));
            if !Resource::match_resource(&wtables.data, &mut res, matches) {
                Resource::clean(&mut res);
                return false;
            }
            (Some(res), wtables)
        }
    } else {
        drop(rtables);
        (None, zwrite!(tables.tables))
    };
    if let Some(state) = get_mut_unchecked(face).remote_key_interests.get_mut(&id) {
        // Do not replace the old resource until all admission checks succeeded.
        let old = std::mem::replace(&mut state.res, res);
        if let Some(mut old) = old {
            Resource::clean(&mut old);
        }
    } else {
        let mut state = reserved.take().expect("new key interest has a reservation");
        state.res = res;
        get_mut_unchecked(face)
            .remote_key_interests
            .insert(id, state);
    }
    true
}

#[cfg(all(test, feature = "zenss-route-gate"))]
mod native_resource_tests {
    use super::*;
    use crate::net::routing::interceptor::route_gate::QueryCapacity;
    use crate::net::routing::interceptor::route_gate::{RouteGate, RouteRequest, RouteSubject};
    use crate::net::runtime::RuntimeBuilder;
    const CONTROL_KEY: &str = "trusted/exact/control";
    struct Controlled;
    impl RouteGate for Controlled {
        fn resource_capacity(&self, key: &str) -> QueryCapacity {
            if key == CONTROL_KEY {
                QueryCapacity::Control
            } else {
                QueryCapacity::Business
            }
        }
        fn authorize(&self, _: &RouteSubject, _: &RouteRequest<'_>) -> bool {
            true
        }
    }

    #[test]
    fn shared_resource_reserve_preserves_each_dimension_and_absolute_cap() {
        for (business, total) in [
            (
                NativeResourceUsage {
                    nodes: BUSINESS_RESOURCE_NODES,
                    ..Default::default()
                },
                NativeResourceUsage {
                    nodes: RESOURCE_NODES,
                    ..Default::default()
                },
            ),
            (
                NativeResourceUsage {
                    contexts: BUSINESS_RESOURCE_CONTEXTS,
                    ..Default::default()
                },
                NativeResourceUsage {
                    contexts: RESOURCE_CONTEXTS,
                    ..Default::default()
                },
            ),
            (
                NativeResourceUsage {
                    bytes: BUSINESS_RESOURCE_EXPR_BYTES,
                    ..Default::default()
                },
                NativeResourceUsage {
                    bytes: RESOURCE_EXPR_BYTES,
                    ..Default::default()
                },
            ),
            (
                NativeResourceUsage {
                    matches: BUSINESS_RESOURCE_MATCH_EDGES,
                    ..Default::default()
                },
                NativeResourceUsage {
                    matches: RESOURCE_MATCH_EDGES,
                    ..Default::default()
                },
            ),
        ] {
            let budget = Arc::new(NativeResourceBudget::default());
            let held = budget.reserve(business).unwrap();
            let unit = NativeResourceUsage {
                nodes: usize::from(total.nodes > 0),
                contexts: usize::from(total.contexts > 0),
                bytes: usize::from(total.bytes > 0),
                matches: usize::from(total.matches > 0),
                ..Default::default()
            };
            assert!(budget.reserve(unit).is_none());
            let reserved = NativeResourceUsage {
                nodes: total.nodes - business.nodes,
                contexts: total.contexts - business.contexts,
                bytes: total.bytes - business.bytes,
                matches: total.matches - business.matches,
                ..Default::default()
            };
            let control = budget
                .reserve_for(reserved, QueryCapacity::Control)
                .unwrap();
            assert!(budget.reserve_for(unit, QueryCapacity::Control).is_none());
            drop(control);
            let fresh = budget.reserve_for(unit, QueryCapacity::Control).unwrap();
            drop(fresh);
            drop(held);
            let recovered = budget.reserve(unit).unwrap();
            assert!(budget
                .reserve_for(
                    NativeResourceUsage {
                        nodes: usize::MAX,
                        ..Default::default()
                    },
                    QueryCapacity::Control
                )
                .is_none());
            drop(recovered);
            let current = budget.0.lock().unwrap();
            assert_eq!(
                (
                    current.nodes,
                    current.contexts,
                    current.bytes,
                    current.matches
                ),
                (0, 0, 0, 0)
            );
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn trusted_control_tree_and_matches_admit_atomically_under_business_pressure() {
        let config =
            crate::Config::from_json5(r#"{mode:"router",scouting:{multicast:{enabled:false}}}"#)
                .unwrap();
        let router = RuntimeBuilder::new(config).build().await.unwrap();
        router.install_route_gate(Arc::new(Controlled)).unwrap();
        let gateway = router.router();
        let mut tables = gateway.tables.tables.write().unwrap();
        let budget = tables.data.native_resource_budget.clone().unwrap();
        let mut root = tables.data.root_res.clone();
        let mut wildcard = Resource::make_resource(&mut tables, &mut root, "**").unwrap();
        let current = *budget.0.lock().unwrap();
        let held = budget
            .reserve(NativeResourceUsage {
                nodes: BUSINESS_RESOURCE_NODES - current.nodes,
                contexts: BUSINESS_RESOURCE_CONTEXTS - current.contexts,
                bytes: BUSINESS_RESOURCE_EXPR_BYTES - current.bytes,
                matches: BUSINESS_RESOURCE_MATCH_EDGES,
                ..Default::default()
            })
            .unwrap();
        for key in [
            "trusted/exact/ordinary",
            "trusted/exact",
            "trusted/exact/control/forged",
        ] {
            assert!(Resource::make_resource(&mut tables, &mut root, key).is_none());
            assert!(Resource::get_resource(&root, "trusted").is_none());
        }
        let mut control = Resource::make_resource(&mut tables, &mut root, CONTROL_KEY).unwrap();
        assert_eq!(budget.0.lock().unwrap().nodes, BUSINESS_RESOURCE_NODES + 3);
        // Exact shared resource reuse adds no nodes or contexts.
        let reused = Resource::make_resource(&mut tables, &mut root, CONTROL_KEY).unwrap();
        assert!(Arc::ptr_eq(&control, &reused));
        drop(reused);
        let remaining = budget
            .reserve_for(
                NativeResourceUsage {
                    matches: RESOURCE_MATCH_EDGES - BUSINESS_RESOURCE_MATCH_EDGES - 1,
                    ..Default::default()
                },
                QueryCapacity::Control,
            )
            .unwrap();
        assert!(!Resource::match_resource(
            &tables.data,
            &mut control,
            vec![Arc::downgrade(&wildcard)]
        ));
        assert!(control.ctx.as_ref().unwrap().matches.is_empty());
        assert!(wildcard.ctx.as_ref().unwrap().matches.is_empty());
        assert_eq!(budget.0.lock().unwrap().matches, RESOURCE_MATCH_EDGES - 1);
        drop(remaining);
        assert!(Resource::match_resource(
            &tables.data,
            &mut control,
            vec![Arc::downgrade(&wildcard)]
        ));
        assert_eq!(
            budget.0.lock().unwrap().matches,
            BUSINESS_RESOURCE_MATCH_EDGES + 2
        );
        drop(tables);
        gateway
            .tables
            .update_config(&router.config().lock().clone())
            .unwrap();
        let tables = gateway.tables.tables.write().unwrap();
        assert!(Arc::ptr_eq(
            &budget,
            tables.data.native_resource_budget.as_ref().unwrap()
        ));
        Resource::clean(&mut control);
        drop(control);
        Resource::clean(&mut wildcard);
        drop(wildcard);
        assert_eq!(
            budget.0.lock().unwrap().matches,
            BUSINESS_RESOURCE_MATCH_EDGES
        );
        drop(held);
        assert_eq!(budget.0.lock().unwrap().nodes, 0);
        assert_eq!(budget.0.lock().unwrap().contexts, 0);
        assert_eq!(budget.0.lock().unwrap().bytes, 0);
        assert_eq!(budget.0.lock().unwrap().matches, 0);
        drop(tables);
        router.close().await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn control_declared_after_business_tree_pressure_serves_real_tcp_query() {
        use std::time::Duration;
        let config = crate::Config::from_json5(r#"{mode:"router",listen:{endpoints:["tcp/127.0.0.1:0"]},scouting:{multicast:{enabled:false}}}"#).unwrap();
        let mut router = RuntimeBuilder::new(config).build().await.unwrap();
        router.install_route_gate(Arc::new(Controlled)).unwrap();
        router.start().await.unwrap();
        let platform = crate::session::init(router.clone().into()).await.unwrap();
        let config = crate::Config::from_json5(&format!(r#"{{mode:"client",connect:{{endpoints:["{}"]}},scouting:{{multicast:{{enabled:false}}}}}}"#, router.get_locators()[0])).unwrap();
        let client = crate::open(config).await.unwrap();
        let gateway = router.router();
        let budget = gateway
            .tables
            .tables
            .read()
            .unwrap()
            .data
            .native_resource_budget
            .clone()
            .unwrap();
        let current = *budget.0.lock().unwrap();
        let held = budget
            .reserve(NativeResourceUsage {
                nodes: BUSINESS_RESOURCE_NODES - current.nodes,
                contexts: BUSINESS_RESOURCE_CONTEXTS - current.contexts,
                bytes: BUSINESS_RESOURCE_EXPR_BYTES - current.bytes,
                matches: BUSINESS_RESOURCE_MATCH_EDGES - current.matches,
                ..Default::default()
            })
            .unwrap();
        let control = platform.declare_queryable(CONTROL_KEY).await.unwrap();
        let replies = client
            .get(CONTROL_KEY)
            .timeout(Duration::from_secs(2))
            .await
            .unwrap();
        let query = tokio::time::timeout(Duration::from_secs(2), control.recv_async())
            .await
            .unwrap()
            .unwrap();
        query
            .reply(CONTROL_KEY, "control available after pressure")
            .await
            .unwrap();
        drop(query);
        assert!(
            tokio::time::timeout(Duration::from_secs(2), replies.recv_async())
                .await
                .unwrap()
                .unwrap()
                .result()
                .is_ok()
        );
        // Disconnect and undeclare must release the newly created shared records.
        client.close().await.unwrap();
        control.undeclare().await.unwrap();
        drop(held);
        platform.close().await.unwrap();
        router.close().await.unwrap();
        let current = budget.0.lock().unwrap();
        assert_eq!(
            (
                current.nodes,
                current.contexts,
                current.bytes,
                current.matches
            ),
            (0, 0, 0, 0)
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn resource_capacity_rejects_wildcards_and_gate_panics() {
        struct Untrusted;
        impl RouteGate for Untrusted {
            fn resource_capacity(&self, key: &str) -> QueryCapacity {
                if key == "panic" {
                    panic!("injected classifier panic");
                }
                QueryCapacity::Control
            }
            fn authorize(&self, _: &RouteSubject, _: &RouteRequest<'_>) -> bool {
                true
            }
        }
        let config =
            crate::Config::from_json5(r#"{mode:"router",scouting:{multicast:{enabled:false}}}"#)
                .unwrap();
        let router = RuntimeBuilder::new(config).build().await.unwrap();
        router.install_route_gate(Arc::new(Untrusted)).unwrap();
        let gateway = router.router();
        {
            let tables = gateway.tables.tables.read().unwrap();
            for key in ["", "a/**", "a/*/control", "a//b", "panic"] {
                assert_eq!(
                    resource_capacity(&tables.data, key),
                    QueryCapacity::Business
                );
            }
            assert_eq!(
                resource_capacity(&tables.data, CONTROL_KEY),
                QueryCapacity::Control
            );
        }
        router.close().await.unwrap();
    }

    struct Allow;
    impl RouteGate for Allow {
        fn authorize(&self, _: &RouteSubject, _: &RouteRequest<'_>) -> bool {
            true
        }
    }

    #[test]
    fn sparse_route_ids_and_per_map_pressure_preserve_uncached_results() {
        let budget = Arc::new(NativeResourceBudget::default());
        let routes = RwLock::new(DataRoutes::default());
        let region = Region::South {
            id: usize::MAX,
            mode: zenoh_config::WhatAmI::Router,
        };
        let expected = Arc::new(Route::new());
        let first = get_or_set_route(
            &routes,
            1,
            &region,
            NodeId::MAX,
            || expected.clone(),
            Some(&budget),
        );
        assert!(Arc::ptr_eq(&first, &expected));
        assert_eq!(routes.read().unwrap().mapping.len(), 1);
        let hit = get_or_set_route(
            &routes,
            1,
            &region,
            NodeId::MAX,
            || panic!("sparse ID should hit cache"),
            Some(&budget),
        );
        assert!(Arc::ptr_eq(&hit, &expected));
        for id in 0..ROUTE_CACHE_PER_MAP - 1 {
            get_or_set_route(
                &routes,
                1,
                &region,
                id as NodeId,
                || expected.clone(),
                Some(&budget),
            );
        }
        let calls = std::cell::Cell::new(0);
        for _ in 0..2 {
            let result = get_or_set_route(
                &routes,
                1,
                &region,
                500,
                || {
                    calls.set(calls.get() + 1);
                    expected.clone()
                },
                Some(&budget),
            );
            assert!(Arc::ptr_eq(&result, &expected));
        }
        assert_eq!(calls.get(), 2);
        assert_eq!(budget.0.lock().unwrap().cache_entries, ROUTE_CACHE_PER_MAP);
        // New version drops stale reservations and allows new routing to cache.
        get_or_set_route(&routes, 2, &region, 500, || expected.clone(), Some(&budget));
        assert_eq!(routes.read().unwrap().mapping.len(), 1);
        assert!(routes
            .read()
            .unwrap()
            .get_route(1, &region, NodeId::MAX)
            .is_none());
        assert_eq!(budget.0.lock().unwrap().cache_entries, 1);
        routes.write().unwrap().clear();
        assert_eq!(budget.0.lock().unwrap().cache_entries, 0);
        assert_eq!(budget.0.lock().unwrap().cache_bytes, 0);
    }

    #[test]
    fn runtime_cache_entries_are_shared_across_data_query_and_hats() {
        let budget = Arc::new(NativeResourceBudget::default());
        let expected = Arc::new(Route::new());
        let mut retained = Vec::new();
        for _ in 0..ROUTE_CACHE_ENTRIES / ROUTE_CACHE_PER_MAP {
            let mut cache = DataRoutes::default();
            for id in 0..ROUTE_CACHE_PER_MAP {
                cache.set_route(
                    1,
                    &Region::North,
                    id as NodeId,
                    expected.clone(),
                    Some(&budget),
                );
            }
            retained.push(cache);
        }
        assert_eq!(budget.0.lock().unwrap().cache_entries, ROUTE_CACHE_ENTRIES);
        let queries = RwLock::new(QueryRoutes::default());
        let result = Arc::new(QueryTargetQablSet::new());
        let uncached = get_or_set_route(
            &queries,
            1,
            &Region::Local,
            0,
            || result.clone(),
            Some(&budget),
        );
        assert!(Arc::ptr_eq(&uncached, &result));
        assert!(queries.read().unwrap().mapping.is_empty());
        retained.pop();
        get_or_set_route(
            &queries,
            1,
            &Region::Local,
            0,
            || result.clone(),
            Some(&budget),
        );
        assert_eq!(queries.read().unwrap().mapping.len(), 1);
        drop((retained, queries));
        assert_eq!(budget.0.lock().unwrap().cache_entries, 0);
        assert_eq!(budget.0.lock().unwrap().cache_bytes, 0);
    }

    #[test]
    fn cache_byte_pressure_accounts_vector_capacity_and_reclaims_on_drop() {
        let budget = Arc::new(NativeResourceBudget::default());
        // Empty routes can retain allocated direction storage: length alone is insufficient.
        let route = Arc::new(Route::with_capacity(
            ROUTE_CACHE_BYTES / std::mem::size_of::<Direction>(),
        ));
        let routes = RwLock::new(DataRoutes::default());
        let returned = get_or_set_route(
            &routes,
            1,
            &Region::Local,
            0,
            || route.clone(),
            Some(&budget),
        );
        assert!(Arc::ptr_eq(&returned, &route));
        assert!(routes.read().unwrap().mapping.is_empty());
        assert_eq!(budget.0.lock().unwrap().cache_bytes, 0);
        let smaller = Arc::new(Route::with_capacity(
            ROUTE_CACHE_BYTES / 2 / std::mem::size_of::<Direction>(),
        ));
        get_or_set_route(
            &routes,
            1,
            &Region::Local,
            1,
            || smaller.clone(),
            Some(&budget),
        );
        assert!(budget.0.lock().unwrap().cache_bytes > smaller.retained_bytes());
        let queries = RwLock::new(QueryRoutes::default());
        let large_query = Arc::new(QueryTargetQablSet::with_capacity(
            ROUTE_CACHE_BYTES / 2 / std::mem::size_of::<QueryTargetQabl>(),
        ));
        get_or_set_route(
            &queries,
            1,
            &Region::Local,
            1,
            || large_query.clone(),
            Some(&budget),
        );
        assert!(queries.read().unwrap().mapping.is_empty());
        drop(routes);
        assert_eq!(budget.0.lock().unwrap().cache_bytes, 0);
        get_or_set_route(
            &queries,
            1,
            &Region::Local,
            1,
            || large_query.clone(),
            Some(&budget),
        );
        assert_eq!(queries.read().unwrap().mapping.len(), 1);
        drop(queries);
        assert_eq!(budget.0.lock().unwrap().cache_bytes, 0);
        // Callers still own their transient Arcs; cache accounting is not RSS.
        assert!(!smaller.is_empty() || smaller.capacity() > 0);
    }

    #[test]
    fn actual_allocation_reservations_are_atomic_and_reclaimed() {
        assert_eq!(Resource::split_first_chunk("节点/é"), Some(("节点", "/é")));
        assert_eq!(
            Resource::split_first_chunk("/节点/é"),
            Some(("/节点", "/é"))
        );
        let budget = Arc::new(NativeResourceBudget::default());
        let all_nodes = budget
            .reserve(NativeResourceUsage {
                nodes: BUSINESS_RESOURCE_NODES,
                ..Default::default()
            })
            .unwrap();
        assert!(budget
            .reserve(NativeResourceUsage {
                nodes: 1,
                ..Default::default()
            })
            .is_none());
        let all_bytes = budget
            .reserve(NativeResourceUsage {
                bytes: BUSINESS_RESOURCE_EXPR_BYTES,
                ..Default::default()
            })
            .unwrap();
        assert!(budget
            .reserve(NativeResourceUsage {
                bytes: 1,
                ..Default::default()
            })
            .is_none());
        let all_contexts = budget
            .reserve(NativeResourceUsage {
                contexts: BUSINESS_RESOURCE_CONTEXTS,
                ..Default::default()
            })
            .unwrap();
        assert!(budget
            .reserve(NativeResourceUsage {
                contexts: 1,
                ..Default::default()
            })
            .is_none());
        drop((all_nodes, all_bytes, all_contexts));
        let current = budget.0.lock().unwrap();
        assert_eq!((current.nodes, current.bytes, current.contexts), (0, 0, 0));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn gate_rejects_excessive_region_multiplier_without_installing_budget() {
        for (count, accepted) in [(5usize, false), (4, true)] {
            let config = crate::Config::from_json5(
                &serde_json::json!({
                    "mode":"router", "gateway":{"south":vec![serde_json::json!({});count]},
                    "scouting":{"multicast":{"enabled":false}}
                })
                .to_string(),
            )
            .unwrap();
            let router = RuntimeBuilder::new(config).build().await.unwrap();
            assert_eq!(router.install_route_gate(Arc::new(Allow)).is_ok(), accepted);
            let gateway = router.router();
            {
                let tables = gateway.tables.tables.read().unwrap();
                assert_eq!(tables.data.route_gate.is_some(), accepted);
                assert_eq!(tables.data.native_resource_budget.is_some(), accepted);
                assert_eq!(tables.hats.iter().count(), 2 + 3 * count);
            }
            router.close().await.unwrap();
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn whole_tree_path_is_admitted_atomically_and_survives_reload() {
        let config =
            crate::Config::from_json5(r#"{mode:"router",scouting:{multicast:{enabled:false}}}"#)
                .unwrap();
        let router = RuntimeBuilder::new(config).build().await.unwrap();
        router.install_route_gate(Arc::new(Allow)).unwrap();
        let gateway = router.router();
        let tables_lock = &gateway.tables;
        let mut tables = tables_lock.tables.write().unwrap();
        let budget = tables.data.native_resource_budget.clone().unwrap();
        let mut root = tables.data.root_res.clone();
        let before = budget.0.lock().unwrap().nodes;
        assert_eq!(before, 0);
        let mut retained = Vec::new();
        for id in 0..BUSINESS_RESOURCE_NODES / 8 {
            retained.push(
                Resource::make_resource(&mut tables, &mut root, &format!("n{id}/a/b/c/d/e/f/g"))
                    .unwrap(),
            );
        }
        assert_eq!(budget.0.lock().unwrap().nodes, BUSINESS_RESOURCE_NODES);
        assert!(Resource::make_resource(&mut tables, &mut root, "refused/a/b/c").is_none());
        assert!(Resource::get_resource(&root, "refused").is_none());
        assert_eq!(budget.0.lock().unwrap().nodes, BUSINESS_RESOURCE_NODES);
        drop(tables);
        tables_lock
            .update_config(&router.config().lock().clone())
            .unwrap();
        let mut tables = tables_lock.tables.write().unwrap();
        assert!(Arc::ptr_eq(
            &budget,
            tables.data.native_resource_budget.as_ref().unwrap()
        ));
        assert_eq!(budget.0.lock().unwrap().nodes, BUSINESS_RESOURCE_NODES);
        let mut released = retained.pop().unwrap();
        Resource::clean(&mut released);
        drop(released);
        assert_eq!(budget.0.lock().unwrap().nodes, BUSINESS_RESOURCE_NODES - 8);
        let mut added =
            Resource::make_resource(&mut tables, &mut root, "new/a/b/c/d/e/f/g").unwrap();
        assert_eq!(budget.0.lock().unwrap().nodes, BUSINESS_RESOURCE_NODES);
        assert!(
            Resource::make_resource(&mut tables, &mut root, &vec!["deep"; 65].join("/")).is_none()
        );
        assert!(Resource::get_resource(&root, "deep").is_none());
        Resource::clean(&mut added);
        drop(added);
        for mut res in retained {
            Resource::clean(&mut res);
        }
        assert_eq!(budget.0.lock().unwrap().nodes, 0);
        assert_eq!(budget.0.lock().unwrap().contexts, 0);
        assert_eq!(budget.0.lock().unwrap().bytes, 0);
        drop(tables);
        router.close().await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn installation_accounts_existing_resources_and_prefix_upgrade() {
        let config =
            crate::Config::from_json5(r#"{mode:"router",scouting:{multicast:{enabled:false}}}"#)
                .unwrap();
        let router = RuntimeBuilder::new(config).build().await.unwrap();
        let gateway = router.router();
        let lock = &gateway.tables;
        let mut tables = lock.tables.write().unwrap();
        let mut root = tables.data.root_res.clone();
        let mut res = Resource::make_resource(&mut tables, &mut root, "existing/a/b").unwrap();
        {
            let ctx = res.ctx.as_ref().unwrap();
            ctx.data_routes.write().unwrap().set_route(
                1,
                &Region::Local,
                NodeId::MAX,
                Arc::new(Route::new()),
                None,
            );
            for hat in ctx.hats.values() {
                hat.data_routes.write().unwrap().set_route(
                    1,
                    &Region::Local,
                    NodeId::MAX,
                    Arc::new(Route::new()),
                    None,
                );
                hat.query_routes.write().unwrap().set_route(
                    1,
                    &Region::Local,
                    NodeId::MAX,
                    Arc::new(QueryTargetQablSet::new()),
                    None,
                );
            }
        }
        drop(tables);
        router.install_route_gate(Arc::new(Allow)).unwrap();
        let mut tables = lock.tables.write().unwrap();
        let budget = tables.data.native_resource_budget.clone().unwrap();
        assert_eq!(budget.0.lock().unwrap().nodes, 3);
        assert_eq!(budget.0.lock().unwrap().contexts, 1);
        {
            let ctx = res.ctx.as_ref().unwrap();
            assert!(ctx.data_routes.read().unwrap().mapping.is_empty());
            for hat in ctx.hats.values() {
                assert!(hat.data_routes.read().unwrap().mapping.is_empty());
                assert!(hat.query_routes.read().unwrap().mapping.is_empty());
            }
        }
        let prefix = Resource::make_resource(&mut tables, &mut root, "existing/a").unwrap();
        assert_eq!(budget.0.lock().unwrap().nodes, 3);
        assert_eq!(budget.0.lock().unwrap().contexts, 2);
        // A suffix can complete a partial prefix; charge the resulting full path once.
        let mut partial = Resource::make_resource(&mut tables, &mut root, "part").unwrap();
        let mut completed = Resource::make_resource(&mut tables, &mut partial, "ial/key").unwrap();
        assert_eq!(completed.expr(), "partial/key");
        Resource::clean(&mut completed);
        drop(completed);
        Resource::clean(&mut partial);
        drop(partial);
        drop(prefix); // Original terminal leaf keeps this ancestor alive until cleanup.
        Resource::clean(&mut res);
        drop(res);
        assert_eq!(budget.0.lock().unwrap().nodes, 0);
        assert_eq!(budget.0.lock().unwrap().contexts, 0);
        drop(tables);
        router.close().await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn actual_tree_context_and_string_caps_reject_without_partial_prefixes() {
        let config =
            crate::Config::from_json5(r#"{mode:"router",scouting:{multicast:{enabled:false}}}"#)
                .unwrap();
        let router = RuntimeBuilder::new(config).build().await.unwrap();
        router.install_route_gate(Arc::new(Allow)).unwrap();
        let gateway = router.router();
        let mut tables = gateway.tables.tables.write().unwrap();
        let budget = tables.data.native_resource_budget.clone().unwrap();
        let mut root = tables.data.root_res.clone();
        let mut retained = Vec::new();
        for id in 0..BUSINESS_RESOURCE_CONTEXTS {
            retained.push(
                Resource::make_resource(&mut tables, &mut root, &format!("ctx{id}")).unwrap(),
            );
        }
        assert!(Resource::make_resource(&mut tables, &mut root, "context-refused/a/b").is_none());
        assert!(Resource::get_resource(&root, "context-refused").is_none());
        assert_eq!(budget.0.lock().unwrap().nodes, BUSINESS_RESOURCE_CONTEXTS);
        for mut res in retained.drain(..) {
            Resource::clean(&mut res);
        }
        assert_eq!(budget.0.lock().unwrap().nodes, 0);
        // Long first chunks force many distinct retained ancestor strings, not just leaf bytes.
        for id in 0..BUSINESS_RESOURCE_NODES / 64 {
            let key = format!("{id}{}{}", "x".repeat(1800), "/a".repeat(63));
            if let Some(res) = Resource::make_resource(&mut tables, &mut root, &key) {
                retained.push(res);
            } else {
                let current = budget.0.lock().unwrap();
                assert!(current.bytes <= BUSINESS_RESOURCE_EXPR_BYTES);
                assert!(current.nodes < BUSINESS_RESOURCE_NODES);
                assert!(current.contexts < BUSINESS_RESOURCE_CONTEXTS);
                drop(current);
                assert!(
                    Resource::get_resource(&root, &format!("{id}{}", "x".repeat(1800))).is_none()
                );
                break;
            }
        }
        assert!(!retained.is_empty());
        for mut res in retained {
            Resource::clean(&mut res);
        }
        assert_eq!(budget.0.lock().unwrap().bytes, 0);
        assert_eq!(budget.0.lock().unwrap().nodes, 0);
        drop(tables);
        router.close().await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn overbudget_existing_tree_refuses_gate_installation_without_mutation() {
        let config =
            crate::Config::from_json5(r#"{mode:"router",scouting:{multicast:{enabled:false}}}"#)
                .unwrap();
        let router = RuntimeBuilder::new(config).build().await.unwrap();
        let gateway = router.router();
        let mut tables = gateway.tables.tables.write().unwrap();
        let mut root = tables.data.root_res.clone();
        let mut res =
            Resource::make_resource(&mut tables, &mut root, &vec!["a"; 65].join("/")).unwrap();
        drop(tables);
        assert!(router.install_route_gate(Arc::new(Allow)).is_err());
        let tables = gateway.tables.tables.write().unwrap();
        assert!(tables.data.route_gate.is_none());
        assert!(tables.data.native_resource_budget.is_none());
        assert!(res.native_reservation.is_none());
        Resource::clean(&mut res);
        drop(res);
        drop(tables);
        router.install_route_gate(Arc::new(Allow)).unwrap();
        router.close().await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn remote_tree_pressure_preserves_control_handler_and_releases_on_disconnect() {
        use std::time::Duration;
        let config = crate::Config::from_json5(r#"{mode:"router",listen:{endpoints:["tcp/127.0.0.1:0"]},scouting:{multicast:{enabled:false}}}"#).unwrap();
        let mut router = RuntimeBuilder::new(config).build().await.unwrap();
        router.install_route_gate(Arc::new(Allow)).unwrap();
        router.start().await.unwrap();
        let platform = crate::session::init(router.clone().into()).await.unwrap();
        let control = platform.declare_queryable("control").await.unwrap();
        let mut config = crate::Config::default();
        config.insert_json5("mode", r#""client""#).unwrap();
        config
            .insert_json5("scouting/multicast/enabled", "false")
            .unwrap();
        config
            .insert_json5(
                "connect/endpoints",
                &format!(r#"["{}"]"#, router.get_locators()[0]),
            )
            .unwrap();
        let client = crate::open(config).await.unwrap();
        let mut retained = Vec::new();
        for id in 0..128 {
            retained.push(
                client
                    .declare_queryable(format!("branch{id}{}", "/a".repeat(63)))
                    .await
                    .unwrap(),
            );
        }
        let gateway = router.router();
        let budget = gateway
            .tables
            .tables
            .read()
            .unwrap()
            .data
            .native_resource_budget
            .clone()
            .unwrap();
        for _ in 0..200 {
            if budget.0.lock().unwrap().nodes >= (1 + (BUSINESS_RESOURCE_NODES - 1) / 64 * 64) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(
            budget.0.lock().unwrap().nodes,
            (1 + (BUSINESS_RESOURCE_NODES - 1) / 64 * 64)
        );
        {
            let tables = gateway.tables.tables.read().unwrap();
            assert!(Resource::get_resource(&tables.data.root_res, "branch127").is_none());
        }
        let refused = platform
            .get(format!("branch127{}", "/a".repeat(63)))
            .timeout(Duration::from_millis(100))
            .await
            .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(200), retained[127].recv_async())
                .await
                .is_err()
        );
        drop(refused);
        let replies = client
            .get("control")
            .consolidation(crate::query::ConsolidationMode::None)
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
        client.close().await.unwrap();
        drop(retained);
        for _ in 0..200 {
            if budget.0.lock().unwrap().nodes == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(budget.0.lock().unwrap().nodes, 1);
        assert_eq!(budget.0.lock().unwrap().contexts, 1);
        platform.close().await.unwrap();
        drop(control);
        router.close().await.unwrap();
        assert_eq!(budget.0.lock().unwrap().nodes, 0);
        assert_eq!(budget.0.lock().unwrap().bytes, 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn real_query_reply_and_data_routing_survive_exhausted_cache_budget() {
        use std::time::Duration;
        let config = crate::Config::from_json5(r#"{mode:"router",listen:{endpoints:["tcp/127.0.0.1:0"]},scouting:{multicast:{enabled:false}}}"#).unwrap();
        let mut router = RuntimeBuilder::new(config).build().await.unwrap();
        router.install_route_gate(Arc::new(Allow)).unwrap();
        router.start().await.unwrap();
        let platform = crate::session::init(router.clone().into()).await.unwrap();
        let queryable = platform.declare_queryable("live/query").await.unwrap();
        let subscriber = platform.declare_subscriber("live/data").await.unwrap();
        let config = crate::Config::from_json5(&format!(r#"{{mode:"client",connect:{{endpoints:["{}"]}},scouting:{{multicast:{{enabled:false}}}}}}"#, router.get_locators()[0])).unwrap();
        let client = crate::open(config).await.unwrap();
        let publisher = client.declare_publisher("live/data").await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            while !publisher.matching_status().await.unwrap().matching() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        let gateway = router.router();
        let budget = gateway
            .tables
            .tables
            .read()
            .unwrap()
            .data
            .native_resource_budget
            .clone()
            .unwrap();
        assert_eq!(budget.0.lock().unwrap().cache_entries, 0);
        let mut retained = Vec::new();
        for _ in 0..ROUTE_CACHE_ENTRIES / ROUTE_CACHE_PER_MAP {
            let mut cache = DataRoutes::default();
            for id in 0..ROUTE_CACHE_PER_MAP {
                cache.set_route(
                    1,
                    &Region::North,
                    id as NodeId,
                    Arc::new(Route::new()),
                    Some(&budget),
                );
            }
            retained.push(cache);
        }
        for round in 0..3 {
            let replies = client
                .get("live/query")
                .consolidation(crate::query::ConsolidationMode::None)
                .timeout(Duration::from_secs(1))
                .await
                .unwrap();
            let query = tokio::time::timeout(Duration::from_secs(1), queryable.recv_async())
                .await
                .unwrap()
                .unwrap();
            query.reply("live/query", "still-running").await.unwrap();
            drop(query);
            assert!(
                tokio::time::timeout(Duration::from_secs(1), replies.recv_async())
                    .await
                    .unwrap()
                    .unwrap()
                    .result()
                    .is_ok()
            );
            publisher.put("still-running").await.unwrap();
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(1), subscriber.recv_async())
                    .await
                    .unwrap()
                    .unwrap()
                    .key_expr()
                    .as_str(),
                "live/data"
            );
            if round == 0 {
                assert_eq!(budget.0.lock().unwrap().cache_entries, ROUTE_CACHE_ENTRIES);
                retained.clear();
                assert_eq!(budget.0.lock().unwrap().cache_entries, 0);
                // Reconfiguration keeps this same budget; the next traffic may cache.
                gateway
                    .tables
                    .update_config(&router.config().lock().clone())
                    .unwrap();
                assert!(Arc::ptr_eq(
                    &budget,
                    gateway
                        .tables
                        .tables
                        .read()
                        .unwrap()
                        .data
                        .native_resource_budget
                        .as_ref()
                        .unwrap()
                ));
            } else {
                assert!(budget.0.lock().unwrap().cache_entries > 0);
            }
        }
        client.close().await.unwrap();
        drop(publisher);
        platform.close().await.unwrap();
        drop((queryable, subscriber));
        router.close().await.unwrap();
        assert_eq!(budget.0.lock().unwrap().cache_entries, 0);
        assert_eq!(budget.0.lock().unwrap().cache_bytes, 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn actual_aggregation_pressure_preserves_routes_and_disconnect_reclaims() {
        use super::super::local_resources::{NativeAggregationBudget, NativeAggregationUsage};
        use std::time::Duration;
        for mode in ["router", "peer"] {
            let config = crate::Config::from_json5(&format!(r#"{{mode:"{mode}",listen:{{endpoints:["tcp/127.0.0.1:0"]}},scouting:{{multicast:{{enabled:false}}}}}}"#)).unwrap();
            let mut router = RuntimeBuilder::new(config).build().await.unwrap();
            router.install_route_gate(Arc::new(Allow)).unwrap();
            router.start().await.unwrap();
            let platform = crate::session::init(router.clone().into()).await.unwrap();
            let control = platform.declare_queryable("control").await.unwrap();
            let subscriber = platform.declare_subscriber("data").await.unwrap();
            let config = crate::Config::from_json5(&format!(r#"{{mode:"client",connect:{{endpoints:["{}"]}},scouting:{{multicast:{{enabled:false}}}}}}"#, router.get_locators()[0])).unwrap();
            let client = crate::open(config).await.unwrap();
            let querier = client.declare_querier("**").await.unwrap();
            let query_matches = querier.matching_listener().await.unwrap();
            let publisher = client.declare_publisher("data").await.unwrap();
            let subscriber_matches = publisher.matching_listener().await.unwrap();
            // Installing a subscriber/queryable generates interest projections on the peer/broker face.
            let gateway = router.router();
            let snapshot = || {
                let tables = gateway.tables.tables.read().unwrap();
                let mut total = NativeAggregationUsage::default();
                for face in tables.data.faces.values() {
                    for (_, hat) in tables.hats.iter() {
                        total = total.add(hat.native_aggregation_usage(face));
                    }
                }
                total
            };
            for _ in 0..200 {
                if snapshot().records >= 2 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            let initial = snapshot();
            assert!(
                initial.records >= 2,
                "{mode}: no actual aggregation projections"
            );
            let budget: Arc<NativeAggregationBudget> = gateway
                .tables
                .tables
                .read()
                .unwrap()
                .data
                .native_aggregation_budget
                .clone()
                .unwrap();
            let held = budget
                .reserve(NativeAggregationUsage {
                    records: budget.business_limits().records - initial.records,
                    ..Default::default()
                })
                .unwrap();
            gateway
                .tables
                .update_config(&router.config().lock().clone())
                .unwrap();
            assert!(Arc::ptr_eq(
                &budget,
                gateway
                    .tables
                    .tables
                    .read()
                    .unwrap()
                    .data
                    .native_aggregation_budget
                    .as_ref()
                    .unwrap()
            ));
            let refused = platform.declare_queryable("refused").await.unwrap();
            tokio::time::sleep(Duration::from_millis(50)).await;
            assert_eq!(
                snapshot(),
                initial,
                "{mode}: refused propagation retained partial state"
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
            refused.undeclare().await.unwrap();
            drop(held);
            let recovered = platform.declare_queryable("recovered").await.unwrap();
            for _ in 0..200 {
                if snapshot().records > initial.records {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            assert!(
                snapshot().records > initial.records,
                "{mode}: released capacity unavailable"
            );
            let replies = client
                .get("recovered")
                .timeout(Duration::from_secs(1))
                .await
                .unwrap();
            let query = tokio::time::timeout(Duration::from_millis(500), recovered.recv_async())
                .await
                .unwrap()
                .unwrap();
            query.reply("recovered", "reclaimed").await.unwrap();
            drop(query);
            assert!(replies.recv_async().await.unwrap().result().is_ok());
            client.close().await.unwrap();
            for _ in 0..200 {
                if snapshot().records == 0 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            assert_eq!(
                snapshot(),
                Default::default(),
                "{mode}: disconnected projections retained"
            );
            // A whole budget reservation proves RAII returned actual ownership, beyond map lengths.
            let all = budget
                .reserve(NativeAggregationUsage {
                    records: budget.business_limits().records,
                    references: budget.business_limits().references,
                    memberships: budget.business_limits().memberships,
                })
                .unwrap();
            drop(all);
            platform.close().await.unwrap();
            drop((
                control,
                subscriber,
                recovered,
                querier,
                publisher,
                query_matches,
                subscriber_matches,
            ));
            router.close().await.unwrap();
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn wildcard_matching_edges_are_bounded_atomic_and_reclaimed() {
        let config =
            crate::Config::from_json5(r#"{mode:"router",scouting:{multicast:{enabled:false}}}"#)
                .unwrap();
        let router = RuntimeBuilder::new(config).build().await.unwrap();
        router.install_route_gate(Arc::new(Allow)).unwrap();
        let gateway = router.router();
        let mut tables = gateway.tables.tables.write().unwrap();
        let budget = tables.data.native_resource_budget.clone().unwrap();
        let mut root = tables.data.root_res.clone();
        let mut retained = Vec::new();
        let mut refused = false;
        for id in 0..400 {
            let key = format!("**/i{id}/**");
            let mut matches = Resource::get_matches(&tables.data, keyexpr::new(&key).unwrap());
            let mut res = Resource::make_resource(&mut tables, &mut root, &key).unwrap();
            matches.push(Arc::downgrade(&res));
            let before = budget.0.lock().unwrap().matches;
            if Resource::match_resource(&tables.data, &mut res, matches) {
                retained.push(res);
                assert_eq!(
                    budget.0.lock().unwrap().matches,
                    retained.len() * retained.len()
                );
            } else {
                refused = true;
                assert_eq!(budget.0.lock().unwrap().matches, before);
                assert!(res.context().matches.is_empty());
                assert!(retained
                    .iter()
                    .all(|r| r.context().matches.len() == retained.len()));
                Resource::clean(&mut res);
                drop(res);
                assert!(Resource::get_resource(&root, &format!("**/i{id}")).is_none());
                break;
            }
        }
        assert!(refused);
        assert!(budget.0.lock().unwrap().matches <= BUSINESS_RESOURCE_MATCH_EDGES);
        for mut res in retained {
            Resource::clean(&mut res);
        }
        assert_eq!(budget.0.lock().unwrap().matches, 0);
        assert_eq!(budget.0.lock().unwrap().nodes, 0);
        assert_eq!(budget.0.lock().unwrap().contexts, 0);
        drop(tables);
        router.close().await.unwrap();
    }
}
