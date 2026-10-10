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
    collections::{HashMap, HashSet},
    hash::Hash,
    ops::Deref,
    sync::Arc,
};

use zenoh_protocol::network::interest::InterestId;

use crate::net::routing::gateway::Resource;

#[cfg(feature = "zenss-route-gate")]
use crate::net::routing::interceptor::route_gate::{QueryCapacity, RouteGate};
#[cfg(feature = "zenss-route-gate")]
pub(crate) type NativeDeclarationCapacity = QueryCapacity;
#[cfg(not(feature = "zenss-route-gate"))]
#[derive(Clone, Copy)]
pub(crate) enum NativeDeclarationCapacity {
    Business,
}

#[derive(Clone, Copy)]
pub(crate) enum NativeDeclarationKind {
    Subscriber,
    Queryable,
    Token,
}
#[cfg(feature = "zenss-route-gate")]
impl NativeDeclarationKind {
    fn action(self) -> crate::net::routing::interceptor::route_gate::RouteAction {
        use crate::net::routing::interceptor::route_gate::RouteAction;
        match self {
            Self::Subscriber => RouteAction::DeclareSubscriber,
            Self::Queryable => RouteAction::DeclareQueryable,
            Self::Token => RouteAction::LivelinessToken,
        }
    }
}

// ZenSS: retained aggregation state, shared across all faces/hats/entity kinds.
#[cfg(feature = "zenss-route-gate")]
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub(crate) struct NativeAggregationUsage {
    pub(crate) records: usize,
    pub(crate) references: usize,
    pub(crate) memberships: usize,
}
#[cfg(feature = "zenss-route-gate")]
impl NativeAggregationUsage {
    pub(crate) fn add(self, other: Self) -> Self {
        Self {
            records: self.records + other.records,
            references: self.references + other.references,
            memberships: self.memberships + other.memberships,
        }
    }
}
#[cfg(feature = "zenss-route-gate")]
pub(crate) struct NativeAggregationBudget {
    usage: std::sync::Mutex<NativeAggregationUsage>,
    limits: NativeAggregationUsage,
    reserved: NativeAggregationUsage,
    pub(crate) gate: Option<Arc<dyn RouteGate>>,
}
#[cfg(feature = "zenss-route-gate")]
impl Default for NativeAggregationBudget {
    fn default() -> Self {
        Self {
            usage: Default::default(),
            limits: NativeAggregationUsage {
                records: 8192,
                references: 131072,
                memberships: 65536,
            },
            reserved: NativeAggregationUsage {
                records: 256,
                references: 8192,
                memberships: 4096,
            },
            gate: None,
        }
    }
}
#[cfg(feature = "zenss-route-gate")]
pub(crate) struct NativeAggregationReservation {
    budget: Arc<NativeAggregationBudget>,
    usage: NativeAggregationUsage,
}
#[cfg(feature = "zenss-route-gate")]
impl NativeAggregationBudget {
    pub(crate) fn with_gate(gate: Arc<dyn RouteGate>) -> Self {
        Self {
            gate: Some(gate),
            ..Default::default()
        }
    }
    pub(crate) fn reserve(
        self: &Arc<Self>,
        usage: NativeAggregationUsage,
    ) -> Option<NativeAggregationReservation> {
        self.reserve_for(usage, QueryCapacity::Business)
    }
    pub(crate) fn business_limits(&self) -> NativeAggregationUsage {
        NativeAggregationUsage {
            records: self.limits.records.saturating_sub(self.reserved.records),
            references: self
                .limits
                .references
                .saturating_sub(self.reserved.references),
            memberships: self
                .limits
                .memberships
                .saturating_sub(self.reserved.memberships),
        }
    }
    fn reserve_for(
        self: &Arc<Self>,
        usage: NativeAggregationUsage,
        capacity: QueryCapacity,
    ) -> Option<NativeAggregationReservation> {
        let mut current = self.usage.lock().ok()?;
        let next = NativeAggregationUsage {
            records: current.records.checked_add(usage.records)?,
            references: current.references.checked_add(usage.references)?,
            memberships: current.memberships.checked_add(usage.memberships)?,
        };
        let limit = if capacity == QueryCapacity::Control {
            self.limits
        } else {
            self.business_limits()
        };
        if next.records > self.limits.records
            || next.references > self.limits.references
            || next.memberships > self.limits.memberships
            || (usage.records != 0 && next.records > limit.records)
            || (usage.references != 0 && next.references > limit.references)
            || (usage.memberships != 0 && next.memberships > limit.memberships)
        {
            tracing::debug!("native aggregation capacity refused");
            return None;
        }
        *current = next;
        Some(NativeAggregationReservation {
            budget: self.clone(),
            usage,
        })
    }
}
#[cfg(feature = "zenss-route-gate")]
impl NativeAggregationReservation {
    pub(crate) fn split(&mut self, usage: NativeAggregationUsage) -> Self {
        self.release_owned(usage);
        Self {
            budget: self.budget.clone(),
            usage,
        }
    }
    fn release_owned(&mut self, usage: NativeAggregationUsage) {
        self.usage.records -= usage.records;
        self.usage.references -= usage.references;
        self.usage.memberships -= usage.memberships;
    }
    fn retain(&mut self, usage: NativeAggregationUsage) {
        let released = NativeAggregationUsage {
            records: self.usage.records - usage.records,
            references: self.usage.references - usage.references,
            memberships: self.usage.memberships - usage.memberships,
        };
        let mut current = self.budget.usage.lock().unwrap_or_else(|e| e.into_inner());
        current.records -= released.records;
        current.references -= released.references;
        current.memberships -= released.memberships;
        self.usage = usage;
    }
    fn grow(&mut self, usage: NativeAggregationUsage, capacity: QueryCapacity) -> Option<()> {
        let mut extra = self.budget.reserve_for(usage, capacity)?;
        self.usage = self.usage.add(extra.usage);
        extra.usage = Default::default();
        Some(())
    }
}
#[cfg(feature = "zenss-route-gate")]
impl Drop for NativeAggregationReservation {
    fn drop(&mut self) {
        self.retain(Default::default());
    }
}

pub(crate) trait LocalResourceTrait: Hash + Clone + Eq {
    fn matches(&self, other: &Self) -> bool;
    fn native_key(&self) -> Option<&str> {
        None
    }
}

pub(crate) trait LocalResourceInfoTrait<Res: LocalResourceTrait>
where
    Self: Sized + Eq + Clone + Copy,
{
    fn aggregate(self_val: Option<Self>, self_res: &Res, other_val: &Self, other_res: &Res)
        -> Self;

    fn aggregate_many<'a>(
        self_res: &'a Res,
        iter: impl Iterator<Item = (&'a Res, Self)>,
    ) -> Option<Self> {
        let mut out = None;
        for (res, val) in iter {
            out = Some(Self::aggregate(out, self_res, &val, res));
        }
        out
    }
}

struct ResourceData<Id: Copy, Res: LocalResourceTrait, Info: LocalResourceInfoTrait<Res>> {
    id: Id,
    aggregated_to: HashSet<Res>,
    simple_interest_ids: HashSet<InterestId>,
    info: Info,
}

struct AggregatedResourceData<Id: Copy, Res: LocalResourceTrait, Info: LocalResourceInfoTrait<Res>>
{
    id: Id,
    aggregates: HashSet<Res>,
    aggregated_interest_ids: HashSet<InterestId>,
    info: Option<Info>,
}

impl<Id: Copy, Res: LocalResourceTrait, Info: LocalResourceInfoTrait<Res>>
    AggregatedResourceData<Id, Res, Info>
{
    fn recompute_info(
        &self,
        self_res: &Res,
        subs: &HashMap<Res, ResourceData<Id, Res, Info>>,
    ) -> Option<Info> {
        let iter = self
            .aggregates
            .iter()
            .map(|r| (r, subs.get(r).unwrap().info));
        Info::aggregate_many(self_res, iter)
    }
}

pub(crate) struct LocalResourceRemoveResult<
    Id: Copy,
    Res: LocalResourceTrait,
    Info: LocalResourceInfoTrait<Res>,
> {
    pub(crate) id: Id,
    pub(crate) resource: Res,
    pub(crate) update: Option<Info>,
}

pub(crate) struct LocalResourceInsertResult<
    Id: Copy,
    Res: LocalResourceTrait,
    Info: LocalResourceInfoTrait<Res>,
> {
    pub(crate) id: Id,
    pub(crate) resource: Res,
    pub(crate) info: Info,
}

pub(crate) struct LocalResources<
    Id: Copy,
    Res: LocalResourceTrait,
    Info: LocalResourceInfoTrait<Res>,
> {
    #[cfg(feature = "zenss-route-gate")]
    native_reservation: Option<NativeAggregationReservation>,
    simple_resources: HashMap<Res, ResourceData<Id, Res, Info>>,
    aggregated_resources: HashMap<Res, AggregatedResourceData<Id, Res, Info>>,
}

impl<Id: Copy, Res: LocalResourceTrait, Info: LocalResourceInfoTrait<Res>>
    LocalResources<Id, Res, Info>
{
    pub(crate) fn new() -> Self {
        Self {
            #[cfg(feature = "zenss-route-gate")]
            native_reservation: None,
            simple_resources: HashMap::new(),
            aggregated_resources: HashMap::new(),
        }
    }

    #[cfg(feature = "zenss-route-gate")]
    pub(crate) fn with_budget(budget: Option<&Arc<NativeAggregationBudget>>) -> Self {
        let mut resources = Self::new();
        resources.native_reservation = budget.map(|b| {
            b.reserve(Default::default())
                .expect("empty aggregation reservation")
        });
        resources
    }

    #[cfg(feature = "zenss-route-gate")]
    pub(crate) fn native_usage(&self) -> NativeAggregationUsage {
        NativeAggregationUsage {
            records: self.simple_resources.len() + self.aggregated_resources.len(),
            references: self
                .simple_resources
                .values()
                .map(|r| r.aggregated_to.len())
                .sum::<usize>()
                * 2,
            memberships: self
                .simple_resources
                .values()
                .map(|r| r.simple_interest_ids.len())
                .sum::<usize>()
                + self
                    .aggregated_resources
                    .values()
                    .map(|r| r.aggregated_interest_ids.len())
                    .sum::<usize>(),
        }
    }

    #[cfg(feature = "zenss-route-gate")]
    pub(crate) fn bind_native_reservation(&mut self, reservation: NativeAggregationReservation) {
        debug_assert!(self.native_reservation.is_none());
        debug_assert_eq!(reservation.usage, self.native_usage());
        self.native_reservation = Some(reservation);
    }

    #[cfg(feature = "zenss-route-gate")]
    fn reserve_delta(
        &mut self,
        usage: NativeAggregationUsage,
        capacity: QueryCapacity,
    ) -> Option<()> {
        if let Some(reservation) = &mut self.native_reservation {
            reservation.grow(usage, capacity)?;
        }
        Some(())
    }

    fn reclaim_native(&mut self) {
        #[cfg(feature = "zenss-route-gate")]
        {
            let usage = self.native_usage();
            if let Some(reservation) = &mut self.native_reservation {
                reservation.retain(usage);
            }
        }
    }

    pub(crate) fn insert_simple_resource<F>(
        &mut self,
        key: Res,
        info: Info,
        f_id: F,
        interests: HashSet<InterestId>,
    ) -> Option<(Id, Vec<LocalResourceInsertResult<Id, Res, Info>>)>
    where
        F: FnOnce() -> Id,
    {
        self.insert_simple_resource_with_capacity(
            key,
            info,
            f_id,
            interests,
            NativeDeclarationCapacity::Business,
        )
    }

    pub(crate) fn native_capacity(
        &self,
        key: &Res,
        _face: &super::face::FaceState,
        _kind: NativeDeclarationKind,
    ) -> NativeDeclarationCapacity {
        #[cfg(feature = "zenss-route-gate")]
        if let Some(gate) = self
            .native_reservation
            .as_ref()
            .and_then(|r| r.budget.gate.as_ref())
        {
            if let Some(key) = key.native_key() {
                return crate::net::routing::interceptor::route_gate::declaration_capacity(
                    gate.as_ref(),
                    _face,
                    key,
                    _kind.action(),
                    crate::net::routing::interceptor::route_gate::RouteFlow::Egress,
                );
            }
        }
        NativeDeclarationCapacity::Business
    }

    pub(crate) fn insert_simple_resource_with_capacity<F>(
        &mut self,
        key: Res,
        info: Info,
        f_id: F,
        interests: HashSet<InterestId>,
        _capacity: NativeDeclarationCapacity,
    ) -> Option<(Id, Vec<LocalResourceInsertResult<Id, Res, Info>>)>
    where
        F: FnOnce() -> Id,
    {
        #[cfg(feature = "zenss-route-gate")]
        {
            let delta = match self.simple_resources.get(&key) {
                Some(existing) => NativeAggregationUsage {
                    memberships: interests.difference(&existing.simple_interest_ids).count(),
                    ..Default::default()
                },
                None => NativeAggregationUsage {
                    records: 1,
                    references: self
                        .aggregated_resources
                        .keys()
                        .filter(|a| key.matches(a))
                        .count()
                        * 2,
                    memberships: interests.len(),
                },
            };
            self.reserve_delta(delta, _capacity)?;
        }
        Some(self.insert_simple_resource_unchecked(key, info, f_id, interests))
    }

    #[cfg(test)]
    pub(crate) fn insert_aggregated_resource<F>(
        &mut self,
        key: Res,
        f_id: F,
        interests: HashSet<InterestId>,
    ) -> Option<(Id, Option<Info>)>
    where
        F: FnOnce() -> Id,
    {
        #[cfg(feature = "zenss-route-gate")]
        {
            let delta = match self.aggregated_resources.get(&key) {
                Some(existing) => NativeAggregationUsage {
                    memberships: interests
                        .difference(&existing.aggregated_interest_ids)
                        .count(),
                    ..Default::default()
                },
                None => NativeAggregationUsage {
                    records: 1,
                    memberships: interests.len(),
                    references: self
                        .simple_resources
                        .keys()
                        .filter(|r| r.matches(&key))
                        .count()
                        * 2,
                },
            };
            self.reserve_delta(delta, QueryCapacity::Business)?;
        }
        Some(self.insert_aggregated_resource_unchecked(key, f_id, interests))
    }

    // Aggregate and current matches are one mutation: preflight all records,
    // reciprocal links and memberships before IDs, info changes or notifications.
    pub(crate) fn insert_aggregate_with_matches<F>(
        &mut self,
        key: Res,
        f_id: F,
        interests: HashSet<InterestId>,
        matches: HashMap<Res, Info>,
    ) -> Option<(Id, Option<Info>)>
    where
        F: FnMut() -> Id,
    {
        self.insert_aggregate_with_matches_with_capacity(
            key,
            f_id,
            interests,
            matches,
            NativeDeclarationCapacity::Business,
        )
    }

    pub(crate) fn insert_aggregate_with_matches_with_capacity<F>(
        &mut self,
        key: Res,
        mut f_id: F,
        interests: HashSet<InterestId>,
        matches: HashMap<Res, Info>,
        _capacity: NativeDeclarationCapacity,
    ) -> Option<(Id, Option<Info>)>
    where
        F: FnMut() -> Id,
    {
        #[cfg(feature = "zenss-route-gate")]
        {
            let mut delta = NativeAggregationUsage::default();
            for simple in matches
                .keys()
                .filter(|r| !self.simple_resources.contains_key(*r))
            {
                delta.records += 1;
                delta.references += self
                    .aggregated_resources
                    .keys()
                    .filter(|a| simple.matches(a))
                    .count()
                    * 2;
            }
            if let Some(existing) = self.aggregated_resources.get(&key) {
                delta.memberships += interests
                    .difference(&existing.aggregated_interest_ids)
                    .count();
            } else {
                delta.records += 1;
                delta.memberships += interests.len();
                delta.references += self
                    .simple_resources
                    .keys()
                    .filter(|r| r.matches(&key))
                    .count()
                    * 2;
                delta.references += matches
                    .keys()
                    .filter(|r| !self.simple_resources.contains_key(*r) && r.matches(&key))
                    .count()
                    * 2;
            }
            // An exact controlled aggregate cannot import a different new record
            // into its reserve merely because that record intersects its key.
            let capacity = if _capacity == QueryCapacity::Control
                && matches
                    .keys()
                    .any(|r| r != &key && !self.simple_resources.contains_key(r))
            {
                QueryCapacity::Business
            } else {
                _capacity
            };
            self.reserve_delta(delta, capacity)?;
        }
        for (simple, info) in matches {
            self.insert_simple_resource_unchecked(simple, info, &mut f_id, HashSet::new());
        }
        Some(self.insert_aggregated_resource_unchecked(key, f_id, interests))
    }

    pub(crate) fn contains_simple_resource(&self, key: &Res) -> bool {
        self.simple_resources.contains_key(key)
    }

    // Returns Id of newly inserted resource and the list of resources that were enabled/changed info by this operation
    fn insert_simple_resource_unchecked<F>(
        &mut self,
        key: Res,
        info: Info,
        f_id: F,
        simple_interests: HashSet<InterestId>,
    ) -> (Id, Vec<LocalResourceInsertResult<Id, Res, Info>>)
    where
        F: FnOnce() -> Id,
    {
        let mut updated_resources = Vec::new();
        match self.simple_resources.entry(key.clone()) {
            std::collections::hash_map::Entry::Occupied(mut occupied_entry) => {
                {
                    let s_res_data = occupied_entry.get_mut();
                    s_res_data.simple_interest_ids.extend(simple_interests);
                    if !s_res_data.simple_interest_ids.is_empty() && s_res_data.info != info {
                        updated_resources.push(LocalResourceInsertResult {
                            id: s_res_data.id,
                            resource: key.clone(),
                            info,
                        });
                    }
                    s_res_data.info = info;
                };
                let s_res_data = self.simple_resources.get(&key).unwrap(); // reborrow as shared ref

                for a_res in &s_res_data.aggregated_to {
                    if let Some(a_res_data) = self.aggregated_resources.get_mut(a_res) {
                        let new_info = a_res_data.recompute_info(a_res, &self.simple_resources);
                        if new_info != a_res_data.info {
                            a_res_data.info = new_info;
                            updated_resources.push(LocalResourceInsertResult {
                                id: a_res_data.id,
                                resource: a_res.clone(),
                                info: new_info.unwrap(), // aggregated resource contains at least one simple - so it is guaranteed to have an initialized info
                            });
                        }
                    }
                }
                (s_res_data.id, updated_resources)
            }
            std::collections::hash_map::Entry::Vacant(vacant_entry) => {
                let id = self
                    .aggregated_resources
                    .get(&key)
                    .map_or_else(f_id, |r| r.id);

                let mut aggregated_to = HashSet::new();
                for (a_res, a_res_data) in &mut self.aggregated_resources {
                    if key.matches(a_res) {
                        let new_info = Info::aggregate(a_res_data.info, a_res, &info, &key);
                        if Some(new_info) != a_res_data.info {
                            a_res_data.info = Some(new_info);
                            updated_resources.push(LocalResourceInsertResult {
                                id: a_res_data.id,
                                resource: a_res.clone(),
                                info: new_info,
                            });
                        }
                        a_res_data.aggregates.insert(key.clone());
                        aggregated_to.insert(a_res.clone());
                    }
                }
                let inserted_res = vacant_entry.insert(ResourceData {
                    id,
                    aggregated_to,
                    simple_interest_ids: simple_interests,
                    info,
                });
                if !inserted_res.simple_interest_ids.is_empty() {
                    updated_resources.push(LocalResourceInsertResult {
                        id,
                        resource: key,
                        info,
                    });
                }
                (id, updated_resources)
            }
        }
    }

    fn insert_aggregated_resource_unchecked<F>(
        &mut self,
        key: Res,
        f_id: F,
        aggregated_interests: HashSet<InterestId>,
    ) -> (Id, Option<Info>)
    where
        F: FnOnce() -> Id,
    {
        match self.aggregated_resources.entry(key.clone()) {
            std::collections::hash_map::Entry::Occupied(mut occupied_entry) => {
                occupied_entry
                    .get_mut()
                    .aggregated_interest_ids
                    .extend(aggregated_interests);
                (occupied_entry.get().id, occupied_entry.get().info)
            }
            std::collections::hash_map::Entry::Vacant(vacant_entry) => {
                let mut aggregates = HashSet::new();
                for (s_res, s_res_data) in &mut self.simple_resources {
                    if s_res.matches(&key) {
                        s_res_data.aggregated_to.insert(key.clone());
                        aggregates.insert(s_res.clone());
                    }
                }
                let inserted_res = vacant_entry.insert(AggregatedResourceData {
                    id: self.simple_resources.get(&key).map_or_else(f_id, |r| r.id),
                    aggregates,
                    aggregated_interest_ids: aggregated_interests,
                    info: None,
                });
                inserted_res.info = inserted_res.recompute_info(&key, &self.simple_resources);
                (inserted_res.id, inserted_res.info)
            }
        }
    }

    // Returns resources that were removed/changed info due to simple resource removal.
    pub(crate) fn remove_simple_resource(
        &mut self,
        key: &Res,
    ) -> Vec<LocalResourceRemoveResult<Id, Res, Info>> {
        let mut updated_resources = Vec::new();
        if let Some(s_res_data) = self.simple_resources.remove(key) {
            if !s_res_data.simple_interest_ids.is_empty() {
                // there was an interest for this specific resource
                updated_resources.push(LocalResourceRemoveResult {
                    id: s_res_data.id,
                    resource: key.clone(),
                    update: None,
                });
            }
            if !s_res_data.aggregated_to.is_empty() {
                for a_res in &s_res_data.aggregated_to {
                    let a_res_data = self.aggregated_resources.get_mut(a_res).unwrap();
                    a_res_data.aggregates.remove(key);
                    let new_info = a_res_data.recompute_info(a_res, &self.simple_resources);
                    if new_info != a_res_data.info {
                        a_res_data.info = new_info;
                        updated_resources.push(LocalResourceRemoveResult {
                            id: a_res_data.id,
                            resource: a_res.clone(),
                            update: new_info,
                        })
                    }
                }
            }
        }
        self.reclaim_native();
        updated_resources
    }

    pub(crate) fn remove_simple_resource_interest(&mut self, simple_interest: InterestId) {
        self.simple_resources.retain(|_, res_data| {
            !(res_data.simple_interest_ids.remove(&simple_interest)
                && res_data.simple_interest_ids.is_empty()
                && res_data.aggregated_to.is_empty())
        });
        self.reclaim_native();
    }

    pub(crate) fn remove_aggregated_resource_interest(
        &mut self,
        key: &Res,
        aggregated_interest: InterestId,
    ) -> bool {
        let removed = match self.aggregated_resources.entry(key.clone()) {
            std::collections::hash_map::Entry::Occupied(mut occupied_entry) => {
                if occupied_entry
                    .get_mut()
                    .aggregated_interest_ids
                    .remove(&aggregated_interest)
                {
                    if occupied_entry.get_mut().aggregated_interest_ids.is_empty() {
                        // the aggregate can be removed if there is no other interest for it
                        let aggregates = occupied_entry.remove().aggregates;
                        for s_res in aggregates {
                            if let std::collections::hash_map::Entry::Occupied(mut e) =
                                self.simple_resources.entry(s_res)
                            {
                                e.get_mut().aggregated_to.remove(key);
                                if e.get().simple_interest_ids.is_empty()
                                    && e.get().aggregated_to.is_empty()
                                {
                                    // remove simple resource if there is no interest for it, nor it is aggregated into any other one
                                    e.remove();
                                }
                            }
                        }
                    }
                    true
                } else {
                    false
                }
            }
            std::collections::hash_map::Entry::Vacant(_) => false,
        };
        self.reclaim_native();
        removed
    }

    pub(crate) fn clear(&mut self) {
        self.simple_resources.clear();
        self.aggregated_resources.clear();
        self.reclaim_native();
    }
}

impl LocalResourceTrait for Arc<Resource> {
    fn native_key(&self) -> Option<&str> {
        Some(self.expr())
    }
    fn matches(&self, other: &Self) -> bool {
        self.deref().matches(other)
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, sync::atomic::AtomicUsize};

    use zenoh_keyexpr::OwnedKeyExpr;

    use super::*;

    impl LocalResourceTrait for OwnedKeyExpr {
        fn native_key(&self) -> Option<&str> {
            Some(self.as_str())
        }
        fn matches(&self, other: &Self) -> bool {
            self.intersects(other)
        }
    }

    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    struct TestInfo {
        count: usize,
    }

    impl LocalResourceInfoTrait<OwnedKeyExpr> for TestInfo {
        fn aggregate(
            self_val: Option<Self>,
            _self_res: &OwnedKeyExpr,
            other_val: &Self,
            _other_res: &OwnedKeyExpr,
        ) -> Self {
            match self_val {
                Some(self_val) => TestInfo {
                    count: self_val.count + other_val.count,
                },
                None => *other_val,
            }
        }
    }

    type LocalTestResources = LocalResources<usize, OwnedKeyExpr, TestInfo>;

    fn ke(s: &str) -> OwnedKeyExpr {
        s.try_into().unwrap()
    }

    #[cfg(feature = "zenss-route-gate")]
    fn budget(
        records: usize,
        references: usize,
        memberships: usize,
    ) -> Arc<NativeAggregationBudget> {
        Arc::new(NativeAggregationBudget {
            usage: Default::default(),
            limits: NativeAggregationUsage {
                records,
                references,
                memberships,
            },
            reserved: Default::default(),
            gate: None,
        })
    }

    #[cfg(feature = "zenss-route-gate")]
    #[test]
    fn aggregation_reserve_covers_each_dimension_and_empty_owners_at_control_capacity() {
        let b = Arc::new(NativeAggregationBudget::default());
        let limit = b.business_limits();
        let held = b.reserve(limit).unwrap();
        for delta in [
            NativeAggregationUsage {
                records: 1,
                ..Default::default()
            },
            NativeAggregationUsage {
                references: 1,
                ..Default::default()
            },
            NativeAggregationUsage {
                memberships: 1,
                ..Default::default()
            },
        ] {
            assert!(b.reserve(delta).is_none());
            let control = b.reserve_for(delta, QueryCapacity::Control).unwrap();
            let empty = LocalTestResources::with_budget(Some(&b));
            drop(empty);
            drop(control);
        }
        let control = b.reserve_for(b.reserved, QueryCapacity::Control).unwrap();
        assert!(b
            .reserve_for(
                NativeAggregationUsage {
                    records: 1,
                    ..Default::default()
                },
                QueryCapacity::Control
            )
            .is_none());
        assert!(b
            .reserve_for(
                NativeAggregationUsage {
                    records: usize::MAX,
                    ..Default::default()
                },
                QueryCapacity::Control
            )
            .is_none());
        drop((held, control));
        assert_eq!(usage(&b), NativeAggregationUsage::default());
    }

    #[cfg(feature = "zenss-route-gate")]
    #[test]
    fn controlled_aggregation_refuses_imported_wildcard_without_partial_records_or_ids() {
        let b = Arc::new(NativeAggregationBudget::default());
        let held = b.reserve(b.business_limits()).unwrap();
        let mut local = LocalTestResources::with_budget(Some(&b));
        let count = AtomicUsize::new(0);
        let key = ke("trusted/control");
        assert!(local
            .insert_aggregate_with_matches_with_capacity(
                key.clone(),
                || count.fetch_add(1, std::sync::atomic::Ordering::SeqCst),
                HashSet::from([1]),
                HashMap::from([(ke("trusted/*"), TestInfo { count: 1 })]),
                QueryCapacity::Control
            )
            .is_none());
        assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert_eq!(local.native_usage(), NativeAggregationUsage::default());
        assert_eq!(usage(&b), b.business_limits());
        local
            .insert_aggregate_with_matches_with_capacity(
                key.clone(),
                || count.fetch_add(1, std::sync::atomic::Ordering::SeqCst),
                HashSet::from([1]),
                HashMap::from([(key.clone(), TestInfo { count: 1 })]),
                QueryCapacity::Control,
            )
            .unwrap();
        let before = usage(&b);
        // Existing exact resource updates need no promotion or new budget.
        local
            .insert_simple_resource_with_capacity(
                key,
                TestInfo { count: 2 },
                || panic!("duplicate ID"),
                HashSet::new(),
                QueryCapacity::Business,
            )
            .unwrap();
        assert_eq!(usage(&b), before);
        local.clear();
        drop((local, held));
        assert_eq!(usage(&b), NativeAggregationUsage::default());
    }

    #[cfg(feature = "zenss-route-gate")]
    fn usage(b: &NativeAggregationBudget) -> NativeAggregationUsage {
        *b.usage.lock().unwrap()
    }

    #[cfg(feature = "zenss-route-gate")]
    #[test]
    fn atomic_aggregate_refuses_each_dimension_before_ids_or_info_changes() {
        for b in [
            budget(2, 100, 100),
            budget(100, 1, 100),
            budget(100, 100, 1),
        ] {
            let mut local = LocalTestResources::with_budget(Some(&b));
            local
                .insert_simple_resource(
                    ke("test/1"),
                    TestInfo { count: 1 },
                    || 7,
                    HashSet::from([1]),
                )
                .unwrap();
            let before = usage(&b);
            let counter = AtomicUsize::new(0);
            assert!(local
                .insert_aggregate_with_matches(
                    ke("test/*"),
                    || counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst),
                    HashSet::from([2]),
                    HashMap::from([
                        (ke("test/1"), TestInfo { count: 9 }),
                        (ke("test/2"), TestInfo { count: 2 })
                    ]),
                )
                .is_none());
            assert_eq!(counter.load(std::sync::atomic::Ordering::SeqCst), 0);
            assert_eq!(usage(&b), before);
            assert_eq!(local.simple_resources[&ke("test/1")].info.count, 1);
            assert_eq!(local.simple_resources[&ke("test/1")].id, 7);
            assert!(local.simple_resources[&ke("test/1")]
                .aggregated_to
                .is_empty());
            assert!(!local.contains_simple_resource(&ke("test/2")));
            assert!(local.aggregated_resources.is_empty());
        }
    }

    #[cfg(feature = "zenss-route-gate")]
    #[test]
    fn global_aggregation_capacity_reclaims_on_all_removal_paths_and_drop() {
        let b = budget(3, 2, 3);
        let mut subs = LocalTestResources::with_budget(Some(&b));
        let mut qabls = LocalTestResources::with_budget(Some(&b));
        subs.insert_aggregate_with_matches(
            ke("test/*"),
            || 1,
            HashSet::from([1]),
            HashMap::from([(ke("test/1"), TestInfo { count: 1 })]),
        )
        .unwrap();
        qabls
            .insert_simple_resource(ke("other"), TestInfo { count: 1 }, || 2, HashSet::from([2]))
            .unwrap();
        assert!(qabls
            .insert_simple_resource(
                ke("more"),
                TestInfo { count: 1 },
                || panic!("refused ID"),
                HashSet::from([3])
            )
            .is_none());
        assert_eq!(
            usage(&b),
            NativeAggregationUsage {
                records: 3,
                references: 2,
                memberships: 2
            }
        );
        // Membership removal keeps aggregate-owned simple records until the aggregate is gone.
        subs.insert_simple_resource(
            ke("test/1"),
            TestInfo { count: 1 },
            || panic!("existing ID"),
            HashSet::from([3]),
        )
        .unwrap();
        subs.remove_simple_resource_interest(3);
        assert_eq!(usage(&b).records, 3);
        subs.remove_simple_resource(&ke("test/1"));
        assert_eq!(
            usage(&b),
            NativeAggregationUsage {
                records: 2,
                references: 0,
                memberships: 2
            }
        );
        subs.insert_simple_resource(ke("test/2"), TestInfo { count: 1 }, || 3, HashSet::new())
            .unwrap();
        assert!(subs.remove_aggregated_resource_interest(&ke("test/*"), 1));
        assert_eq!(
            usage(&b),
            NativeAggregationUsage {
                records: 1,
                references: 0,
                memberships: 1
            }
        );
        subs.insert_simple_resource(ke("again"), TestInfo { count: 1 }, || 4, HashSet::from([4]))
            .unwrap();
        subs.clear();
        assert_eq!(usage(&b).records, 1);
        drop(qabls);
        assert_eq!(usage(&b), Default::default());
        subs.insert_simple_resource(ke("last"), TestInfo { count: 1 }, || 5, HashSet::from([5]))
            .unwrap();
        subs.remove_simple_resource_interest(5);
        assert_eq!(usage(&b), Default::default());
    }

    #[cfg(feature = "zenss-route-gate")]
    #[test]
    fn duplicate_memberships_and_info_updates_work_at_capacity() {
        let b = budget(2, 2, 2);
        let mut local = LocalTestResources::with_budget(Some(&b));
        local
            .insert_simple_resource(
                ke("test/1"),
                TestInfo { count: 1 },
                || 1,
                HashSet::from([1]),
            )
            .unwrap();
        local
            .insert_aggregated_resource(ke("test/*"), || 2, HashSet::from([2]))
            .unwrap();
        let full = usage(&b);
        let (id, updates) = local
            .insert_simple_resource(
                ke("test/1"),
                TestInfo { count: 4 },
                || panic!("duplicate ID"),
                HashSet::from([1]),
            )
            .unwrap();
        assert_eq!(id, 1);
        assert_eq!(updates.len(), 2);
        assert_eq!(
            local.aggregated_resources[&ke("test/*")].info,
            Some(TestInfo { count: 4 })
        );
        local
            .insert_aggregated_resource(ke("test/*"), || panic!("duplicate ID"), HashSet::from([2]))
            .unwrap();
        assert_eq!(usage(&b), full);
        assert!(local
            .insert_simple_resource(
                ke("test/1"),
                TestInfo { count: 9 },
                || panic!("refused ID"),
                HashSet::from([3])
            )
            .is_none());
        assert_eq!(local.simple_resources[&ke("test/1")].info.count, 4);
        assert!(local
            .insert_aggregated_resource(ke("test/*"), || panic!("refused ID"), HashSet::from([3]))
            .is_none());
        assert_eq!(usage(&b), full);
    }

    #[cfg(feature = "zenss-route-gate")]
    #[test]
    fn batch_counts_existing_aggregate_links_and_shared_same_key_id_exactly() {
        let b = budget(4, 6, 2);
        let mut local = LocalTestResources::with_budget(Some(&b));
        local
            .insert_aggregated_resource(ke("test/**"), || 10, HashSet::from([1]))
            .unwrap();
        let before = usage(&b);
        let matches = HashMap::from([
            (ke("test/*"), TestInfo { count: 1 }),
            (ke("test/1"), TestInfo { count: 2 }),
        ]);
        assert!(local
            .insert_aggregate_with_matches(
                ke("test/*"),
                || panic!("refused ID"),
                HashSet::from([2]),
                matches
            )
            .is_none());
        assert_eq!(usage(&b), before);
        // Same-key simple shares the already allocated aggregate ID.
        local
            .insert_aggregate_with_matches(
                ke("test/**"),
                || 11,
                HashSet::from([1]),
                HashMap::from([
                    (ke("test/**"), TestInfo { count: 1 }),
                    (ke("test/1"), TestInfo { count: 2 }),
                ]),
            )
            .unwrap();
        assert_eq!(local.simple_resources[&ke("test/**")].id, 10);
        assert_eq!(
            usage(&b),
            NativeAggregationUsage {
                records: 3,
                references: 4,
                memberships: 1
            }
        );
        local.remove_simple_resource(&ke("test/1"));
        assert_eq!(usage(&b).references, 2);
        local.remove_aggregated_resource_interest(&ke("test/**"), 1);
        assert_eq!(usage(&b), Default::default());
    }

    #[cfg(feature = "zenss-route-gate")]
    #[test]
    fn preexisting_maps_are_reserved_together_before_binding() {
        let b = budget(2, 0, 2);
        let mut first = LocalTestResources::new();
        let mut second = LocalTestResources::new();
        first
            .insert_simple_resource(ke("a"), TestInfo { count: 1 }, || 1, HashSet::from([1]))
            .unwrap();
        second
            .insert_simple_resource(ke("b"), TestInfo { count: 1 }, || 2, HashSet::from([2]))
            .unwrap();
        let mut reservation = b
            .reserve(first.native_usage().add(second.native_usage()))
            .unwrap();
        first.bind_native_reservation(reservation.split(first.native_usage()));
        second.bind_native_reservation(reservation.split(second.native_usage()));
        drop(reservation);
        assert_eq!(usage(&b).records, 2);
        assert!(first
            .insert_simple_resource(
                ke("c"),
                TestInfo { count: 1 },
                || panic!("refused ID"),
                HashSet::new()
            )
            .is_none());
        drop(first);
        assert_eq!(usage(&b).records, 1);
        drop(second);
        assert_eq!(usage(&b), Default::default());
        assert!(b
            .reserve(NativeAggregationUsage {
                records: 3,
                ..Default::default()
            })
            .is_none());
        assert_eq!(usage(&b), Default::default());
    }

    #[test]
    fn test_simple() {
        let mut local_res = LocalTestResources::new();
        let info0 = TestInfo { count: 0 };
        let info1 = TestInfo { count: 1 };
        let counter = AtomicUsize::new(0);
        let out = local_res
            .insert_simple_resource(
                "test/simple/1".try_into().unwrap(),
                info0,
                || counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst),
                HashSet::from([1u32]),
            )
            .unwrap();

        assert_eq!(out.0, 0);
        assert_eq!(out.1.len(), 1);
        assert_eq!(out.1[0].id, 0);
        assert_eq!(out.1[0].info, info0);
        assert_eq!(out.1[0].resource, ke("test/simple/1"));

        let _ = local_res
            .insert_simple_resource(
                ke("test/simple/2"),
                info0,
                || counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst),
                HashSet::from([2u32]),
            )
            .unwrap();

        let out = local_res
            .insert_simple_resource(
                ke("test/simple/2"),
                info0,
                || counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst),
                HashSet::from([2u32]),
            )
            .unwrap();
        assert_eq!(out.0, 1);
        assert_eq!(out.1.len(), 0);

        let out = local_res
            .insert_simple_resource(
                ke("test/simple/2"),
                info1,
                || counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst),
                HashSet::from([2u32]),
            )
            .unwrap();
        assert_eq!(out.0, 1);
        assert_eq!(out.1.len(), 1);
        assert_eq!(out.1[0].id, 1);
        assert_eq!(out.1[0].info, info1);
        assert_eq!(out.1[0].resource, ke("test/simple/2"));

        let _ = local_res
            .insert_simple_resource(
                ke("test/simple/*"),
                info1,
                || counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst),
                HashSet::from([1u32, 2u32]),
            )
            .unwrap();

        assert!(local_res.contains_simple_resource(&ke("test/simple/1")));
        assert!(local_res.contains_simple_resource(&ke("test/simple/2")));
        assert!(local_res.contains_simple_resource(&ke("test/simple/*")));

        let out = local_res.remove_simple_resource(&ke("test/simple/2"));
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].id, 1);
        assert_eq!(out[0].update, None);
        assert_eq!(out[0].resource, ke("test/simple/2"));

        assert!(local_res.contains_simple_resource(&ke("test/simple/1")));
        assert!(!local_res.contains_simple_resource(&ke("test/simple/2")));
        assert!(local_res.contains_simple_resource(&ke("test/simple/*")));

        local_res.remove_simple_resource_interest(1);

        assert!(!local_res.contains_simple_resource(&ke("test/simple/1")));
        assert!(local_res.contains_simple_resource(&ke("test/simple/*")));

        local_res.remove_simple_resource_interest(2);

        assert!(!local_res.contains_simple_resource(&ke("test/simple/*")));
    }

    #[test]
    fn test_aggregate() {
        fn hm(
            v: Vec<LocalResourceInsertResult<usize, OwnedKeyExpr, TestInfo>>,
        ) -> HashMap<usize, (OwnedKeyExpr, TestInfo)> {
            v.into_iter()
                .map(|r| (r.id, (r.resource, r.info)))
                .collect::<HashMap<_, _>>()
        }

        let mut local_res = LocalTestResources::new();
        let info1 = TestInfo { count: 1 };
        let counter = AtomicUsize::new(0);
        local_res
            .insert_simple_resource(
                ke("test/aggregate/1"),
                info1,
                || counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst),
                HashSet::from([1u32]),
            )
            .unwrap();
        let _ = local_res
            .insert_simple_resource(
                ke("test/wrong/2"),
                info1,
                || counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst),
                HashSet::from([10u32]),
            )
            .unwrap();
        let out = local_res
            .insert_aggregated_resource(
                ke("test/aggregate/*"),
                || counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst),
                HashSet::from([2u32]),
            )
            .unwrap();
        assert_eq!(out.0, 2);
        assert_eq!(out.1, Some(TestInfo { count: 1 }));
        let out = local_res
            .insert_simple_resource(
                ke("test/aggregate/*"),
                info1,
                || counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst),
                HashSet::new(),
            )
            .unwrap();
        assert_eq!(out.0, 2);
        assert_eq!(out.1.len(), 1);
        assert_eq!(out.1[0].id, 2);
        assert_eq!(out.1[0].info, TestInfo { count: 2 });
        assert_eq!(out.1[0].resource, ke("test/aggregate/*"));

        let out = local_res
            .insert_simple_resource(
                ke("test/aggregate/2"),
                info1,
                || counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst),
                HashSet::from([3u32]),
            )
            .unwrap();
        assert_eq!(out.0, 3);
        let hm = hm(out.1);
        assert_eq!(hm.len(), 2);
        assert_eq!(
            hm.get(&3).unwrap(),
            &(ke("test/aggregate/2"), TestInfo { count: 1 })
        );
        assert_eq!(
            hm.get(&2).unwrap(),
            &(ke("test/aggregate/*"), TestInfo { count: 3 })
        );

        let out = local_res
            .insert_simple_resource(
                "test/aggregate/**".try_into().unwrap(),
                info1,
                || counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst),
                HashSet::new(),
            )
            .unwrap();
        assert_eq!(out.0, 4);
        assert_eq!(out.1.len(), 1);
        assert_eq!(out.1[0].id, 2);
        assert_eq!(out.1[0].info, TestInfo { count: 4 });
        assert_eq!(out.1[0].resource, ke("test/aggregate/*"));

        assert!(local_res.contains_simple_resource(&ke("test/aggregate/*")));
        let out = local_res.remove_simple_resource(&ke("test/aggregate/*"));
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].id, 2);
        assert_eq!(out[0].update, Some(TestInfo { count: 3 }));
        assert_eq!(out[0].resource, ke("test/aggregate/*"));
        assert!(!local_res.contains_simple_resource(&ke("test/aggregate/*")));

        local_res.remove_simple_resource_interest(1u32);
        assert!(local_res.contains_simple_resource(&ke("test/aggregate/1")));
        assert!(local_res.contains_simple_resource(&ke("test/aggregate/**")));

        local_res.remove_aggregated_resource_interest(&ke("test/aggregate/*"), 2);

        assert!(!local_res.contains_simple_resource(&ke("test/aggregate/1")));
        assert!(!local_res.contains_simple_resource(&ke("test/aggregate/**")));
        assert!(local_res.contains_simple_resource(&ke("test/aggregate/2")));
    }
}

// ZenSS: simple hat map ownership. No DerefMut/entry API can bypass admission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativeHatKind {
    Entity,
    Interest,
}
#[cfg(feature = "zenss-route-gate")]
impl NativeHatKind {
    fn weight(self) -> usize {
        match self {
            Self::Entity => 128,
            Self::Interest => 64,
        }
    }
    fn index(self) -> usize {
        match self {
            Self::Entity => 0,
            Self::Interest => 1,
        }
    }
}
#[cfg(feature = "zenss-route-gate")]
#[derive(Default)]
struct NativeHatLedger {
    enabled: bool,
    entries: [usize; 2],
    bytes: usize,
    // Zero-usage map owners are not retained by the shared ledger.
    owners: HashMap<usize, (NativeHatKind, usize)>,
}
#[cfg(feature = "zenss-route-gate")]
pub(crate) struct NativeHatBudget {
    ledger: std::sync::Mutex<NativeHatLedger>,
    limits: [usize; 2],
    per_map: [usize; 2],
    bytes: usize,
    reserved: [usize; 2],
    reserved_per_map: [usize; 2],
    reserved_bytes: usize,
    gate: std::sync::OnceLock<Arc<dyn RouteGate>>,
}
#[cfg(feature = "zenss-route-gate")]
impl Default for NativeHatBudget {
    fn default() -> Self {
        Self {
            ledger: Default::default(),
            limits: [32768, 4096],
            per_map: [2048, 256],
            bytes: 8 * 1024 * 1024,
            reserved: [1024, 128],
            reserved_per_map: [64, 8],
            reserved_bytes: 128 * 1024,
            gate: Default::default(),
        }
    }
}
#[cfg(feature = "zenss-route-gate")]
impl NativeHatBudget {
    fn fits(&self, ledger: &NativeHatLedger) -> bool {
        ledger.bytes <= self.bytes.saturating_sub(self.reserved_bytes)
            && ledger
                .entries
                .iter()
                .enumerate()
                .all(|(i, n)| *n <= self.limits[i].saturating_sub(self.reserved[i]))
            && ledger.owners.values().all(|(kind, n)| {
                *n <= self.per_map[kind.index()].saturating_sub(self.reserved_per_map[kind.index()])
            })
    }
    pub(crate) fn can_enable(&self) -> bool {
        self.ledger.lock().map(|l| self.fits(&l)).unwrap_or(false)
    }
    pub(crate) fn bind_gate(&self, gate: Arc<dyn RouteGate>) {
        assert!(self.gate.set(gate).is_ok(), "native hat gate installs once");
    }
    pub(crate) fn enable(&self) {
        let mut ledger = self.ledger.lock().unwrap_or_else(|e| e.into_inner());
        assert!(
            self.fits(&ledger),
            "native hat preflight under routing locks"
        );
        ledger.enabled = true;
    }
}
#[cfg(feature = "zenss-route-gate")]
struct NativeHatOwner {
    budget: Arc<NativeHatBudget>,
    kind: NativeHatKind,
}
#[cfg(feature = "zenss-route-gate")]
struct NativeHatPermit {
    owner: Arc<NativeHatOwner>,
    count: usize,
}
#[cfg(feature = "zenss-route-gate")]
impl NativeHatPermit {
    fn empty(&self) -> Self {
        Self {
            owner: self.owner.clone(),
            count: 0,
        }
    }
    fn reserve(&self, capacity: QueryCapacity) -> Option<Self> {
        let budget = &self.owner.budget;
        let kind = self.owner.kind;
        // A permit retains the Arc, so the pointer cannot be reused while charged.
        let id = Arc::as_ptr(&self.owner) as usize;
        let mut ledger = budget.ledger.lock().ok()?;
        let count = ledger
            .owners
            .get(&id)
            .map_or(0, |(_, n)| *n)
            .checked_add(1)?;
        let entries = ledger.entries[kind.index()].checked_add(1)?;
        let bytes = ledger.bytes.checked_add(kind.weight())?;
        let control = capacity == QueryCapacity::Control;
        let local_limit = budget.per_map[kind.index()].saturating_sub(if control {
            0
        } else {
            budget.reserved_per_map[kind.index()]
        });
        let shared_limit = budget.limits[kind.index()].saturating_sub(if control {
            0
        } else {
            budget.reserved[kind.index()]
        });
        let byte_limit =
            budget
                .bytes
                .saturating_sub(if control { 0 } else { budget.reserved_bytes });
        if ledger.enabled && (count > local_limit || entries > shared_limit || bytes > byte_limit) {
            tracing::debug!(?kind, "native hat map capacity refused");
            return None;
        }
        ledger.entries[kind.index()] = entries;
        ledger.bytes = bytes;
        ledger.owners.insert(id, (kind, count));
        Some(Self {
            owner: self.owner.clone(),
            count: 1,
        })
    }
    fn release(&mut self, count: usize) {
        if count == 0 {
            return;
        }
        assert!(count <= self.count);
        let id = Arc::as_ptr(&self.owner) as usize;
        let kind = self.owner.kind;
        let mut ledger = self
            .owner
            .budget
            .ledger
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        ledger.entries[kind.index()] -= count;
        ledger.bytes -= count * kind.weight();
        let (_, owned) = ledger.owners.get_mut(&id).expect("owned native hat permit");
        *owned -= count;
        if *owned == 0 {
            ledger.owners.remove(&id);
        }
        self.count -= count;
        if ledger.owners.is_empty() {
            ledger.owners = HashMap::new();
        } else if ledger.owners.capacity() > ledger.owners.len().saturating_mul(4) {
            ledger.owners.shrink_to_fit();
        }
    }
    fn absorb(&mut self, mut other: Self) {
        assert!(Arc::ptr_eq(&self.owner, &other.owner));
        self.count += other.count;
        other.count = 0;
    }
}
#[cfg(feature = "zenss-route-gate")]
impl Drop for NativeHatPermit {
    fn drop(&mut self) {
        self.release(self.count);
    }
}

pub(crate) struct NativeHatInsert<K> {
    key: K,
    existing: bool,
    #[cfg(feature = "zenss-route-gate")]
    permit: NativeHatPermit,
}
pub(crate) struct NativeHatMap<K, V> {
    // Field order ensures entries/backing allocation drop before the permit.
    entries: HashMap<K, V>,
    #[cfg(feature = "zenss-route-gate")]
    permit: NativeHatPermit,
}
impl<K: Eq + Hash, V> NativeHatMap<K, V> {
    pub(crate) fn new(_tables: &super::tables::TablesData, _kind: NativeHatKind) -> Self {
        Self {
            entries: HashMap::new(),
            #[cfg(feature = "zenss-route-gate")]
            permit: NativeHatPermit {
                owner: Arc::new(NativeHatOwner {
                    budget: _tables.native_hat_budget.clone(),
                    kind: _kind,
                }),
                count: 0,
            },
        }
    }
    pub(crate) fn prepare_insert(&self, key: K) -> Option<NativeHatInsert<K>> {
        self.prepare_insert_with_capacity(key, NativeDeclarationCapacity::Business)
    }
    pub(crate) fn prepare_insert_declaration(
        &self,
        key: K,
        _res: &Arc<Resource>,
        _face: &super::face::FaceState,
        _kind: NativeDeclarationKind,
        _ingress: bool,
    ) -> Option<NativeHatInsert<K>> {
        let mut capacity = NativeDeclarationCapacity::Business;
        #[cfg(feature = "zenss-route-gate")]
        if self.permit.owner.kind == NativeHatKind::Entity {
            if let Some(gate) = self.permit.owner.budget.gate.get() {
                use crate::net::routing::interceptor::route_gate::{
                    declaration_capacity, RouteFlow,
                };
                capacity = declaration_capacity(
                    gate.as_ref(),
                    _face,
                    _res.expr(),
                    _kind.action(),
                    if _ingress {
                        RouteFlow::Ingress
                    } else {
                        RouteFlow::Egress
                    },
                );
            }
        }
        self.prepare_insert_with_capacity(key, capacity)
    }
    pub(crate) fn prepare_insert_interest(
        &self,
        key: K,
        _face: &super::face::FaceState,
        _msg: &zenoh_protocol::network::Interest,
    ) -> Option<NativeHatInsert<K>> {
        let capacity = {
            #[cfg(feature = "zenss-route-gate")]
            {
                _face.native_interest_capacity(
                    _face
                        .mapped_interest_key(_msg.wire_expr.as_ref())
                        .as_deref(),
                    _msg.options,
                    true,
                )
            }
            #[cfg(not(feature = "zenss-route-gate"))]
            {
                NativeDeclarationCapacity::Business
            }
        };
        self.prepare_insert_with_capacity(key, capacity)
    }
    fn prepare_insert_with_capacity(
        &self,
        key: K,
        _capacity: NativeDeclarationCapacity,
    ) -> Option<NativeHatInsert<K>> {
        let existing = self.entries.contains_key(&key);
        Some(NativeHatInsert {
            key,
            existing,
            #[cfg(feature = "zenss-route-gate")]
            permit: if existing {
                self.permit.empty()
            } else {
                self.permit.reserve(_capacity)?
            },
        })
    }
    pub(crate) fn insert_prepared(&mut self, prepared: NativeHatInsert<K>, value: V) -> Option<V> {
        assert_eq!(
            prepared.existing,
            self.entries.contains_key(&prepared.key),
            "map changed after preflight"
        );
        #[cfg(feature = "zenss-route-gate")]
        assert!(Arc::ptr_eq(&self.permit.owner, &prepared.permit.owner));
        let old = self.entries.insert(prepared.key, value);
        #[cfg(feature = "zenss-route-gate")]
        self.permit.absorb(prepared.permit);
        old
    }
    pub(crate) fn remove(&mut self, key: &K) -> Option<V> {
        let old = self.entries.remove(key)?;
        self.shrink();
        #[cfg(feature = "zenss-route-gate")]
        self.permit.release(1);
        Some(old)
    }
    fn shrink(&mut self) {
        if self.entries.is_empty() {
            self.entries = HashMap::new();
        } else if self.entries.capacity() > self.entries.len().saturating_mul(4) {
            self.entries.shrink_to_fit();
        }
    }
    pub(crate) fn clear(&mut self) {
        self.entries = HashMap::new();
        #[cfg(feature = "zenss-route-gate")]
        self.permit.release(self.permit.count);
    }
    pub(crate) fn drain(&mut self) -> NativeHatDrain<K, V> {
        NativeHatDrain {
            entries: std::mem::take(&mut self.entries).into_iter(),
            #[cfg(feature = "zenss-route-gate")]
            _permit: {
                let empty = self.permit.empty();
                std::mem::replace(&mut self.permit, empty)
            },
        }
    }
}
impl<K, V> Deref for NativeHatMap<K, V> {
    type Target = HashMap<K, V>;
    fn deref(&self) -> &Self::Target {
        &self.entries
    }
}
pub(crate) struct NativeHatDrain<K, V> {
    entries: std::collections::hash_map::IntoIter<K, V>,
    #[cfg(feature = "zenss-route-gate")]
    _permit: NativeHatPermit,
}
impl<K, V> Iterator for NativeHatDrain<K, V> {
    type Item = (K, V);
    fn next(&mut self) -> Option<Self::Item> {
        self.entries.next()
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.entries.size_hint()
    }
}

#[cfg(all(test, feature = "zenss-route-gate"))]
mod native_hat_map_tests {
    use super::*;
    use crate::net::{
        routing::interceptor::route_gate::{RouteGate, RouteRequest, RouteSubject},
        runtime::RuntimeBuilder,
    };
    fn map(budget: &Arc<NativeHatBudget>, kind: NativeHatKind) -> NativeHatMap<u32, u32> {
        NativeHatMap {
            entries: HashMap::new(),
            permit: NativeHatPermit {
                owner: Arc::new(NativeHatOwner {
                    budget: budget.clone(),
                    kind,
                }),
                count: 0,
            },
        }
    }
    fn insert(map: &mut NativeHatMap<u32, u32>, key: u32) {
        let prepared = map.prepare_insert(key).unwrap();
        map.insert_prepared(prepared, key);
    }
    fn empty(b: &NativeHatBudget) {
        let l = b.ledger.lock().unwrap();
        assert_eq!(l.entries, [0, 0]);
        assert_eq!(l.bytes, 0);
        assert!(l.owners.is_empty());
        assert_eq!(l.owners.capacity(), 0);
    }
    #[test]
    fn shares_kind_caps_across_maps_and_returns_capacity_after_drop() {
        for (kind, cap, local) in [
            (NativeHatKind::Entity, 31744, 1984),
            (NativeHatKind::Interest, 3968, 248),
        ] {
            let b = Arc::new(NativeHatBudget::default());
            b.enable();
            let mut maps = (0..cap / local).map(|_| map(&b, kind)).collect::<Vec<_>>();
            for m in &mut maps {
                for key in 0..local {
                    insert(m, key);
                }
                assert!(m.prepare_insert(local).is_none());
            }
            let mut other = map(&b, kind);
            assert!(other.prepare_insert(0).is_none());
            drop(maps.pop());
            insert(&mut other, 0);
            drop((maps, other));
            empty(&b);
        }
    }
    #[test]
    fn combined_weight_refuses_atomically_and_reservation_rollback_recovers() {
        let b = Arc::new(NativeHatBudget {
            bytes: 192,
            reserved_bytes: 0,
            ..Default::default()
        });
        b.enable();
        let mut entities = map(&b, NativeHatKind::Entity);
        let mut interests = map(&b, NativeHatKind::Interest);
        insert(&mut entities, 1);
        let guard = interests.prepare_insert(1).unwrap();
        assert!(interests.is_empty());
        assert!(entities.prepare_insert(2).is_none());
        assert!(interests.prepare_insert(2).is_none());
        drop(guard);
        let guard = interests.prepare_insert(2).unwrap();
        interests.insert_prepared(guard, 2);
        assert_eq!(b.ledger.lock().unwrap().bytes, 192);
        drop((entities, interests));
        empty(&b);
    }
    #[test]
    fn duplicate_info_update_at_capacity_reclaims_remove_clear_and_sparse_backing() {
        let b = Arc::new(NativeHatBudget::default());
        b.enable();
        let mut m = map(&b, NativeHatKind::Entity);
        for k in 0..1984 {
            insert(&mut m, k);
        }
        let guard = m.prepare_insert(1).unwrap();
        assert_eq!(m.insert_prepared(guard, 9000), Some(1));
        assert_eq!(b.ledger.lock().unwrap().entries, [1984, 0]);
        assert!(m.prepare_insert(1984).is_none());
        assert_eq!(m.remove(&500), Some(500));
        insert(&mut m, 1984);
        for k in 2..1985 {
            m.remove(&k);
        }
        assert!(m.capacity() <= 4 * m.len());
        assert_eq!(m.get(&1), Some(&9000));
        m.clear();
        assert_eq!(m.capacity(), 0);
        empty(&b);
        insert(&mut m, 3);
        drop(m);
        empty(&b);
    }
    #[test]
    fn detached_drain_retains_ownership_after_map_drop_until_iterator_drop() {
        let b = Arc::new(NativeHatBudget {
            limits: [2, 2],
            per_map: [2, 2],
            reserved: [0, 0],
            reserved_per_map: [0, 0],
            ..Default::default()
        });
        b.enable();
        let mut m = map(&b, NativeHatKind::Entity);
        insert(&mut m, 1);
        insert(&mut m, 2);
        let mut drain = m.drain();
        assert_eq!(m.capacity(), 0);
        assert!(m.prepare_insert(3).is_none());
        drain.next().unwrap();
        drop(m);
        assert_eq!(b.ledger.lock().unwrap().entries, [2, 0]);
        let mut other = map(&b, NativeHatKind::Entity);
        assert!(other.prepare_insert(3).is_none());
        assert_eq!(drain.count(), 1);
        empty(&b);
        insert(&mut other, 3);
        drop(other);
        empty(&b);
    }
    #[test]
    fn entity_control_reserve_spans_shared_per_map_weight_and_detached_ownership() {
        let b = Arc::new(NativeHatBudget {
            limits: [4, 4],
            per_map: [3, 4],
            bytes: 6 * 128,
            reserved: [2, 0],
            reserved_per_map: [1, 0],
            reserved_bytes: 128,
            ..Default::default()
        });
        b.enable();
        let mut first = map(&b, NativeHatKind::Entity);
        let mut other = map(&b, NativeHatKind::Entity);
        insert(&mut first, 1);
        insert(&mut first, 2);
        assert!(first.prepare_insert(3).is_none());
        assert!(other.prepare_insert(1).is_none());
        let control = first
            .prepare_insert_with_capacity(3, QueryCapacity::Control)
            .unwrap();
        first.insert_prepared(control, 3);
        let mut drain = first.drain();
        assert!(first
            .prepare_insert_with_capacity(4, QueryCapacity::Control)
            .is_none());
        let control = other
            .prepare_insert_with_capacity(1, QueryCapacity::Control)
            .unwrap();
        other.insert_prepared(control, 1);
        assert!(other
            .prepare_insert_with_capacity(2, QueryCapacity::Control)
            .is_none());
        drain.next();
        drop(first);
        assert_eq!(b.ledger.lock().unwrap().entries, [4, 0]);
        drop(drain);
        assert_eq!(b.ledger.lock().unwrap().entries, [1, 0]);
        insert(&mut other, 2);
        drop(other);
        empty(&b);
        let b = Arc::new(NativeHatBudget {
            bytes: 192,
            reserved_bytes: 64,
            reserved: [0, 0],
            reserved_per_map: [0, 0],
            ..Default::default()
        });
        b.enable();
        let mut entities = map(&b, NativeHatKind::Entity);
        insert(&mut entities, 1);
        assert!(entities
            .prepare_insert_with_capacity(2, QueryCapacity::Control)
            .is_none());
        let mut interests = map(&b, NativeHatKind::Interest);
        // Control Interest now has its own authenticated path to shared metadata.
        let control = interests
            .prepare_insert_with_capacity(1, QueryCapacity::Control)
            .unwrap();
        interests.insert_prepared(control, 1);
        assert!(interests
            .prepare_insert_with_capacity(2, QueryCapacity::Control)
            .is_none());
        interests.clear();
        drop(entities);
        insert(&mut interests, 1);
        drop(interests);
        empty(&b);
    }

    struct Allow;
    impl RouteGate for Allow {
        fn authorize(&self, _: &RouteSubject, _: &RouteRequest<'_>) -> bool {
            true
        }
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn gate_preflights_existing_map_guard_and_detached_drain_without_partial_installation() {
        for ownership in ["map", "guard", "drain"] {
            let config = crate::Config::from_json5(
                r#"{mode:"router",scouting:{multicast:{enabled:false}}}"#,
            )
            .unwrap();
            let runtime = RuntimeBuilder::new(config).build().await.unwrap();
            let gateway = runtime.router();
            let (mut m, b) = {
                let tables = gateway.tables.tables.read().unwrap();
                (
                    NativeHatMap::<u32, u32>::new(&tables.data, NativeHatKind::Interest),
                    tables.data.native_hat_budget.clone(),
                )
            };
            for k in 0..256 {
                insert(&mut m, k);
            }
            let mut guard = Some(m.prepare_insert(256).unwrap());
            let drain = if ownership == "drain" {
                m.insert_prepared(guard.take().unwrap(), 256);
                Some(m.drain())
            } else {
                None
            };
            if ownership == "map" {
                m.insert_prepared(guard.take().unwrap(), 256);
            }
            assert!(!b.can_enable());
            assert!(runtime.install_route_gate(Arc::new(Allow)).is_err());
            drop(guard);
            {
                let tables = gateway.tables.tables.read().unwrap();
                assert!(tables.data.route_gate.is_none());
                assert!(tables.data.native_resource_budget.is_none());
                assert!(tables.data.native_aggregation_budget.is_none());
                assert!(!b.ledger.lock().unwrap().enabled);
            }
            drop((m, drain));
            empty(&b);
            runtime.install_route_gate(Arc::new(Allow)).unwrap();
            assert!(b.ledger.lock().unwrap().enabled);
            runtime.close().await.unwrap();
        }
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn real_tcp_control_declarations_require_peer_permission_under_shared_hat_pressure() {
        use crate::net::routing::interceptor::route_gate::{
            declaration_capacity, RouteAction, RouteFlow,
        };
        use std::{
            sync::atomic::{AtomicBool, Ordering},
            time::Duration,
        };
        const KEY: &str = "trusted/exact/control";
        struct Policy {
            peer: AtomicBool,
        }
        impl RouteGate for Policy {
            fn resource_capacity(&self, key: &str) -> QueryCapacity {
                if key == KEY {
                    QueryCapacity::Control
                } else {
                    QueryCapacity::Business
                }
            }
            fn authorize(&self, subject: &RouteSubject, request: &RouteRequest<'_>) -> bool {
                if matches!(
                    request.action,
                    RouteAction::DeclareQueryable
                        | RouteAction::DeclareSubscriber
                        | RouteAction::LivelinessToken
                ) && request.key == Some(KEY)
                {
                    self.peer.load(Ordering::Acquire)
                        && subject.role == zenoh_protocol::core::WhatAmI::Client
                } else {
                    true
                }
            }
        }
        for mode in ["router", "peer"] {
            let gate = Arc::new(Policy {
                peer: AtomicBool::new(false),
            });
            let config=crate::Config::from_json5(&format!(r#"{{mode:"{mode}",listen:{{endpoints:["tcp/127.0.0.1:0"]}},scouting:{{multicast:{{enabled:false}}}}}}"#)).unwrap();
            let mut runtime = RuntimeBuilder::new(config).build().await.unwrap();
            runtime.install_route_gate(gate.clone()).unwrap();
            runtime.start().await.unwrap();
            let platform = crate::session::init(runtime.clone().into()).await.unwrap();
            let config=crate::Config::from_json5(&format!(r#"{{mode:"client",connect:{{endpoints:["{}"]}},scouting:{{multicast:{{enabled:false}}}}}}"#,runtime.get_locators()[0])).unwrap();
            let client = crate::open(config).await.unwrap();
            let querier = client.declare_querier("**").await.unwrap();
            let gateway = runtime.router();
            let (hat, aggregation, face) = {
                let tables = gateway.tables.tables.read().unwrap();
                (
                    tables.data.native_hat_budget.clone(),
                    tables.data.native_aggregation_budget.clone().unwrap(),
                    tables
                        .data
                        .faces
                        .values()
                        .find(|f| !f.is_local)
                        .unwrap()
                        .clone(),
                )
            };
            assert_eq!(
                declaration_capacity(
                    gate.as_ref(),
                    &face,
                    KEY,
                    RouteAction::DeclareQueryable,
                    RouteFlow::Egress
                ),
                QueryCapacity::Business
            );
            // Interest permission is deliberately insufficient for a declaration reserve.
            assert!(gate.authorize(
                &crate::net::routing::interceptor::route_gate::transport_subject(
                    &face
                        .primitives
                        .as_any()
                        .downcast_ref::<crate::net::primitives::Mux>()
                        .unwrap()
                        .handler
                )
                .unwrap(),
                &RouteRequest {
                    action: RouteAction::Interest,
                    flow: RouteFlow::Ingress,
                    key: Some(KEY),
                    payload: None
                }
            ));
            let shared_limit = hat.limits[0] - hat.reserved[0];
            let per_map = hat.per_map[0] - hat.reserved_per_map[0];
            let remaining = shared_limit - hat.ledger.lock().unwrap().entries[0];
            let mut held_maps = Vec::new();
            let mut left = remaining;
            while left != 0 {
                let mut m = map(&hat, NativeHatKind::Entity);
                let take = left.min(per_map);
                for key in 0..take {
                    insert(&mut m, key as u32);
                }
                held_maps.push(m);
                left -= take;
            }
            let baseline = *aggregation.usage.lock().unwrap();
            let business = aggregation.business_limits();
            let held = aggregation
                .reserve(NativeAggregationUsage {
                    records: business.records - baseline.records,
                    references: business.references - baseline.references,
                    memberships: business.memberships - baseline.memberships,
                })
                .unwrap();
            let first = platform.declare_queryable(KEY).await.unwrap();
            tokio::time::sleep(Duration::from_millis(100)).await;
            assert_eq!(
                aggregation.usage.lock().unwrap().records,
                business.records,
                "unauthorized metadata reserve: {mode}"
            );
            first.undeclare().await.unwrap();
            gate.peer.store(true, Ordering::Release);
            assert_eq!(
                declaration_capacity(
                    gate.as_ref(),
                    &face,
                    KEY,
                    RouteAction::DeclareQueryable,
                    RouteFlow::Egress
                ),
                QueryCapacity::Control
            );
            let control = platform.declare_queryable(KEY).await.unwrap();
            tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    if aggregation.usage.lock().unwrap().records > business.records {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .unwrap();
            let replies = client
                .get(KEY)
                .timeout(Duration::from_secs(2))
                .await
                .unwrap();
            let query = tokio::time::timeout(Duration::from_secs(2), control.recv_async())
                .await
                .unwrap()
                .unwrap();
            query
                .reply(KEY, "reserved declaration reached control")
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
            gateway
                .tables
                .update_config(&runtime.config().lock().clone())
                .unwrap();
            assert!(Arc::ptr_eq(
                &hat,
                &gateway.tables.tables.read().unwrap().data.native_hat_budget
            ));
            gate.peer.store(false, Ordering::Release);
            assert_eq!(
                declaration_capacity(
                    gate.as_ref(),
                    &face,
                    KEY,
                    RouteAction::DeclareQueryable,
                    RouteFlow::Egress
                ),
                QueryCapacity::Business
            );
            drop(held_maps);
            drop(held);
            drop(querier);
            client.close().await.unwrap();
            drop(face);
            control.undeclare().await.unwrap();
            platform.close().await.unwrap();
            runtime.close().await.unwrap();
            empty(&hat);
            assert_eq!(
                *aggregation.usage.lock().unwrap(),
                NativeAggregationUsage::default()
            );
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn actual_router_peer_entity_and_non_keyexpr_interest_pressure_recovers_tcp_routes() {
        use crate::net::routing::dispatcher::{face::Face, pubsub::SubscriberInfo};
        use std::{sync::atomic::Ordering, time::Duration};
        use zenoh_protocol::{
            core::WireExpr,
            network::{
                declare::{common::ext::WireExprType, queryable::ext::QueryableInfoType},
                interest::{self, InterestMode, InterestOptions},
                Interest,
            },
        };
        for mode in ["router", "peer"] {
            let config = crate::Config::from_json5(&format!(r#"{{mode:"{mode}",listen:{{endpoints:["tcp/127.0.0.1:0"]}},scouting:{{multicast:{{enabled:false}}}}}}"#)).unwrap();
            let mut center = RuntimeBuilder::new(config).build().await.unwrap();
            center.install_route_gate(Arc::new(Allow)).unwrap();
            center.start().await.unwrap();
            let platform = crate::session::init(center.clone().into()).await.unwrap();
            let control = platform.declare_queryable("control").await.unwrap();
            let data = platform.declare_subscriber("data").await.unwrap();
            let config = crate::Config::from_json5(&format!(r#"{{mode:"client",connect:{{endpoints:["{}"]}},scouting:{{multicast:{{enabled:false}}}}}}"#,center.get_locators()[0])).unwrap();
            let mut edge = RuntimeBuilder::new(config).build().await.unwrap();
            edge.install_route_gate(Arc::new(Allow)).unwrap();
            edge.start().await.unwrap();
            let client = crate::session::init(edge.clone().into()).await.unwrap();
            let gateway = center.router();
            let (face, b) = {
                let tables = gateway.tables.tables.read().unwrap();
                (
                    Face {
                        state: tables
                            .data
                            .faces
                            .values()
                            .find(|f| !f.is_local && f.whatami.is_client())
                            .unwrap()
                            .clone(),
                        tables: gateway.tables.clone(),
                    },
                    tables.data.native_hat_budget.clone(),
                )
            };
            let counts = || {
                let l = b.ledger.lock().unwrap();
                (l.entries, l.bytes)
            };
            // Drive the real dispatcher on a connected face: aliased IDs retain
            // one Resource but must each consume their simple-map entry.
            for kind in ["subscriber", "queryable", "token"] {
                let expr = WireExpr::from(format!("pressure/{kind}"));
                let rejected = WireExpr::from(format!("refused/{kind}"));
                let baseline = counts();
                let declare =
                    |id,
                     expr: &WireExpr,
                     info,
                     send: &mut crate::net::routing::hat::SendDeclare| {
                        match kind {
                            "subscriber" => {
                                face.declare_subscriber(id, expr, &SubscriberInfo, 0, send)
                            }
                            "queryable" => face.declare_queryable(
                                id,
                                expr,
                                &QueryableInfoType {
                                    complete: info,
                                    distance: 0,
                                },
                                0,
                                send,
                            ),
                            _ => face.declare_token(id, expr, 0, None, send),
                        }
                    };
                let undeclare = |id, send: &mut crate::net::routing::hat::SendDeclare| match kind {
                    "subscriber" => face.undeclare_subscriber(id, &WireExpr::empty(), 0, send),
                    "queryable" => face.undeclare_queryable(id, &WireExpr::empty(), 0, send),
                    _ => face.undeclare_token(id, &WireExprType::null(), 0, send),
                };
                {
                    let _ctrl = gateway.tables.ctrl_lock.lock().unwrap();
                    for id in 10000..11984 {
                        declare(id, &expr, true, &mut |_, _| {});
                    }
                    assert_eq!(counts().0[0], baseline.0[0] + 1984, "{mode} {kind}");
                    let full = counts();
                    let mut emitted = 0;
                    declare(20000, &rejected, true, &mut |_, _| {
                        emitted += 1;
                    });
                    assert_eq!(emitted, 0);
                    assert_eq!(counts(), full);
                    assert!(Resource::get_resource(
                        &gateway.tables.tables.read().unwrap().data.root_res,
                        &format!("refused/{kind}")
                    )
                    .is_none());
                    declare(10001, &expr, false, &mut |_, _| {});
                    assert_eq!(counts(), full);
                    undeclare(10000, &mut |_, _| {});
                    assert_eq!(counts().0[0], full.0[0] - 1);
                    declare(20000, &expr, true, &mut |_, _| {});
                    assert_eq!(counts(), full);
                    for id in 10001..11984 {
                        undeclare(id, &mut |_, _| {});
                    }
                    undeclare(20000, &mut |_, _| {});
                    assert_eq!(counts(), baseline);
                }
            }
            {
                let _ctrl = gateway.tables.ctrl_lock.lock().unwrap();
                let baseline = counts();
                let message = |id, options, wire_expr| Interest {
                    id,
                    mode: InterestMode::Future,
                    options,
                    wire_expr,
                    ext_qos: interest::ext::QoSType::INTEREST,
                    ext_tstamp: None,
                    ext_nodeid: interest::ext::NodeIdType::DEFAULT,
                };
                let mut retained = Vec::new();
                for id in 30000..30248 {
                    let before = counts();
                    face.interest(
                        &mut message(id, InterestOptions::TOKENS, None),
                        &mut |_, _| {},
                    );
                    if counts().0[1] > before.0[1] {
                        retained.push(id);
                    }
                }
                assert!(!retained.is_empty());
                assert!(retained.len() <= 248);
                let full = counts();
                let before = {
                    let tables = gateway.tables.tables.read().unwrap();
                    tables
                        .data
                        .faces
                        .values()
                        .map(|f| {
                            (
                                f.id,
                                f.local_interests.len(),
                                f.pending_current_interests.len(),
                                f.next_native_interest_id.load(Ordering::SeqCst),
                            )
                        })
                        .collect::<Vec<_>>()
                };
                let mut emitted = 0;
                face.interest(
                    &mut message(
                        40000,
                        InterestOptions::KEYEXPRS + InterestOptions::TOKENS,
                        Some("refused/interest".into()),
                    ),
                    &mut |_, _| {
                        emitted += 1;
                    },
                );
                assert_eq!(emitted, 0);
                assert_eq!(counts(), full);
                assert!(!face.state.remote_key_interests.contains_key(&40000));
                assert!(Resource::get_resource(
                    &gateway.tables.tables.read().unwrap().data.root_res,
                    "refused/interest"
                )
                .is_none());
                let after = {
                    let tables = gateway.tables.tables.read().unwrap();
                    tables
                        .data
                        .faces
                        .values()
                        .map(|f| {
                            (
                                f.id,
                                f.local_interests.len(),
                                f.pending_current_interests.len(),
                                f.next_native_interest_id.load(Ordering::SeqCst),
                            )
                        })
                        .collect::<Vec<_>>()
                };
                assert_eq!(before, after);
                let mut final_msg = message(retained.pop().unwrap(), InterestOptions::TOKENS, None);
                final_msg.mode = InterestMode::Final;
                face.interest_final(&final_msg);
                face.interest(
                    &mut message(40000, InterestOptions::TOKENS, None),
                    &mut |_, _| {},
                );
                assert_eq!(counts(), full);
                retained.push(40000);
                for id in retained {
                    let mut msg = message(id, InterestOptions::TOKENS, None);
                    msg.mode = InterestMode::Final;
                    face.interest_final(&msg);
                }
                assert_eq!(counts(), baseline);
            }
            gateway
                .tables
                .update_config(&center.config().lock().clone())
                .unwrap();
            assert!(Arc::ptr_eq(
                &b,
                &gateway.tables.tables.read().unwrap().data.native_hat_budget
            ));
            let replies = client
                .get("control")
                .timeout(Duration::from_secs(1))
                .await
                .unwrap();
            let query = tokio::time::timeout(Duration::from_secs(1), control.recv_async())
                .await
                .unwrap()
                .unwrap();
            query.reply("control", "alive").await.unwrap();
            drop(query);
            assert!(replies.recv_async().await.unwrap().result().is_ok());
            client.put("data", "alive").await.unwrap();
            assert!(
                tokio::time::timeout(Duration::from_secs(1), data.recv_async())
                    .await
                    .unwrap()
                    .is_ok()
            );
            client.close().await.unwrap();
            edge.close().await.unwrap();
            drop(face);
            platform.close().await.unwrap();
            drop((control, data));
            center.close().await.unwrap();
            empty(&b);
        }
    }
    #[test]
    fn interest_map_control_counts_and_detached_drain_hold_their_reservations() {
        let b = Arc::new(NativeHatBudget {
            limits: [2, 4],
            per_map: [2, 3],
            reserved: [0, 2],
            reserved_per_map: [0, 1],
            reserved_bytes: 0,
            ..Default::default()
        });
        b.enable();
        let mut m = map(&b, NativeHatKind::Interest);
        insert(&mut m, 1);
        insert(&mut m, 2);
        assert!(m.prepare_insert(3).is_none());
        let p = m
            .prepare_insert_with_capacity(3, QueryCapacity::Control)
            .unwrap();
        m.insert_prepared(p, 3);
        assert!(m
            .prepare_insert_with_capacity(4, QueryCapacity::Control)
            .is_none());
        let p = m.prepare_insert(1).unwrap();
        assert_eq!(m.insert_prepared(p, 90), Some(1));
        let drain = m.drain();
        drop(m);
        assert_eq!(b.ledger.lock().unwrap().entries, [0, 3]);
        let mut other = map(&b, NativeHatKind::Interest);
        let p = other
            .prepare_insert_with_capacity(1, QueryCapacity::Control)
            .unwrap();
        other.insert_prepared(p, 1);
        assert!(other
            .prepare_insert_with_capacity(2, QueryCapacity::Control)
            .is_none());
        drop(drain);
        assert_eq!(b.ledger.lock().unwrap().entries, [0, 1]);
        insert(&mut other, 2);
        other.clear();
        empty(&b);
    }
}
