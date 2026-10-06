//
// Copyright (c) 2025 ZettaScale Technology
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

//! ⚠️ WARNING ⚠️
//!
//! This module is intended for Zenoh's internal use.
//!
//! [Click here for Zenoh's documentation](https://docs.rs/zenoh/latest/zenoh)
use std::{
    any::Any,
    fmt::Debug,
    sync::{atomic::AtomicU32, Arc},
};

use zenoh_config::WhatAmI;
use zenoh_protocol::{
    core::{Region, ZenohIdProto},
    network::{
        declare::{queryable::ext::QueryableInfoType, QueryableId, SubscriberId, TokenId},
        interest::InterestId,
        Oam,
    },
};
use zenoh_result::ZResult;
use zenoh_sync::get_mut_unchecked;
use zenoh_transport::unicast::TransportUnicast;

use super::{
    super::dispatcher::{
        face::FaceState,
        tables::{NodeId, Resource, TablesData, TablesLock},
    },
    HatBaseTrait, HatTrait,
};
use crate::net::{
    routing::{
        dispatcher::{interests::RemoteInterest, queries::LocalQueryables, region::RegionMap},
        gateway::{FaceContext, LocalSubscribers, DEFAULT_NODE_ID},
        hat::{DispatcherContext, Remote, UnregisterFaceEntitiesResult},
    },
    runtime::Runtime,
};

mod interests;
mod pubsub;
mod queries;
mod token;

pub(crate) struct Hat {
    region: Region,
}

impl Debug for Hat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.region)
    }
}

impl Hat {
    #[tracing::instrument(level = "trace")]
    pub(crate) fn new(region: Region) -> Self {
        debug_assert!(region.bound().is_south());
        Self { region }
    }

    pub(self) fn face_hat<'f>(&self, face_state: &'f FaceState) -> &'f HatFace {
        face_state.hats[self.region].downcast_ref().unwrap()
    }

    pub(self) fn face_hat_mut<'f>(&self, face_state: &'f mut Arc<FaceState>) -> &'f mut HatFace {
        get_mut_unchecked(face_state).hats[self.region]
            .downcast_mut()
            .unwrap()
    }

    pub(self) fn hat_remote<'r>(&self, remote: &'r Remote) -> &'r HatRemote {
        remote.as_any().downcast_ref().unwrap()
    }

    /// Returns an iterator over the [`FaceContext`]s this hat [`Self::owns`].
    pub(crate) fn owned_face_contexts<'r>(
        &'r self,
        res: &'r Resource,
    ) -> impl Iterator<Item = &'r Arc<FaceContext>> {
        res.face_ctxs
            .values()
            .filter(move |ctx| self.owns(&ctx.face))
    }

    pub(crate) fn owned_faces<'h, 't>(
        &'h self,
        tables: &'t TablesData,
    ) -> impl Iterator<Item = &'t Arc<FaceState>> + 'h
    where
        't: 'h,
    {
        tables.faces.values().filter(|face| self.owns(face))
    }

    pub(crate) fn owned_faces_mut<'h, 't>(
        &'h self,
        tables: &'t mut TablesData,
    ) -> impl Iterator<Item = &'t mut Arc<FaceState>> + 'h
    where
        't: 'h,
    {
        tables.faces.values_mut().filter(|face| self.owns(face))
    }
}

impl HatBaseTrait for Hat {
    fn init(&mut self, _tables: &mut TablesData, _runtime: Runtime) -> ZResult<()> {
        Ok(())
    }

    fn new_face(&self, _tables: &TablesData) -> Box<dyn Any + Send + Sync> {
        Box::new(HatFace::new(_tables))
    }

    #[cfg(feature = "zenss-route-gate")]
    fn native_aggregation_usage(
        &self,
        face: &Arc<FaceState>,
    ) -> super::super::dispatcher::local_resources::NativeAggregationUsage {
        let hat = self.face_hat(face);
        hat.local_subs
            .native_usage()
            .add(hat.local_qabls.native_usage())
    }

    #[cfg(feature = "zenss-route-gate")]
    fn bind_native_aggregation(
        &self,
        face: &mut Arc<FaceState>,
        reservation: &mut super::super::dispatcher::local_resources::NativeAggregationReservation,
    ) {
        let hat = self.face_hat_mut(face);
        let subs = reservation.split(hat.local_subs.native_usage());
        let qabls = reservation.split(hat.local_qabls.native_usage());
        hat.local_subs.bind_native_reservation(subs);
        hat.local_qabls.bind_native_reservation(qabls);
    }

    fn new_resource(&self) -> Box<dyn Any + Send + Sync> {
        Box::new(HatContext::new())
    }

    fn new_remote(&self, face: &Arc<FaceState>, _nid: NodeId) -> Option<Remote> {
        Some(Remote(Box::new(face.clone())))
    }

    fn new_local_face(
        &mut self,
        ctx: DispatcherContext,
        _tables_lock: &Arc<TablesLock>,
    ) -> ZResult<()> {
        debug_assert!(self.owns(ctx.src_face));
        debug_assert!(ctx.src_face.region.bound().is_south());

        // NOTE(regions): see `new_transport_unicast_face`

        self.disable_all_routes(ctx.tables);

        Ok(())
    }

    #[tracing::instrument(level = "debug", skip(ctx, _transport, _other_hats), fields(src = %ctx.src_face), ret)]
    fn new_transport_unicast_face(
        &mut self,
        ctx: DispatcherContext,
        _transport: &TransportUnicast,
        _other_hats: RegionMap<&dyn HatTrait>,
    ) -> ZResult<()> {
        debug_assert!(self.owns(ctx.src_face));
        debug_assert!(ctx.src_face.region.bound().is_south());

        // NOTE(regions):
        // 1. The broker hat is never the north hat, thus there are no interests to re-propagate
        // 2. The broker hat doesn't re-propagate entities between clients

        self.disable_all_routes(ctx.tables);

        Ok(())
    }

    fn close_face(&mut self, ctx: DispatcherContext) {
        let mut face_clone = ctx.src_face.clone();
        let face = get_mut_unchecked(&mut face_clone);
        let hat_face = match face.hats[self.region].downcast_mut::<HatFace>() {
            Some(hate_face) => hate_face,
            None => {
                tracing::error!("Error downcasting face hat in close_face!");
                return;
            }
        };

        hat_face.remote_interests.clear();
        hat_face.local_subs.clear();
        hat_face.local_qabls.clear();
        hat_face.local_tokens.clear();
    }

    fn handle_oam(
        &mut self,
        _ctx: DispatcherContext,
        _oam: &mut Oam,
        _other_hats: RegionMap<&mut dyn HatTrait>,
    ) -> ZResult<()> {
        Ok(())
    }

    #[inline]
    fn map_routing_context(
        &self,
        _tables: &TablesData,
        _face: &FaceState,
        _routing_context: NodeId,
    ) -> NodeId {
        0
    }

    fn info(&self) -> String {
        "graph {}".to_string()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn mode(&self) -> WhatAmI {
        WhatAmI::Client
    }

    fn region(&self) -> Region {
        self.region
    }

    fn remote_node_id_to_zid(&self, src: &FaceState, node_id: NodeId) -> Option<ZenohIdProto> {
        debug_assert_eq!(node_id, DEFAULT_NODE_ID);

        Some(src.zid)
    }

    #[tracing::instrument(level = "trace", skip(_tables), ret)]
    fn gateways_of(&self, _tables: &TablesData, _zid: &ZenohIdProto) -> Option<Vec<ZenohIdProto>> {
        None
    }

    #[tracing::instrument(level = "trace", skip(_tables), ret)]
    fn gateways(&self, _tables: &TablesData) -> Option<Vec<ZenohIdProto>> {
        None
    }
}

struct HatContext {}

impl HatContext {
    fn new() -> Self {
        Self {}
    }
}

use crate::net::routing::dispatcher::local_resources::{NativeHatKind, NativeHatMap};

struct HatFace {
    next_id: AtomicU32, // @TODO: manage rollover and uniqueness
    remote_interests: NativeHatMap<InterestId, RemoteInterest>,
    local_subs: LocalSubscribers,
    remote_subs: NativeHatMap<SubscriberId, Arc<Resource>>,
    local_qabls: LocalQueryables,
    remote_qabls: NativeHatMap<QueryableId, (Arc<Resource>, QueryableInfoType)>,
    local_tokens: NativeHatMap<Arc<Resource>, TokenId>,
    remote_tokens: NativeHatMap<TokenId, Arc<Resource>>,
}

impl HatFace {
    fn new(_tables: &TablesData) -> Self {
        Self {
            next_id: AtomicU32::new(1),
            remote_interests: NativeHatMap::new(_tables, NativeHatKind::Interest),
            #[cfg(feature = "zenss-route-gate")]
            local_subs: LocalSubscribers::with_budget(_tables.native_aggregation_budget.as_ref()),
            #[cfg(not(feature = "zenss-route-gate"))]
            local_subs: LocalSubscribers::new(),
            remote_subs: NativeHatMap::new(_tables, NativeHatKind::Entity),
            #[cfg(feature = "zenss-route-gate")]
            local_qabls: LocalQueryables::with_budget(_tables.native_aggregation_budget.as_ref()),
            #[cfg(not(feature = "zenss-route-gate"))]
            local_qabls: LocalQueryables::new(),
            remote_qabls: NativeHatMap::new(_tables, NativeHatKind::Entity),
            local_tokens: NativeHatMap::new(_tables, NativeHatKind::Entity),
            remote_tokens: NativeHatMap::new(_tables, NativeHatKind::Entity),
        }
    }
}

impl HatTrait for Hat {
    #[tracing::instrument(level = "debug", skip(ctx), ret)]
    fn unregister_face_entities(
        &mut self,
        ctx: DispatcherContext,
    ) -> super::UnregisterFaceEntitiesResult {
        debug_assert!(self.owns(ctx.src_face));

        let fid = ctx.src_face.id;

        let removed_subscribers = self
            .face_hat_mut(ctx.src_face)
            .remote_subs
            .drain()
            .map(|(_, mut res)| {
                if let Some(ctx) = get_mut_unchecked(&mut res).face_ctxs.get_mut(&fid) {
                    get_mut_unchecked(ctx).subs = None;
                }

                res
            })
            .collect();

        let removed_queryables = self
            .face_hat_mut(ctx.src_face)
            .remote_qabls
            .drain()
            .map(|(_, (mut res, _))| {
                if let Some(ctx) = get_mut_unchecked(&mut res).face_ctxs.get_mut(&fid) {
                    get_mut_unchecked(ctx).qabl = None;
                }

                res
            })
            .collect();

        let removed_tokens = self
            .face_hat_mut(ctx.src_face)
            .remote_tokens
            .drain()
            .map(|(_, mut res)| {
                if let Some(ctx) = get_mut_unchecked(&mut res).face_ctxs.get_mut(&fid) {
                    get_mut_unchecked(ctx).token = false;
                }

                res
            })
            .collect();
        UnregisterFaceEntitiesResult {
            removed_subscribers,
            removed_queryables,
            removed_tokens,
        }
    }
}

type HatRemote = Arc<FaceState>;
