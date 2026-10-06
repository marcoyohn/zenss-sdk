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
        dispatcher::{interests::RemoteInterest, region::RegionMap},
        gateway::{FaceContext, DEFAULT_NODE_ID},
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
        debug_assert!(region.bound().is_north());

        Self { region }
    }

    pub(self) fn face_hat<'f>(&self, face_state: &'f Arc<FaceState>) -> &'f HatFace {
        face_state.hats[self.region].downcast_ref().unwrap()
    }

    pub(self) fn face_hat_mut<'f>(&self, face_state: &'f mut Arc<FaceState>) -> &'f mut HatFace {
        get_mut_unchecked(face_state).hats[self.region]
            .downcast_mut()
            .unwrap()
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

    fn new_resource(&self) -> Box<dyn Any + Send + Sync> {
        Box::new(HatContext::new())
    }

    fn new_remote(&self, face: &Arc<FaceState>, _nid: NodeId) -> Option<Remote> {
        Some(Remote(Box::new(face.clone())))
    }

    fn new_local_face(
        &mut self,
        _ctx: DispatcherContext,
        _tables_ref: &Arc<TablesLock>,
    ) -> ZResult<()> {
        bail!("Local sessions should not be bound to client hats");
    }

    #[tracing::instrument(level = "debug", skip(ctx, _transport, other_hats), fields(src = %ctx.src_face), ret)]
    fn new_transport_unicast_face(
        &mut self,
        mut ctx: DispatcherContext,
        _transport: &TransportUnicast,
        other_hats: RegionMap<&dyn HatTrait>,
    ) -> ZResult<()> {
        debug_assert!(self.owns(ctx.src_face));
        debug_assert!(ctx.src_face.remote_bound.is_south());
        debug_assert!(ctx.src_face.region.bound().is_north());
        debug_assert_eq!(self.owned_faces(ctx.tables).count(), 1);

        self.repropagate_interests(ctx.reborrow(), &other_hats);
        self.repropagate_subscribers(ctx.reborrow(), &other_hats);
        self.repropagate_queryables(ctx.reborrow(), &other_hats);
        self.repropagate_tokens(ctx.reborrow(), &other_hats);
        self.disable_all_routes(ctx.tables);
        Ok(())
    }

    fn close_face(&mut self, ctx: DispatcherContext) {
        debug_assert!(self.owns(ctx.src_face));

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

    fn gateways_of(&self, _tables: &TablesData, _zid: &ZenohIdProto) -> Option<Vec<ZenohIdProto>> {
        bug!("Unreachable");
        None
    }

    fn gateways(&self, _tables: &TablesData) -> Option<Vec<ZenohIdProto>> {
        bug!("Unreachable");
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
    local_subs: NativeHatMap<Arc<Resource>, SubscriberId>,
    remote_subs: NativeHatMap<SubscriberId, Arc<Resource>>,
    local_qabls: NativeHatMap<Arc<Resource>, (QueryableId, QueryableInfoType)>,
    remote_qabls: NativeHatMap<QueryableId, (Arc<Resource>, QueryableInfoType)>,
    local_tokens: NativeHatMap<Arc<Resource>, TokenId>,
    remote_tokens: NativeHatMap<TokenId, Arc<Resource>>,
}

impl HatFace {
    fn new(_tables: &TablesData) -> Self {
        Self {
            next_id: AtomicU32::new(1),
            remote_interests: NativeHatMap::new(_tables, NativeHatKind::Interest),
            local_subs: NativeHatMap::new(_tables, NativeHatKind::Entity),
            remote_subs: NativeHatMap::new(_tables, NativeHatKind::Entity),
            local_qabls: NativeHatMap::new(_tables, NativeHatKind::Entity),
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

#[cfg(all(test, feature = "zenss-route-gate"))]
mod native_hat_admission_tests {
    use super::*;
    use crate::net::{
        routing::{
            dispatcher::pubsub::SubscriberInfo,
            hat::{HatPubSubTrait, HatQueriesTrait, HatTokenTrait},
            interceptor::route_gate::{RouteGate, RouteRequest, RouteSubject},
        },
        runtime::RuntimeBuilder,
    };
    use std::sync::atomic::Ordering;
    struct Allow;
    impl RouteGate for Allow {
        fn authorize(&self, _: &RouteSubject, _: &RouteRequest<'_>) -> bool {
            true
        }
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn upstream_simple_map_refusal_precedes_id_info_and_wire_mutation() {
        let cfg=crate::Config::from_json5(r#"{mode:"router",listen:{endpoints:["tcp/127.0.0.1:0"]},scouting:{multicast:{enabled:false}}}"#).unwrap();
        let center = crate::open(cfg).await.unwrap();
        let cfg=crate::Config::from_json5(&format!(r#"{{mode:"client",connect:{{endpoints:["{}"]}},scouting:{{multicast:{{enabled:false}}}}}}"#,center.runtime().get_locators()[0])).unwrap();
        let mut runtime = RuntimeBuilder::new(cfg).build().await.unwrap();
        runtime.install_route_gate(Arc::new(Allow)).unwrap();
        runtime.start().await.unwrap();
        let session = crate::session::init(runtime.clone().into()).await.unwrap();
        let gateway = runtime.router();
        {
            let _ctrl = gateway.tables.ctrl_lock.lock().unwrap();
            let mut tables = gateway.tables.tables.write().unwrap();
            let tables = &mut *tables;
            let mut source = tables
                .data
                .faces
                .values()
                .find(|f| f.is_local)
                .unwrap()
                .clone();
            let mut dst = tables
                .data
                .faces
                .values()
                .find(|f| !f.is_local)
                .unwrap()
                .clone();

            let mut resources = Vec::new();
            for id in 0..1984 {
                let mut root = tables.data.root_res.clone();
                resources.push(
                    Resource::make_resource(tables, &mut root, &format!("retained/{id}")).unwrap(),
                );
            }
            let mut root = tables.data.root_res.clone();
            let mut refused = Resource::make_resource(tables, &mut root, "refused/local").unwrap();
            let hat = tables.hats[Region::North]
                .as_any_mut()
                .downcast_mut::<Hat>()
                .unwrap();
            for kind in ["subscriber", "queryable", "token"] {
                let hf = hat.face_hat_mut(&mut dst);
                for (id, res) in resources.iter().enumerate() {
                    match kind {
                        "subscriber" => {
                            let p = hf.local_subs.prepare_insert(res.clone()).unwrap();
                            hf.local_subs.insert_prepared(p, id as u32);
                        }
                        "queryable" => {
                            let p = hf.local_qabls.prepare_insert(res.clone()).unwrap();
                            hf.local_qabls.insert_prepared(
                                p,
                                (
                                    id as u32,
                                    QueryableInfoType {
                                        complete: true,
                                        distance: 0,
                                    },
                                ),
                            );
                        }
                        _ => {
                            let p = hf.local_tokens.prepare_insert(res.clone()).unwrap();
                            hf.local_tokens.insert_prepared(p, id as u32);
                        }
                    }
                }
                let before = hat.face_hat(&dst).next_id.load(Ordering::SeqCst);
                let mut emitted = 0;
                {
                    let mut send =
                        |_: &Arc<dyn crate::net::primitives::EPrimitives + Send + Sync>,
                         _: crate::net::routing::RoutingContext<
                            zenoh_protocol::network::Declare,
                        >| {
                            emitted += 1;
                        };
                    let ctx = DispatcherContext {
                        tables_lock: &gateway.tables,
                        tables: &mut tables.data,
                        src_face: &mut source,
                        send_declare: &mut send,
                    };
                    match kind {
                        "subscriber" => {
                            hat.propagate_subscriber(ctx, refused.clone(), Some(SubscriberInfo))
                        }
                        "queryable" => hat.propagate_queryable(
                            ctx,
                            refused.clone(),
                            Some(QueryableInfoType {
                                complete: true,
                                distance: 0,
                            }),
                        ),
                        _ => hat.propagate_token(ctx, refused.clone()),
                    }
                }
                assert_eq!(emitted, 0);
                assert_eq!(hat.face_hat(&dst).next_id.load(Ordering::SeqCst), before);
                let hf = hat.face_hat_mut(&mut dst);
                match kind {
                    "subscriber" => {
                        assert!(!hf.local_subs.contains_key(&refused));
                        hf.local_subs.clear();
                    }
                    "queryable" => {
                        assert!(!hf.local_qabls.contains_key(&refused));
                        hf.local_qabls.clear();
                    }
                    _ => {
                        assert!(!hf.local_tokens.contains_key(&refused));
                        hf.local_tokens.clear();
                    }
                }
                {
                    let mut send =
                        |_: &Arc<dyn crate::net::primitives::EPrimitives + Send + Sync>,
                         _: crate::net::routing::RoutingContext<
                            zenoh_protocol::network::Declare,
                        >| {
                            emitted += 1;
                        };
                    let ctx = DispatcherContext {
                        tables_lock: &gateway.tables,
                        tables: &mut tables.data,
                        src_face: &mut source,
                        send_declare: &mut send,
                    };
                    match kind {
                        "subscriber" => {
                            hat.propagate_subscriber(ctx, refused.clone(), Some(SubscriberInfo))
                        }
                        "queryable" => hat.propagate_queryable(
                            ctx,
                            refused.clone(),
                            Some(QueryableInfoType {
                                complete: true,
                                distance: 0,
                            }),
                        ),
                        _ => hat.propagate_token(ctx, refused.clone()),
                    }
                }
                assert_eq!(emitted, 1);
                assert_eq!(
                    hat.face_hat(&dst).next_id.load(Ordering::SeqCst),
                    before + 1
                );
                let hf = hat.face_hat_mut(&mut dst);
                hf.local_subs.clear();
                hf.local_qabls.clear();
                hf.local_tokens.clear();
            }
            for mut res in resources {
                Resource::clean(&mut res);
            }
            Resource::clean(&mut refused);
        }
        session.close().await.unwrap();
        runtime.close().await.unwrap();
        center.close().await.unwrap();
    }
}
