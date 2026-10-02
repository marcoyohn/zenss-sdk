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
    sync::{Arc, Mutex, Weak},
    time::{Duration, Instant},
};
use zenoh_keyexpr::keyexpr;
use zenoh_link::LinkAuthId;
use zenoh_protocol::{
    core::WhatAmI,
    network::{interest::InterestMode, DeclareBody, NetworkBodyMut, NetworkMessageMut},
    zenoh::{PushBody, ResponseBody},
};
use zenoh_result::ZResult;
use zenoh_transport::{multicast::TransportMulticast, unicast::TransportUnicast};

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
    pub role: WhatAmI,
}
#[derive(Clone, Debug)]
pub struct RouteRequest<'a> {
    pub action: RouteAction,
    pub flow: RouteFlow,
    pub key: Option<&'a str>,
    pub payload: Option<&'a [u8]>,
}
pub trait RouteGate: Send + Sync {
    fn authorize(&self, subject: &RouteSubject, request: &RouteRequest<'_>) -> bool;
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

type Claims = Arc<Mutex<HashMap<String, (Weak<()>, u32)>>>;
pub(crate) struct GateFactory {
    gate: Arc<dyn RouteGate>,
    claims: Claims,
}
impl GateFactory {
    pub(crate) fn new(gate: Arc<dyn RouteGate>) -> Self {
        Self {
            gate,
            claims: Arc::default(),
        }
    }
}
struct Pending {
    key: String,
    until: Instant,
}
#[derive(Default)]
struct Correlations {
    incoming: HashMap<u32, Pending>,
    outgoing: HashMap<u32, Pending>,
}
struct GateInterceptor {
    gate: Arc<dyn RouteGate>,
    transport: Option<TransportUnicast>,
    flow: RouteFlow,
    pending: Arc<Mutex<Correlations>>,
    claims: Claims,
    owner: Arc<()>,
    resource_ids: Mutex<HashMap<u16, String>>,
}
impl GateInterceptor {
    fn subject(&self) -> Option<RouteSubject> {
        let transport = self.transport.as_ref()?;
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
            tls_common_name,
            role: transport.get_whatami().ok()?,
        })
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
        if key.is_some_and(|k| k.len() > 2048) {
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
    fn compute_keyexpr_cache(&self, _: &keyexpr) -> Option<Box<dyn Any + Send + Sync>> {
        None
    }
    fn intercept(&self, msg: &mut NetworkMessageMut, ctx: &mut dyn InterceptorContext) -> bool {
        let Some(subject) = self.subject() else {
            return false;
        };
        let key = ctx.full_expr(msg).map(str::to_owned);
        match &msg.body {
            NetworkBodyMut::Request(request) => {
                let Some(key) = key else {
                    return false;
                };
                // Limit before coalescing a fragmented network buffer.
                if request.payload_size() > 20 * 1024 * 1024 + 32 * 1024 {
                    return false;
                }
                let zenoh_protocol::zenoh::RequestBody::Query(query) = &request.payload;
                let body = query
                    .ext_body
                    .as_ref()
                    .map(|body| crate::bytes::ZBytes::from(body.payload.clone()));
                let bytes = body.as_ref().map(|body| body.to_bytes());
                if !self.allowed_payload(&subject, RouteAction::Query, Some(&key), bytes.as_deref())
                {
                    return false;
                }
                let Ok(mut all) = self.pending.lock() else {
                    return false;
                };
                let map = match self.flow {
                    RouteFlow::Ingress => &mut all.incoming,
                    RouteFlow::Egress => &mut all.outgoing,
                };
                let now = Instant::now();
                map.retain(|_, p| p.until > now);
                // Duplicate IDs cannot overwrite the request to which a Reply is bound.
                if map.len() >= 1024 || map.contains_key(&request.id) {
                    return false;
                }
                let timeout = request
                    .ext_timeout
                    .unwrap_or(Duration::from_secs(10))
                    .min(Duration::from_secs(60));
                map.insert(
                    request.id,
                    Pending {
                        key,
                        until: now + timeout,
                    },
                );
                true
            }
            NetworkBodyMut::Response(response) => {
                let Ok(all) = self.pending.lock() else {
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
                self.allowed(&subject, RouteAction::Reply, Some(&p.key))
            }
            NetworkBodyMut::ResponseFinal(final_) => {
                let Ok(mut all) = self.pending.lock() else {
                    return false;
                };
                let map = match self.flow {
                    RouteFlow::Ingress => &mut all.outgoing,
                    RouteFlow::Egress => &mut all.incoming,
                };
                map.remove(&final_.rid).is_some_and(|p| {
                    p.until > Instant::now()
                        && self.allowed(&subject, RouteAction::Reply, Some(&p.key))
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
            NetworkBodyMut::Declare(declare) => match &declare.body {
                DeclareBody::DeclareQueryable(declaration) => {
                    if !self.allowed(&subject, RouteAction::DeclareQueryable, key.as_deref()) {
                        return false;
                    }
                    if self.flow == RouteFlow::Egress {
                        return true;
                    }
                    let Some(key) = key else {
                        return false;
                    };
                    let Ok(mut claims) = self.claims.lock() else {
                        return false;
                    };
                    claims.retain(|_, (owner, _)| owner.strong_count() > 0);
                    if let Some((owner, id)) = claims.get(&key) {
                        return owner
                            .upgrade()
                            .is_some_and(|owner| Arc::ptr_eq(&owner, &self.owner))
                            && *id == declaration.id;
                    }
                    if claims.len() >= 4096 {
                        return false;
                    }
                    claims.insert(key, (Arc::downgrade(&self.owner), declaration.id));
                    true
                }
                DeclareBody::DeclareSubscriber(_) => {
                    self.allowed(&subject, RouteAction::DeclareSubscriber, key.as_deref())
                }
                DeclareBody::DeclareToken(_) => {
                    self.allowed(&subject, RouteAction::LivelinessToken, key.as_deref())
                }
                DeclareBody::DeclareKeyExpr(declaration) => {
                    if !self.allowed(&subject, RouteAction::Resource, key.as_deref()) {
                        return false;
                    }
                    let Some(key) = key else {
                        return false;
                    };
                    let Ok(mut ids) = self.resource_ids.lock() else {
                        return false;
                    };
                    if !ids.contains_key(&declaration.id) && ids.len() >= 128 {
                        return false;
                    }
                    ids.insert(declaration.id, key);
                    true
                }
                DeclareBody::UndeclareKeyExpr(declaration) => {
                    if let Ok(mut ids) = self.resource_ids.lock() {
                        ids.remove(&declaration.id);
                    }
                    true
                }
                DeclareBody::UndeclareQueryable(declaration) => {
                    if self.flow == RouteFlow::Ingress {
                        if let Ok(mut claims) = self.claims.lock() {
                            claims.retain(|_, (owner, id)| {
                                !(*id == declaration.id
                                    && owner
                                        .upgrade()
                                        .is_some_and(|owner| Arc::ptr_eq(&owner, &self.owner)))
                            });
                        }
                    }
                    true
                }
                // Cleanup changes only this face's own IDs and never adds authority.
                DeclareBody::UndeclareSubscriber(_)
                | DeclareBody::UndeclareToken(_)
                | DeclareBody::DeclareFinal(_) => true,
            },
            NetworkBodyMut::Interest(interest) => {
                if matches!(interest.mode, InterestMode::Final) {
                    true
                } else {
                    self.allowed(&subject, RouteAction::Interest, key.as_deref())
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
        let pending = Arc::new(Mutex::new(Correlations::default()));
        let owner = Arc::new(());
        (
            Some(Box::new(GateInterceptor {
                gate: self.gate.clone(),
                transport: Some(transport.clone()),
                flow: RouteFlow::Ingress,
                pending: pending.clone(),
                claims: self.claims.clone(),
                owner: owner.clone(),
                resource_ids: Mutex::default(),
            })),
            Some(Box::new(GateInterceptor {
                gate: self.gate.clone(),
                transport: Some(transport.clone()),
                flow: RouteFlow::Egress,
                pending,
                claims: self.claims.clone(),
                owner,
                resource_ids: Mutex::default(),
            })),
        )
    }
    fn new_transport_multicast(&self, _: &TransportMulticast) -> Option<EgressInterceptor> {
        Some(Box::new(GateInterceptor {
            gate: self.gate.clone(),
            transport: None,
            flow: RouteFlow::Egress,
            pending: Arc::default(),
            claims: self.claims.clone(),
            owner: Arc::new(()),
            resource_ids: Mutex::default(),
        }))
    }
    fn new_peer_multicast(&self, _: &TransportMulticast) -> Option<IngressInterceptor> {
        Some(Box::new(GateInterceptor {
            gate: self.gate.clone(),
            transport: None,
            flow: RouteFlow::Ingress,
            pending: Arc::default(),
            claims: self.claims.clone(),
            owner: Arc::new(()),
            resource_ids: Mutex::default(),
        }))
    }
}
