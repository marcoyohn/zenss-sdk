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
use std::{collections::HashMap, fmt::Debug, num::NonZeroU16};

use zenoh_config::TransportWeight;
use zenoh_protocol::core::{Locator, WhatAmI, ZenohIdProto};
use zenoh_result::ZResult;

pub const PID: u64 = 1; // 0x01
pub const WAI: u64 = 1 << 1; // 0x02
pub const LOC: u64 = 1 << 2; // 0x04
pub const WGT: u64 = 1 << 3; // 0x08
pub const GWY: u64 = 1 << 4; // 0x16

//  7 6 5 4 3 2 1 0
// +-+-+-+-+-+-+-+-+
// ~X|X|X|G|H|L|W|P~
// +-+-+-+-+-+-+-+-+
// ~     psid      ~
// +---------------+
// ~      sn       ~
// +---------------+
// ~      zid      ~ if P == 1
// +---------------+
// ~    whatami    ~ if W == 1
// +---------------+
// ~  [locators]   ~ if L == 1
// +---------------+
// ~    [links]    ~
// +---------------+
// ~    [weights]  ~ if H = 1
// +---------------+
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LinkState {
    pub(crate) psid: u64,
    pub(crate) sn: u64,
    pub(crate) zid: Option<ZenohIdProto>,
    pub(crate) whatami: Option<WhatAmI>,
    pub(crate) locators: Option<Vec<Locator>>,
    pub(crate) links: Vec<u64>,
    pub(crate) link_weights: Option<Vec<u16>>,
    pub(crate) is_gateway: bool,
}

#[derive(Default, Copy, Clone, PartialEq, Eq)]
pub(crate) struct LinkEdgeWeight(pub(crate) Option<NonZeroU16>);

impl Debug for LinkEdgeWeight {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.0 {
            Some(w) => w.fmt(f),
            None => self.0.fmt(f),
        }
    }
}

impl LinkEdgeWeight {
    const DEFAULT_LINK_WEIGHT: u16 = 100;

    pub(crate) fn new(val: NonZeroU16) -> Self {
        LinkEdgeWeight(Some(val))
    }

    pub(crate) fn from_raw(val: u16) -> Self {
        LinkEdgeWeight(NonZeroU16::new(val))
    }

    pub(crate) fn value(&self) -> u16 {
        match self.0 {
            Some(v) => v.get(),
            None => Self::DEFAULT_LINK_WEIGHT,
        }
    }

    pub(crate) fn as_raw(&self) -> u16 {
        match self.0 {
            Some(v) => v.get(),
            None => 0,
        }
    }

    pub(crate) fn is_set(&self) -> bool {
        self.0.is_some()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LocalLinkState {
    pub(crate) sn: u64,
    pub(crate) zid: ZenohIdProto,
    pub(crate) whatami: WhatAmI,
    pub(crate) locators: Option<Vec<Locator>>,
    pub(crate) links: HashMap<ZenohIdProto, LinkEdgeWeight>,
    pub(crate) is_gateway: bool,
}

impl LinkState {
    #[cfg(test)]
    #[doc(hidden)]
    #[allow(dead_code)]
    pub fn rand() -> Self {
        use rand::Rng;

        const MIN: usize = 1;
        const MAX: usize = 16;

        let mut rng = rand::thread_rng();

        let psid: u64 = rng.gen();
        let sn: u64 = rng.gen();
        let zid = if rng.gen_bool(0.5) {
            Some(ZenohIdProto::default())
        } else {
            None
        };
        let whatami = if rng.gen_bool(0.5) {
            Some(WhatAmI::rand())
        } else {
            None
        };
        let locators = if rng.gen_bool(0.5) {
            let n = rng.gen_range(MIN..=MAX);
            let locators = (0..n).map(|_| Locator::rand()).collect::<Vec<Locator>>();
            Some(locators)
        } else {
            None
        };
        let n = rng.gen_range(MIN..=MAX);
        let links = (0..n).map(|_| rng.gen()).collect::<Vec<u64>>();
        let link_weights = if rng.gen_bool(0.5) {
            let n = rng.gen_range(MIN..=MAX);
            let weights = (0..n).map(|_| rng.gen()).collect::<Vec<u16>>();
            Some(weights)
        } else {
            None
        };
        let is_gateway = rng.gen_bool(0.5);

        Self {
            psid,
            sn,
            zid,
            whatami,
            locators,
            links,
            link_weights,
            is_gateway,
        }
    }
}

//  7 6 5 4 3 2 1 0
// +-+-+-+-+-+-+-+-+
// |X|X|X|LK_ST_LS |
// +-+-+-+---------+
// ~ [link_states] ~
// +---------------+
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LinkStateList {
    pub(crate) link_states: Vec<LinkState>,
}

impl LinkStateList {
    #[cfg(test)]
    #[doc(hidden)]
    #[allow(dead_code)]
    pub fn rand() -> Self {
        use rand::Rng;

        const MIN: usize = 1;
        const MAX: usize = 16;

        let mut rng = rand::thread_rng();

        let n = rng.gen_range(MIN..=MAX);
        let link_states = (0..n)
            .map(|_| LinkState::rand())
            .collect::<Vec<LinkState>>();

        Self { link_states }
    }
}

pub(crate) fn link_weights_from_config(
    link_weights: Vec<TransportWeight>,
    network_name: &str,
) -> ZResult<HashMap<ZenohIdProto, LinkEdgeWeight>> {
    let mut link_weights_by_zid = HashMap::new();
    for lw in link_weights {
        if link_weights_by_zid
            .insert(lw.dst_zid.into(), LinkEdgeWeight::new(lw.weight))
            .is_some()
        {
            bail!(
                "{} config contains a duplicate zid value for transport weight: {}",
                network_name,
                lw.dst_zid
            );
        }
    }
    Ok(link_weights_by_zid)
}

impl From<LinkEdgeWeight> for Option<u16> {
    fn from(value: LinkEdgeWeight) -> Self {
        value.is_set().then_some(value.value())
    }
}

#[derive(PartialEq, Debug, serde::Serialize)]
pub(crate) struct LinkInfo {
    pub(crate) src_weight: Option<u16>,
    pub(crate) dst_weight: Option<u16>,
    pub(crate) actual_weight: u16,
}

// ZenSS native topology limits. Counts protect allocation before mutation;
// they are not allocator/RSS byte guarantees. Wire IDs remain interoperable.
#[cfg(feature = "zenss-route-gate")]
pub(crate) const NATIVE_TOPOLOGY_NODES: usize = 256;
#[cfg(feature = "zenss-route-gate")]
pub(crate) const NATIVE_TOPOLOGY_LINKS: usize = 64;
#[cfg(feature = "zenss-route-gate")]
pub(crate) const NATIVE_TOPOLOGY_MAPPINGS: usize = 1024;
#[cfg(feature = "zenss-route-gate")]
pub(crate) const NATIVE_TOPOLOGY_LOCATORS: usize = 8;
#[cfg(feature = "zenss-route-gate")]
pub(crate) const NATIVE_TOPOLOGY_PSID: u64 = u16::MAX as u64;
#[cfg(feature = "zenss-route-gate")]
pub(crate) const NATIVE_TOPOLOGY_FRAME_BYTES: usize = 1024 * 1024;

#[cfg(feature = "zenss-route-gate")]
pub(crate) fn admit_native_topology(
    states: &[LinkState],
    mappings: &std::collections::BTreeMap<usize, ZenohIdProto>,
    graph_nodes: impl Iterator<Item = ZenohIdProto>,
) -> bool {
    use std::collections::HashSet;
    if states.len() > NATIVE_TOPOLOGY_NODES || mappings.len() > NATIVE_TOPOLOGY_MAPPINGS {
        return false;
    }
    let mut planned = mappings.clone();
    let mut ids = HashSet::new();
    for state in states {
        if state.psid > NATIVE_TOPOLOGY_PSID
            || !ids.insert(state.psid)
            || state.links.len() > NATIVE_TOPOLOGY_LINKS
            || state.links.iter().any(|id| *id > NATIVE_TOPOLOGY_PSID)
            || state
                .link_weights
                .as_ref()
                .is_some_and(|weights| weights.len() != state.links.len())
            || state.locators.as_ref().is_some_and(|locators| {
                locators.len() > NATIVE_TOPOLOGY_LOCATORS
                    || locators
                        .iter()
                        .any(|loc| loc.as_str().len() > u8::MAX as usize)
            })
        {
            return false;
        }
        if let Some(zid) = state.zid {
            planned.insert(state.psid as usize, zid);
            if planned.len() > NATIVE_TOPOLOGY_MAPPINGS {
                return false;
            }
        }
    }
    // Include every possibly created placeholder, not just explicitly declared nodes.
    // Account before detached-node cleanup, so transient graph peaks stay bounded.
    let mut nodes = graph_nodes.collect::<HashSet<_>>();
    if nodes.len() > NATIVE_TOPOLOGY_NODES {
        return false;
    }
    for state in states {
        if let Some(zid) = planned.get(&(state.psid as usize)) {
            nodes.insert(*zid);
        }
        for id in &state.links {
            if let Some(zid) = planned.get(&(*id as usize)) {
                nodes.insert(*zid);
            }
        }
        if nodes.len() > NATIVE_TOPOLOGY_NODES {
            return false;
        }
    }
    true
}

#[cfg(all(test, feature = "zenss-route-gate"))]
mod native_topology_tests {
    use super::*;
    use std::collections::BTreeMap;
    fn zid(id: usize) -> ZenohIdProto {
        format!("{:x}", id + 1).parse().unwrap()
    }
    fn state(psid: u64, id: usize) -> LinkState {
        LinkState {
            psid,
            sn: 1,
            zid: Some(zid(id)),
            whatami: Some(WhatAmI::Router),
            locators: None,
            links: vec![],
            link_weights: None,
            is_gateway: false,
        }
    }
    #[test]
    fn preflight_includes_placeholders_and_preserves_input_maps() {
        let mappings = BTreeMap::from([(0, zid(0)), (1, zid(255)), (2, zid(256))]);
        let old = mappings.clone();
        let mut incoming = state(0, 0);
        incoming.zid = None;
        incoming.links = vec![1];
        assert!(admit_native_topology(
            &[incoming.clone()],
            &mappings,
            (0..255).map(zid)
        ));
        incoming.links.push(2);
        assert!(!admit_native_topology(
            &[incoming],
            &mappings,
            (0..255).map(zid)
        ));
        assert_eq!(mappings, old);
        assert!(!admit_native_topology(
            &[state(3, 256)],
            &mappings,
            (0..256).map(zid)
        ));
    }
    #[test]
    fn preflight_caps_mappings_and_rejects_ambiguous_or_invalid_states() {
        let mappings = (0..NATIVE_TOPOLOGY_MAPPINGS)
            .map(|id| (id, zid(0)))
            .collect::<BTreeMap<_, _>>();
        assert!(!admit_native_topology(
            &[state(NATIVE_TOPOLOGY_PSID, 0)],
            &mappings,
            std::iter::once(zid(0))
        ));
        assert!(admit_native_topology(
            &[state(0, 1)],
            &mappings,
            std::iter::once(zid(0))
        ));
        let empty = BTreeMap::new();
        assert!(!admit_native_topology(
            &[state(0, 1), state(0, 2)],
            &empty,
            std::iter::empty()
        ));
        let mut incoming = state(0, 0);
        incoming.links = vec![0; NATIVE_TOPOLOGY_LINKS + 1];
        assert!(!admit_native_topology(
            &[incoming.clone()],
            &empty,
            std::iter::empty()
        ));
        incoming.links = vec![0];
        incoming.link_weights = Some(vec![]);
        assert!(!admit_native_topology(
            &[incoming.clone()],
            &empty,
            std::iter::empty()
        ));
        incoming.link_weights = None;
        incoming.locators = Some(vec![
            "tcp/127.0.0.1:1".parse().unwrap();
            NATIVE_TOPOLOGY_LOCATORS + 1
        ]);
        assert!(!admit_native_topology(
            &[incoming],
            &empty,
            std::iter::empty()
        ));
    }
}
