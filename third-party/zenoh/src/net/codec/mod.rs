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
pub(crate) mod linkstate;

#[derive(Clone, Copy)]
pub struct Zenoh080Routing {
    #[cfg(feature = "zenss-route-gate")]
    native_limits: bool,
}

impl Zenoh080Routing {
    pub const fn new() -> Self {
        Self {
            #[cfg(feature = "zenss-route-gate")]
            native_limits: false,
        }
    }
}

#[cfg(feature = "zenss-route-gate")]
impl Zenoh080Routing {
    pub(crate) const fn native_bounded() -> Self {
        Self {
            native_limits: true,
        }
    }
}
