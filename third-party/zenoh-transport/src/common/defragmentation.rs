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
use zenoh_buffers::{
    reader::{HasReader, Reader},
    ZBuf, ZSlice,
};
use zenoh_codec::{RCodec, Zenoh080Reliability};
use zenoh_protocol::{
    core::{Bits, Reliability},
    network::NetworkMessage,
    transport::TransportSn,
};
use zenoh_result::{bail, ZResult};

use super::seq_num::SeqNum;

#[derive(Debug)]
pub(crate) struct DefragBuffer {
    reliability: Reliability,
    pub(crate) sn: SeqNum,
    // ZenSS: a tiny ZSlice can reference a whole RX batch. Retain only the
    // accepted bytes, with bounded compact chunk references and no original backing allocations.
    buffer: ZBuf,
    partial: Vec<u8>,
    capacity: usize,
    len: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use zenoh_buffers::{buffer::Buffer, writer::HasWriter};
    use zenoh_codec::{WCodec, Zenoh080};
    use zenoh_protocol::network::{NetworkBody, NetworkMessageExt, ResponseFinal};
    fn make(capacity: usize) -> DefragBuffer {
        DefragBuffer::make(Reliability::Reliable, Bits::U32, capacity).unwrap()
    }
    #[test]
    #[ignore = "isolated repeated large-frame allocator/RSS acceptance"]
    fn compact_reassembly_near_frame_reclaims_storage_over_many_cycles() {
        use zenoh_protocol::{common::ZExtBody, network::Oam};
        const FRAME: usize = 20 * 1024 * 1024 + 64 * 1024;
        let rounds: usize = std::env::var("ZENSS_RX_PRESSURE_ROUNDS")
            .unwrap_or_else(|_| "12".into())
            .parse()
            .unwrap();
        assert!((6..=20).contains(&rounds));
        for round in 0..rounds {
            let payload_len = FRAME - 128;
            let message: NetworkMessage = NetworkBody::OAM(Oam {
                id: 17,
                body: ZExtBody::ZBuf(vec![23u8; payload_len].into()),
                ext_qos: Default::default(),
                ext_tstamp: None,
            })
            .into();
            let mut bytes = Vec::new();
            Zenoh080::new()
                .write(&mut bytes.writer(), message.as_ref())
                .unwrap();
            assert!(bytes.len() <= FRAME);
            let encoded_len = bytes.len();
            let input = ZSlice::from(bytes);
            let mut defrag = make(FRAME);
            for (sn, start) in (0..encoded_len).step_by(4093).enumerate() {
                defrag
                    .push(
                        sn as u32,
                        input
                            .subslice(start..(start + 4093).min(encoded_len))
                            .unwrap(),
                    )
                    .unwrap();
                assert!(defrag.buffer.zslices().count() <= FRAME.div_ceil(4096));
                assert!(defrag.partial.capacity() <= 4096);
            }
            let decoded = defrag.defragment().unwrap();
            let NetworkBody::OAM(oam) = decoded.body else {
                panic!("wrong decoded family");
            };
            let ZExtBody::ZBuf(payload) = oam.body else {
                panic!("wrong payload encoding");
            };
            assert_eq!(payload.len(), payload_len);
            assert_eq!(defrag.len, 0);
            assert!(defrag.buffer.is_empty());
            assert_eq!(defrag.partial.capacity(), 0);
            drop(payload);
            drop(input);
            drop(message);
            println!("RX_PRESSURE_ROUND {{\"round\":{round},\"encoded_bytes\":{encoded_len},\"max_chunk_references\":{},\"retained_after_decode\":0}}", FRAME.div_ceil(4096));
        }
    }
    #[test]
    fn tiny_fragments_release_large_backings_and_bound_compact_chunk_references() {
        let mut defrag = make(4096);
        for sn in 0..4096 {
            let backing = Arc::new(vec![7; 65535]);
            let weak = Arc::downgrade(&backing);
            defrag
                .push(sn, ZSlice::new(backing, 0, 1).unwrap())
                .unwrap();
            assert!(weak.upgrade().is_none(), "RX batch was retained");
            assert!(defrag.partial.capacity() <= 4096);
            assert!(defrag.buffer.zslices().count() <= 1);
        }
        assert_eq!(defrag.len, 4096);
        assert!(defrag.push(4096, vec![8].into()).is_err());
        assert!(defrag.is_empty());
        assert_eq!(defrag.partial.capacity(), 0);
        assert!(defrag.buffer.is_empty());
    }
    #[test]
    fn empty_overflow_and_wrong_sequence_reset_without_retaining_storage() {
        let mut defrag = make(8);
        defrag.push(0, vec![1; 4].into()).unwrap();
        assert!(defrag.push(1, ZSlice::empty()).is_err());
        assert_eq!(defrag.partial.capacity(), 0);
        assert!(defrag.buffer.is_empty());
        defrag.sync(7).unwrap();
        assert!(defrag.push(8, vec![1].into()).is_err());
        assert!(defrag.is_empty());
        defrag.sync(9).unwrap();
        assert!(defrag.push(9, vec![1; 9].into()).is_err());
    }
    #[test]
    fn valid_wire_roundtrip_and_trailing_bytes_are_distinct() {
        let message: NetworkMessage = NetworkBody::ResponseFinal(ResponseFinal {
            rid: 42,
            ext_qos: Default::default(),
            ext_tstamp: None,
        })
        .into();
        let mut bytes = Vec::new();
        Zenoh080::new()
            .write(&mut bytes.writer(), message.as_ref())
            .unwrap();
        let mut defrag = make(4096);
        for (sn, byte) in bytes.iter().enumerate() {
            defrag.push(sn as u32, vec![*byte].into()).unwrap();
        }
        assert!(
            matches!(defrag.defragment().unwrap().body, NetworkBody::ResponseFinal(m) if m.rid == 42)
        );
        assert_eq!(defrag.partial.capacity(), 0);
        assert!(defrag.buffer.is_empty());
        bytes.push(0);
        defrag.sync(0).unwrap();
        defrag.push(0, bytes.into()).unwrap();
        assert!(defrag.defragment().is_none());
        assert_eq!(defrag.partial.capacity(), 0);
        assert!(defrag.buffer.is_empty());
    }
}

impl DefragBuffer {
    pub(crate) fn make(
        reliability: Reliability,
        resolution: Bits,
        capacity: usize,
    ) -> ZResult<DefragBuffer> {
        let db = DefragBuffer {
            reliability,
            sn: SeqNum::make(0, resolution)?,
            buffer: ZBuf::empty(),
            partial: Vec::new(),
            capacity,
            len: 0,
        };
        Ok(db)
    }

    #[inline(always)]
    pub(crate) fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[inline(always)]
    pub(crate) fn clear(&mut self) {
        self.buffer = ZBuf::empty();
        self.partial = Vec::new();
        self.len = 0;
    }

    #[inline(always)]
    pub(crate) fn sync(&mut self, sn: TransportSn) -> ZResult<()> {
        self.sn.set(sn)
    }

    pub(crate) fn push(&mut self, sn: TransportSn, zslice: ZSlice) -> ZResult<()> {
        if sn != self.sn.get() {
            self.clear();
            bail!(
                "Defragmentation SN error: expected SN {}, received {}",
                self.sn.get(),
                sn
            )
        }

        let new_len = self.len.checked_add(zslice.len());
        if zslice.is_empty() || new_len.is_none_or(|len| len > self.capacity) {
            self.clear();
            bail!(
                "Defragmentation empty fragment or buffer full: {:?} bytes. Capacity: {}.",
                new_len,
                self.capacity
            )
        }
        let new_len = new_len.unwrap();
        // Fixed 4KiB compact chunks avoid both backing amplification and the
        // transient old+new allocation needed by contiguous Vec growth. There
        // are at most ceil(frame/4096) references, independent of fragment count.
        let mut bytes = zslice.as_slice();
        while !bytes.is_empty() {
            if self.partial.capacity() == 0
                && self
                    .partial
                    .try_reserve_exact(4096.min(self.capacity - self.len))
                    .is_err()
            {
                self.clear();
                bail!("Defragmentation allocation failed")
            }
            let count = bytes.len().min(4096 - self.partial.len());
            self.partial.extend_from_slice(&bytes[..count]);
            bytes = &bytes[count..];
            if self.partial.len() == 4096 {
                self.buffer
                    .push_zslice(std::mem::take(&mut self.partial).into());
            }
        }
        self.sn.increment();
        self.len = new_len;

        Ok(())
    }

    #[inline(always)]
    pub(crate) fn defragment(&mut self) -> Option<NetworkMessage> {
        // Transfer the compact owner to decoding; payloads can remain zero-copy
        // without retaining either the original RX batches or fragment list.
        if !self.partial.is_empty() {
            self.buffer
                .push_zslice(std::mem::take(&mut self.partial).into());
        }
        let buffer = std::mem::take(&mut self.buffer);
        self.len = 0;
        let mut reader = buffer.reader();
        let rcodec = Zenoh080Reliability::new(self.reliability);
        let res: Option<NetworkMessage> = rcodec.read(&mut reader).ok();
        if reader.can_read() {
            None
        } else {
            res
        }
    }
}
