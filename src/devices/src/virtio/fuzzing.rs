// SPDX-License-Identifier: Apache-2.0
//! Entry points for the cargo-fuzz targets in `fuzz/` (feature `fuzzing`).
//!
//! Each function takes the bytes libFuzzer chose and drives one guest-facing parser the way a
//! guest driver reaches it: through guest memory, a virtqueue and the device's own handler. A
//! panic, an out-of-bounds access or a broken invariant is a finding. The stable test in
//! `fuzz/tests/corpus.rs` replays the checked-in inputs through the same functions.

use std::io::{Read, Write};

use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

use super::descriptor_utils::{Reader, Writer};
use super::Queue;

/// Guest RAM of the harness: two regions with a hole between them, like a guest with a PCI or
/// MMIO gap, so ranges that start in the hole or cross it are tried.
pub const REGION_A: (u64, usize) = (0, 0x4_0000);
pub const REGION_B: (u64, usize) = (0x8_0000, 0x4_0000);

/// Guest memory with the two regions of the harness.
pub fn guest_memory() -> GuestMemoryMmap {
    GuestMemoryMmap::from_ranges(&[
        (GuestAddress(REGION_A.0), REGION_A.1),
        (GuestAddress(REGION_B.0), REGION_B.1),
    ])
    .expect("two non-overlapping anonymous regions")
}

/// Copies `bytes` to the start of both regions, as far as they fit.
pub(crate) fn fill(mem: &GuestMemoryMmap, bytes: &[u8]) {
    for (start, size) in [REGION_A, REGION_B] {
        let n = bytes.len().min(size);
        // Cannot fail: `n` bytes at the start of a region of at least `n` bytes.
        let _ = mem.write_slice(&bytes[..n], GuestAddress(start));
    }
}

pub(crate) fn take<'a>(data: &mut &'a [u8], n: usize) -> Option<&'a [u8]> {
    if data.len() < n {
        return None;
    }
    let (head, rest) = data.split_at(n);
    *data = rest;
    Some(head)
}

pub(crate) fn le16(bytes: &[u8]) -> u16 {
    u16::from_le_bytes([bytes[0], bytes[1]])
}

/// The ring layout one queue gets: where the guest says its rings are. Without `scattered` the
/// rings sit at `base`, `base + 0x1000` and `base + 0x2000`, where fuzz bytes written at the
/// start of memory describe them; with it the addresses come from the input, so misaligned and
/// out-of-memory rings reach `Queue::is_valid`.
pub(crate) fn make_queue(size_sel: u8, scattered: bool, base: u64, raw: &[u8]) -> Queue {
    let mut q = Queue::new(256);
    q.size = match size_sel % 10 {
        9 => 0,
        n => 1 << n,
    };
    q.ready = true;
    if scattered {
        q.desc_table = GuestAddress(u64::from(le16(&raw[0..2])) * 16);
        q.avail_ring = GuestAddress(u64::from(le16(&raw[2..4])) * 2);
        q.used_ring = GuestAddress(u64::from(le16(&raw[4..6])) * 4);
    } else {
        q.desc_table = GuestAddress(base);
        q.avail_ring = GuestAddress(base + 0x1000);
        q.used_ring = GuestAddress(base + 0x2000);
    }
    q
}

/// Pops up to `limit` chains from `q` and reads and writes each through `Reader` and `Writer`,
/// then returns it. Checks what a driver could break: a chain longer than the queue, a reader
/// that fails after it was built, a writer that takes fewer bytes than it offered.
fn drain_queue(mem: &GuestMemoryMmap, q: &mut Queue, limit: usize) {
    for _ in 0..limit {
        let Some(head) = q.pop(mem) else { break };
        let index = head.index;
        let mut count = 0usize;
        for desc in head.clone().into_iter() {
            count += 1;
            assert!(
                count <= usize::from(q.actual_size()),
                "a descriptor chain is longer than its queue ({count} descriptors)"
            );
            let _ = desc.descriptor();
            let _ = (desc.is_write_only(), desc.has_next());
        }
        let _ = head.clone().into_iter().readable().count();
        let _ = head.clone().into_iter().writable().count();

        let mut used = 0u32;
        if let Ok(mut reader) = Reader::new(mem, head.clone()) {
            let total = reader.available_bytes();
            let _ = reader.split_at(total / 2);
            let mut sink = Vec::new();
            let got = (&mut reader).take(1 << 20).read_to_end(&mut sink);
            assert!(
                got.is_ok(),
                "a reader built over valid memory failed: {got:?}"
            );
        }
        if let Ok(mut writer) = Writer::new(mem, head.clone()) {
            let offered = writer.available_bytes().min(1 << 20);
            let wrote = writer.write(&vec![0xa5; offered]);
            assert!(
                matches!(wrote, Ok(n) if n <= offered),
                "a writer over valid memory failed: {wrote:?}"
            );
            used = writer.bytes_written() as u32;
        }
        let _ = q.add_used(mem, index, used);
        let _ = q.needs_notification(mem);
        let _ = q.enable_notification(mem);
    }
    let _ = q.capture_state();
}

/// Descriptor chains as the guest lays them out in its descriptor table and available ring.
///
/// Input: 12 bytes of queue setup (size, flags, three ring addresses), then guest memory from
/// address 0. Flag 0x01 turns event-idx on, 0x40 mirrors the memory into the second region, 0x80
/// takes the ring addresses from the input.
pub fn virtqueue_chain(data: &[u8]) {
    let mut data = data;
    let Some(cfg) = take(&mut data, 12) else {
        return;
    };
    let mem = guest_memory();
    fill(&mem, data);
    if cfg[1] & 0x40 != 0 {
        let _ = mem.write_slice(
            &data[..data.len().min(REGION_B.1)],
            GuestAddress(REGION_B.0),
        );
    }
    let mut q = make_queue(cfg[0], cfg[1] & 0x80 != 0, 0, &cfg[4..10]);
    q.set_event_idx(cfg[1] & 1 != 0);
    if !q.is_valid(&mem) {
        // The transport refuses to activate a device on such a queue; nothing else may run.
        let _ = q.len(&mem);
        let _ = q.is_empty(&mem);
        return;
    }
    drain_queue(&mem, &mut q, usize::from(cfg[2] % 32) + 1);
}
