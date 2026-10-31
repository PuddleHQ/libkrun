// SPDX-License-Identifier: Apache-2.0
//! Fuzz entry point for the balloon device (feature `fuzzing`).

use std::sync::Arc;
use std::time::Duration;

use polly::event_manager::Subscriber as _;
use utils::epoll::{EpollEvent, EventSet};
use utils::eventfd::EventFd;
use utils::metrics::MetricsWriter;
use vm_memory::{Bytes, GuestAddress};

use super::defs;
use super::device::{Balloon, DFQ_INDEX, IFQ_INDEX, PHQ_INDEX, STQ_INDEX};
use crate::legacy::DummyIrqChip;
use crate::virtio::fuzzing::{guest_memory, le16, make_queue, take};
use crate::virtio::{DeviceQueue, InterruptTransport, VirtioDevice};

/// The balloon device with all five queues set by the guest.
///
/// Input: 4 bytes (feature bits 0 to 7, queue size, feature bits 8 to 15, 1 for VERSION_1), then for each queue a 16-bit length and that many
/// bytes of ring memory (descriptor table at the start, available ring at +0x1000, used ring at
/// +0x2000 of the queue's own 0x4000 bytes). The device then handles a free page report, a stats
/// buffer and a kick on each queue it does not use.
pub fn balloon_queues(data: &[u8]) {
    let mut data = data;
    let Some(cfg) = take(&mut data, 4) else {
        return;
    };
    let mem = guest_memory();
    let mut queues = Vec::new();
    for index in 0..defs::NUM_QUEUES {
        let chunk = match take(&mut data, 2) {
            Some(len) => {
                let n = usize::from(le16(len)).min(data.len()).min(0x3000);
                take(&mut data, n).unwrap_or(&[])
            }
            None => &[],
        };
        let base = index as u64 * 0x4000;
        let _ = mem.write_slice(chunk, GuestAddress(base));
        let mut q = make_queue(cfg[1] % 5 + 1, false, base, &[]);
        q.size = 1 << (cfg[1] % 5 + 1);
        assert!(q.is_valid(&mem), "the harness rings must be valid");
        queues.push(DeviceQueue::new(
            q,
            Arc::new(EventFd::new(0).expect("eventfd")),
        ));
    }
    let mut balloon =
        Balloon::new(MetricsWriter::default(), Some(Duration::from_secs(3600))).expect("balloon");
    balloon.set_acked_features(
        u64::from(cfg[0]) | u64::from(cfg[2]) << 8 | u64::from(cfg[3] & 1) << 32,
    );
    let interrupt =
        InterruptTransport::new(DummyIrqChip::new().into(), "fuzz".into()).expect("interrupt");
    balloon.activate(mem, interrupt, queues).expect("activate");

    let kick = EpollEvent::new(EventSet::IN, 0);
    for index in 0..defs::NUM_QUEUES {
        if let Some(queues) = balloon.queues.as_ref() {
            let _ = queues[index].event.write(1);
        }
        match index {
            IFQ_INDEX => balloon.handle_ifq_event(&kick),
            DFQ_INDEX => balloon.handle_dfq_event(&kick),
            STQ_INDEX => balloon.handle_stq_event(&kick),
            PHQ_INDEX => balloon.handle_phq_event(&kick),
            _ => balloon.handle_frq_event(&kick),
        }
    }
    let _ = balloon.process_frq();
    balloon.trigger_stats_update();
    let _ = balloon.interest_list();
    let _ = balloon.reset();
}
