use rand::{rngs::OsRng, TryRngCore};
use utils::eventfd::EventFd;
use vm_memory::{Address, Bytes, GuestMemoryMmap};

use super::super::{
    ActivateError, ActivateResult, DeviceQueue, DeviceState, QueueConfig, RngError, VirtioDevice,
    VirtioStateError,
};
use super::{defs, defs::uapi};
use crate::virtio::InterruptTransport;

/// The most random bytes one request gets. The guest picks the descriptor lengths (up to 4 GiB
/// each), and this keeps a request from holding the device thread. Linux's hw_random reads a few
/// hundred bytes at a time.
pub(crate) const MAX_REQUEST_BYTES: u32 = 64 * 1024;
const CHUNK_BYTES: u32 = 4096;

// Request queue.
pub(crate) const REQ_INDEX: usize = 0;

// Supported features.
pub(crate) const AVAIL_FEATURES: u64 = 1 << uapi::VIRTIO_F_VERSION_1 as u64;

pub struct Rng {
    pub(crate) queues: Option<Vec<DeviceQueue>>,
    pub(crate) avail_features: u64,
    pub(crate) acked_features: u64,
    pub(crate) activate_evt: EventFd,
    pub(crate) device_state: DeviceState,
}

impl Rng {
    pub(crate) fn queue_event(&self, idx: usize) -> &std::sync::Arc<utils::eventfd::EventFd> {
        &self.queues.as_ref().expect("queues should exist")[idx].event
    }

    pub fn new() -> super::Result<Rng> {
        Ok(Rng {
            queues: None,
            avail_features: AVAIL_FEATURES,
            acked_features: 0,
            activate_evt: EventFd::new(utils::eventfd::EFD_NONBLOCK).map_err(RngError::EventFd)?,
            device_state: DeviceState::Inactive,
        })
    }

    pub fn id(&self) -> &str {
        defs::RNG_DEV_ID
    }

    pub fn process_req(&mut self) -> bool {
        debug!("rng: process_req()");
        let mem = match self.device_state {
            DeviceState::Activated(ref mem, _) => mem,
            // This should never happen, it's been already validated in the event handler.
            DeviceState::Inactive => unreachable!(),
        };

        let queues = self
            .queues
            .as_mut()
            .expect("queues should exist when activated");
        let mut have_used = false;

        while let Some(head) = queues[REQ_INDEX].queue.pop(mem) {
            let index = head.index;
            let mut written = 0;
            'descs: for desc in head.into_iter() {
                // Stream each descriptor through a small buffer so a guest-chosen length never
                // sets the size of a host allocation, and stop at the per-request cap.
                let mut done = 0u32;
                while done < desc.len {
                    let left = MAX_REQUEST_BYTES.saturating_sub(written);
                    if left == 0 {
                        debug!("rng: request capped at {MAX_REQUEST_BYTES} bytes");
                        break 'descs;
                    }
                    let n = (desc.len - done).min(left).min(CHUNK_BYTES);
                    let mut rand_bytes = [0u8; CHUNK_BYTES as usize];
                    let rand_bytes = &mut rand_bytes[..n as usize];
                    if let Err(e) = OsRng.try_fill_bytes(rand_bytes) {
                        error!("Failed to fill buffer with random data: {e:?}");
                        break 'descs;
                    }
                    let Some(addr) = desc.addr.checked_add(u64::from(done)) else {
                        break 'descs;
                    };
                    if let Err(e) = mem.write_slice(rand_bytes, addr) {
                        // A buffer outside guest RAM. The chain is completed with the bytes
                        // written so far: handing it back to `pop` (go_to_previous_position)
                        // made this loop pop the same chain forever.
                        error!("Failed to write slice: {e:?}");
                        break 'descs;
                    }
                    done += n;
                    written += n;
                }
            }

            have_used = true;
            if let Err(e) = queues[REQ_INDEX].queue.add_used(mem, index, written) {
                error!("failed to add used elements to the queue: {e:?}");
            }
        }

        have_used
    }
}

impl VirtioDevice for Rng {
    fn avail_features(&self) -> u64 {
        self.avail_features
    }

    fn acked_features(&self) -> u64 {
        self.acked_features
    }

    fn set_acked_features(&mut self, acked_features: u64) {
        self.acked_features = acked_features
    }

    fn device_type(&self) -> u32 {
        uapi::VIRTIO_ID_RNG
    }

    fn device_name(&self) -> &str {
        "rng"
    }

    fn queue_config(&self) -> &[QueueConfig] {
        &defs::QUEUE_CONFIG
    }

    fn read_config(&self, _offset: u64, _data: &mut [u8]) {
        error!("rng: invalid request to read config space");
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        warn!(
            "rng: guest driver attempted to write device config (offset={:x}, len={:x})",
            offset,
            data.len()
        );
    }

    fn activate(
        &mut self,
        mem: GuestMemoryMmap,
        interrupt: InterruptTransport,
        queues: Vec<DeviceQueue>,
    ) -> ActivateResult {
        if queues.len() != defs::NUM_QUEUES {
            error!(
                "Cannot perform activate. Expected {} queue(s), got {}",
                defs::NUM_QUEUES,
                queues.len()
            );
            return Err(ActivateError::BadActivate);
        }

        if self.activate_evt.write(1).is_err() {
            error!("Cannot write to activate_evt",);
            return Err(ActivateError::BadActivate);
        }

        self.queues = Some(queues);
        self.device_state = DeviceState::Activated(mem, interrupt);

        Ok(())
    }

    fn is_activated(&self) -> bool {
        self.device_state.is_activated()
    }

    fn reset(&mut self) -> bool {
        self.queues = None;
        self.device_state = DeviceState::Inactive;
        true
    }

    fn supports_quiesce(&self) -> bool {
        true
    }

    fn quiesce(&mut self) -> Result<Vec<DeviceQueue>, VirtioStateError> {
        if !self.device_state.is_activated() {
            return self.queues.take().ok_or(VirtioStateError::InvalidLifecycle(
                "rng queues are unavailable while inactive",
            ));
        }

        // The event-manager callback and this method are serialized by the device mutex. Once the
        // queues move back to the transport, no RNG descriptor or guest-memory write remains owned.
        let queues = self
            .queues
            .take()
            .ok_or(VirtioStateError::InvalidLifecycle(
                "rng is activated without queues",
            ))?;
        self.device_state = DeviceState::Inactive;
        Ok(queues)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use utils::eventfd::EventFd;
    use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

    use super::*;
    use crate::legacy::DummyIrqChip;
    use crate::virtio::queue::tests::VirtQueue;
    use crate::virtio::queue::VIRTQ_DESC_F_WRITE;

    const BUF: u64 = 0x10000;
    /// The documented cap, written out so that changing the constant fails these tests.
    const CAP: u32 = 64 * 1024;

    /// An activated rng whose request queue holds one write-only descriptor of `len` bytes at
    /// `BUF`, the way a guest driver posts a buffer.
    fn rng_with_request(mem: &GuestMemoryMmap, len: u32) -> (Rng, VirtQueue<'_>) {
        let vq = VirtQueue::new(GuestAddress(0), mem, 16);
        vq.dtable[0].set(BUF, len, VIRTQ_DESC_F_WRITE, 0);
        vq.avail.ring[0].set(0);
        vq.avail.idx.set(1);
        let mut rng = Rng::new().unwrap();
        let interrupt =
            InterruptTransport::new(DummyIrqChip::new().into(), "test-rng".into()).unwrap();
        let queue = DeviceQueue::new(vq.create_queue(), Arc::new(EventFd::new(0).unwrap()));
        rng.activate(mem.clone(), interrupt, vec![queue]).unwrap();
        (rng, vq)
    }

    fn mem() -> GuestMemoryMmap {
        GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x40_0000)]).unwrap()
    }

    #[test]
    fn a_request_far_past_the_cap_gets_only_the_cap() {
        let mem = mem();
        // 2 MiB asked for, 64 KiB capped: the reply says how much was written.
        let (mut rng, vq) = rng_with_request(&mem, 2 << 20);
        assert!(rng.process_req());
        assert_eq!(vq.used.idx.get(), 1);
        assert_eq!(vq.used.ring[0].get().len, CAP);
        let mut tail = [0u8; 16];
        mem.read_slice(&mut tail, GuestAddress(BUF + u64::from(CAP)))
            .unwrap();
        assert_eq!(tail, [0u8; 16], "nothing may be written past the cap");
    }

    #[test]
    fn a_four_gib_descriptor_neither_allocates_nor_fails_the_device() {
        let mem = mem();
        let (mut rng, vq) = rng_with_request(&mem, u32::MAX);
        assert!(rng.process_req());
        assert_eq!(vq.used.ring[0].get().len, CAP);
    }

    #[test]
    fn a_buffer_past_guest_memory_completes_the_chain_instead_of_spinning() {
        // 32 KiB of guest RAM behind BUF, 512 MiB announced: the write fails at the end of RAM.
        let mem =
            GuestMemoryMmap::from_ranges(&[(GuestAddress(0), BUF as usize + 0x8000)]).unwrap();
        let (mut rng, vq) = rng_with_request(&mem, 512 << 20);
        assert!(rng.process_req());
        assert_eq!(vq.used.idx.get(), 1, "the chain is completed once");
        assert_eq!(vq.used.ring[0].get().len, 0x8000);
    }

    #[test]
    fn a_normal_request_is_filled_whole() {
        let mem = mem();
        let (mut rng, vq) = rng_with_request(&mem, 6000);
        assert!(rng.process_req());
        assert_eq!(vq.used.ring[0].get().len, 6000);
        let mut got = vec![0u8; 6000];
        mem.read_slice(&mut got, GuestAddress(BUF)).unwrap();
        assert!(got.iter().any(|b| *b != 0));
        assert!(
            got[4096..].iter().any(|b| *b != 0),
            "the second chunk is filled too"
        );
    }
}
