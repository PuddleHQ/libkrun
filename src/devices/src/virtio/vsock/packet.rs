// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//

/// `VsockPacket` provides a thin wrapper over the buffers exchanged via virtio queues.
/// There are two components to a vsock packet, each using its own descriptor in a
/// virtio queue:
/// - the packet header; and
/// - the packet data/buffer.
///
/// There is a 1:1 relation between descriptor chains and packets: the first (chain head) holds
/// the header, and an optional second descriptor holds the data. The second descriptor is only
/// present for data packets (VSOCK_OP_RW).
///
/// `VsockPacket` wraps these two buffers and provides direct access to the data stored
/// in guest memory. This is done to avoid unnecessarily copying data from guest memory
/// to temporary buffers, before passing it on to the vsock backend.
use std::convert::TryInto;
use std::ffi::CStr;
#[cfg(unix)]
use std::net::{Ipv4Addr, SocketAddrV4};
#[cfg(target_os = "macos")]
use std::net::{Ipv6Addr, SocketAddrV6};
use std::result;

#[cfg(target_os = "linux")]
use nix::sys::socket::{sockaddr, AddressFamily};
#[cfg(unix)]
use nix::sys::socket::{SockaddrLike, SockaddrStorage};
use utils::byte_order;
use vm_memory::{self, Address, Bytes, GuestAddress, GuestMemory, GuestMemoryError};

use super::super::DescriptorChain;
use super::defs;
use super::{Result, VsockError};

// The vsock packet header is defined by the C struct:
//
// ```C
// struct virtio_vsock_hdr {
//     le64 src_cid;
//     le64 dst_cid;
//     le32 src_port;
//     le32 dst_port;
//     le32 len;
//     le16 type;
//     le16 op;
//     le32 flags;
//     le32 buf_alloc;
//     le32 fwd_cnt;
// };
// ```
//
// This structed will occupy the buffer pointed to by the head descriptor. We'll be accessing it
// as a byte slice. To that end, we define below the offsets for each field struct, as well as the
// packed struct size, as a bunch of `usize` consts.
// Note that these offsets are only used privately by the `VsockPacket` struct, the public interface
// consisting of getter and setter methods, for each struct field, that will also handle the correct
// endianess.

/// The vsock packet header struct size (when packed).
pub const VSOCK_PKT_HDR_SIZE: usize = 44;

// Source CID.
const HDROFF_SRC_CID: usize = 0;

// Destination CID.
const HDROFF_DST_CID: usize = 8;

// Source port.
const HDROFF_SRC_PORT: usize = 16;

// Destination port.
const HDROFF_DST_PORT: usize = 20;

// Data length (in bytes) - may be 0, if there is no data buffer.
const HDROFF_LEN: usize = 24;

// Socket type. Currently, only connection-oriented streams are defined by the vsock protocol.
const HDROFF_TYPE: usize = 28;

// Operation ID - one of the VSOCK_OP_* values; e.g.
// - VSOCK_OP_RW: a data packet;
// - VSOCK_OP_REQUEST: connection request;
// - VSOCK_OP_RST: forcefull connection termination;
// etc (see `super::defs::uapi` for the full list).
const HDROFF_OP: usize = 30;

// Additional options (flags) associated with the current operation (`op`).
// Currently, only used with shutdown requests (VSOCK_OP_SHUTDOWN).
const HDROFF_FLAGS: usize = 32;

// Size (in bytes) of the packet sender receive buffer (for the connection to which this packet
// belongs).
const HDROFF_BUF_ALLOC: usize = 36;

// Number of bytes the sender has received and consumed (for the connection to which this packet
// belongs). For instance, for our Unix backend, this counter would be the total number of bytes
// we have successfully written to a backing Unix socket.
const HDROFF_FWD_CNT: usize = 40;

#[cfg(unix)]
#[repr(C)]
pub struct TsiProxyCreate {
    pub peer_port: u32,
    pub family: u16,
    pub _type: u16,
}

#[cfg(unix)]
#[repr(C)]
pub struct TsiConnectReq {
    pub peer_port: u32,
    pub addr: SockaddrStorage,
}

#[cfg(unix)]
#[repr(C)]
pub struct TsiConnectRsp {
    pub result: i32,
}

#[cfg(unix)]
#[repr(C)]
pub struct TsiGetnameReq {
    pub peer_port: u32,
    pub local_port: u32,
    pub peer: u32,
}

#[cfg(unix)]
#[repr(C)]
#[derive(Debug)]
pub struct TsiGetnameRsp {
    pub result: i32,
    pub addr_len: u32,
    pub addr: SockaddrStorage,
}

#[cfg(unix)]
impl Default for TsiGetnameRsp {
    fn default() -> Self {
        let addr: SockaddrStorage = SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 0).into();
        TsiGetnameRsp {
            result: -1,
            // It's fine to unwrap here sice we've just created the SocketAddrV4 above.
            addr_len: addr.as_sockaddr_in().unwrap().len(),
            addr,
        }
    }
}

#[cfg(unix)]
#[repr(C)]
#[derive(Debug)]
pub struct TsiSendtoAddr {
    pub peer_port: u32,
    pub addr: SockaddrStorage,
}

#[cfg(unix)]
#[repr(C)]
#[derive(Debug)]
pub struct TsiListenReq {
    pub peer_port: u32,
    pub vm_port: u32,
    pub backlog: i32,
    pub addr: SockaddrStorage,
}

#[cfg(unix)]
#[repr(C)]
#[derive(Debug)]
pub struct TsiListenRsp {
    pub result: i32,
}

#[cfg(unix)]
#[repr(C)]
#[derive(Debug)]
pub struct TsiAcceptReq {
    pub peer_port: u32,
    pub flags: u32,
}

#[cfg(unix)]
#[repr(C)]
#[derive(Debug)]
pub struct TsiAcceptRsp {
    pub result: i32,
}

#[cfg(unix)]
#[repr(C)]
pub struct TsiReleaseReq {
    pub peer_port: u32,
    pub local_port: u32,
}

/// The vsock packet, implemented as a wrapper over a virtq descriptor chain:
/// - the chain head, holding the packet header; and
/// - (an optional) data/buffer descriptor, only present for data packets (VSOCK_OP_RW).
///
/// A TX packet whose data spans several descriptors is copied into `owned_buf`.
pub struct VsockPacket {
    hdr: *mut u8,
    buf: Option<*mut u8>,
    buf_size: usize,
    owned_buf: Option<Vec<u8>>,
}

fn get_host_address<T: GuestMemory + vm_memory::GuestMemoryBackend>(
    mem: &T,
    guest_addr: GuestAddress,
    size: usize,
) -> result::Result<*mut u8, GuestMemoryError> {
    Ok(mem.get_slice(guest_addr, size)?.ptr_guard_mut().as_ptr())
}

impl VsockPacket {
    /// Create the packet wrapper from a TX virtq chain head.
    ///
    /// The chain head is expected to hold valid packet header data. The data may follow the
    /// header in the head descriptor and may span any number of descriptors after it: Linux
    /// 6.12.y sends a write over about 32 KiB with one descriptor per page fragment. Bounds and
    /// pointer checks are performed when creating the wrapper.
    pub fn from_tx_virtq_head(head: &DescriptorChain) -> Result<Self> {
        // All buffers in the TX queue must be readable.
        //
        if head.is_write_only() {
            return Err(VsockError::UnreadableDescriptor);
        }

        // The packet header should fit inside the head descriptor.
        if head.len < VSOCK_PKT_HDR_SIZE as u32 {
            return Err(VsockError::HdrDescTooSmall(head.len));
        }

        let mut pkt = Self {
            hdr: get_host_address(head.mem, head.addr, VSOCK_PKT_HDR_SIZE)
                .map_err(VsockError::GuestMemoryMmap)?,
            buf: None,
            buf_size: 0,
            owned_buf: None,
        };

        // No point looking for a data/buffer descriptor, if the packet is zero-lengthed.
        if pkt.len() == 0 {
            return Ok(pkt);
        }

        // Reject weirdly-sized packets.
        //
        if pkt.len() > defs::MAX_PKT_BUF_SIZE as u32 {
            return Err(VsockError::InvalidPktLen(pkt.len()));
        }
        let pkt_len = pkt.len() as usize;
        let head_data = head.len as usize - VSOCK_PKT_HDR_SIZE;

        if head_data == 0 {
            // If the packet header showed a non-zero length, there should be a data descriptor
            // here.
            let buf_desc = head.next_descriptor().ok_or(VsockError::BufDescMissing)?;

            // TX data should be read-only.
            if buf_desc.is_write_only() {
                return Err(VsockError::UnreadableDescriptor);
            }

            // All the data in one descriptor: use it in place.
            if buf_desc.len as usize >= pkt_len {
                pkt.buf_size = buf_desc.len as usize;
                pkt.buf = Some(
                    get_host_address(buf_desc.mem, buf_desc.addr, pkt.buf_size)
                        .map_err(VsockError::GuestMemoryMmap)?,
                );
                return Ok(pkt);
            }
        }

        // The data is spread over the head and/or several descriptors: copy exactly the declared
        // length, in chain order, and read no descriptor past it.
        let mut data = vec![0u8; pkt_len];
        let mut filled = head_data.min(pkt_len);
        head.mem
            .read_slice(
                &mut data[..filled],
                head.addr
                    .checked_add(VSOCK_PKT_HDR_SIZE as u64)
                    .ok_or(VsockError::GuestMemoryBounds)?,
            )
            .map_err(VsockError::GuestMemoryMmap)?;
        let mut next = head.next_descriptor();
        while filled < pkt_len {
            let desc = match next {
                Some(desc) => desc,
                None if filled == 0 => return Err(VsockError::BufDescMissing),
                None => return Err(VsockError::BufDescTooSmall),
            };
            if desc.is_write_only() {
                return Err(VsockError::UnreadableDescriptor);
            }
            let n = (desc.len as usize).min(pkt_len - filled);
            desc.mem
                .read_slice(&mut data[filled..filled + n], desc.addr)
                .map_err(VsockError::GuestMemoryMmap)?;
            filled += n;
            next = desc.next_descriptor();
        }

        pkt.buf_size = pkt_len;
        pkt.owned_buf = Some(data);

        Ok(pkt)
    }

    /// Create the packet wrapper from an RX virtq chain head.
    ///
    /// There must be two descriptors in the chain, both writable: a header descriptor and a data
    /// descriptor. Bounds and pointer checks are performed when creating the wrapper.
    pub fn from_rx_virtq_head(head: &DescriptorChain) -> Result<Self> {
        // All RX buffers must be writable.
        //
        if !head.is_write_only() {
            return Err(VsockError::UnwritableDescriptor);
        }

        // The packet header should fit inside the head descriptor.
        if head.len < VSOCK_PKT_HDR_SIZE as u32 {
            return Err(VsockError::HdrDescTooSmall(head.len));
        }

        let mut pkt = Self {
            hdr: get_host_address(head.mem, head.addr, VSOCK_PKT_HDR_SIZE)
                .map_err(VsockError::GuestMemoryMmap)?,
            buf: None,
            buf_size: 0,
            owned_buf: None,
        };

        // Starting from Linux 6.2 the virtio-vsock driver can use a single descriptor for both
        // header and data.
        if !head.has_next() && head.len > VSOCK_PKT_HDR_SIZE as u32 {
            let buf_addr = head
                .addr
                .checked_add(VSOCK_PKT_HDR_SIZE as u64)
                .ok_or(VsockError::GuestMemoryBounds)?;

            pkt.buf_size = head.len as usize - VSOCK_PKT_HDR_SIZE;
            pkt.buf = Some(
                get_host_address(head.mem, buf_addr, pkt.buf_size)
                    .map_err(VsockError::GuestMemoryMmap)?,
            );
        } else {
            let buf_desc = head.next_descriptor().ok_or(VsockError::BufDescMissing)?;

            pkt.buf_size = buf_desc.len as usize;
            pkt.buf = Some(
                get_host_address(buf_desc.mem, buf_desc.addr, pkt.buf_size)
                    .map_err(VsockError::GuestMemoryMmap)?,
            );
        }

        Ok(pkt)
    }

    /// Provides in-place, byte-slice, access to the vsock packet header.
    pub fn hdr(&self) -> &[u8] {
        // This is safe since bound checks have already been performed when creating the packet
        // from the virtq descriptor.
        unsafe { std::slice::from_raw_parts(self.hdr as *const u8, VSOCK_PKT_HDR_SIZE) }
    }

    /// Provides in-place, byte-slice, mutable access to the vsock packet header.
    pub fn hdr_mut(&mut self) -> &mut [u8] {
        // This is safe since bound checks have already been performed when creating the packet
        // from the virtq descriptor.
        unsafe { std::slice::from_raw_parts_mut(self.hdr, VSOCK_PKT_HDR_SIZE) }
    }

    /// Provides in-place, byte-slice access to the vsock packet data buffer.
    ///
    /// Note: control packets (e.g. connection request or reset) have no data buffer associated.
    ///       For those packets, this method will return `None`.
    /// Also note: calling `len()` on the returned slice will yield the buffer size, which may be
    ///            (and often is) larger than the length of the packet data. The packet data length
    ///            is stored in the packet header, and accessible via `VsockPacket::len()`.
    pub fn buf(&self) -> Option<&[u8]> {
        if let Some(owned) = &self.owned_buf {
            return Some(owned);
        }
        self.buf.map(|ptr| {
            // This is safe since bound checks have already been performed when creating the packet
            // from the virtq descriptor.
            unsafe { std::slice::from_raw_parts(ptr as *const u8, self.buf_size) }
        })
    }

    /// Return exactly the data length declared in the packet header rather
    /// than the potentially larger backing descriptor.
    pub(crate) fn payload(&self) -> Option<&[u8]> {
        let len = self.len() as usize;
        if len == 0 {
            return Some(&[]);
        }
        self.buf()?.get(..len)
    }

    /// The declared payload of a TX packet, or `None` when it carries no data. Proxies forward
    /// this, never `buf()`: a guest may declare less than its descriptor holds, and the credit
    /// the guest tracks counts the declared length.
    pub(crate) fn tx_data(&self) -> Option<&[u8]> {
        self.payload().filter(|data| !data.is_empty())
    }

    /// Provides in-place, byte-slice, mutable access to the vsock packet data buffer.
    ///
    /// Note: control packets (e.g. connection request or reset) have no data buffer associated.
    ///       For those packets, this method will return `None`.
    /// Also note: calling `len()` on the returned slice will yield the buffer size, which may be
    ///            (and often is) larger than the length of the packet data. The packet data length
    ///            is stored in the packet header, and accessible via `VsockPacket::len()`.
    pub fn buf_mut(&mut self) -> Option<&mut [u8]> {
        if let Some(owned) = &mut self.owned_buf {
            return Some(owned);
        }
        self.buf.map(|ptr| {
            // This is safe since bound checks have already been performed when creating the packet
            // from the virtq descriptor.
            unsafe { std::slice::from_raw_parts_mut(ptr, self.buf_size) }
        })
    }

    pub fn src_cid(&self) -> u64 {
        byte_order::read_le_u64(&self.hdr()[HDROFF_SRC_CID..])
    }

    pub fn set_src_cid(&mut self, cid: u64) -> &mut Self {
        byte_order::write_le_u64(&mut self.hdr_mut()[HDROFF_SRC_CID..], cid);
        self
    }

    pub fn dst_cid(&self) -> u64 {
        byte_order::read_le_u64(&self.hdr()[HDROFF_DST_CID..])
    }

    pub fn set_dst_cid(&mut self, cid: u64) -> &mut Self {
        byte_order::write_le_u64(&mut self.hdr_mut()[HDROFF_DST_CID..], cid);
        self
    }

    pub fn src_port(&self) -> u32 {
        byte_order::read_le_u32(&self.hdr()[HDROFF_SRC_PORT..])
    }

    pub fn set_src_port(&mut self, port: u32) -> &mut Self {
        byte_order::write_le_u32(&mut self.hdr_mut()[HDROFF_SRC_PORT..], port);
        self
    }

    pub fn dst_port(&self) -> u32 {
        byte_order::read_le_u32(&self.hdr()[HDROFF_DST_PORT..])
    }

    pub fn set_dst_port(&mut self, port: u32) -> &mut Self {
        byte_order::write_le_u32(&mut self.hdr_mut()[HDROFF_DST_PORT..], port);
        self
    }

    pub fn len(&self) -> u32 {
        byte_order::read_le_u32(&self.hdr()[HDROFF_LEN..])
    }

    pub fn set_len(&mut self, len: u32) -> &mut Self {
        byte_order::write_le_u32(&mut self.hdr_mut()[HDROFF_LEN..], len);
        self
    }

    pub fn type_(&self) -> u16 {
        byte_order::read_le_u16(&self.hdr()[HDROFF_TYPE..])
    }

    pub fn set_type(&mut self, type_: u16) -> &mut Self {
        byte_order::write_le_u16(&mut self.hdr_mut()[HDROFF_TYPE..], type_);
        self
    }

    pub fn op(&self) -> u16 {
        byte_order::read_le_u16(&self.hdr()[HDROFF_OP..])
    }

    pub fn set_op(&mut self, op: u16) -> &mut Self {
        byte_order::write_le_u16(&mut self.hdr_mut()[HDROFF_OP..], op);
        self
    }

    pub fn flags(&self) -> u32 {
        byte_order::read_le_u32(&self.hdr()[HDROFF_FLAGS..])
    }

    pub fn set_flags(&mut self, flags: u32) -> &mut Self {
        byte_order::write_le_u32(&mut self.hdr_mut()[HDROFF_FLAGS..], flags);
        self
    }

    pub fn set_flag(&mut self, flag: u32) -> &mut Self {
        self.set_flags(self.flags() | flag);
        self
    }

    pub fn buf_alloc(&self) -> u32 {
        byte_order::read_le_u32(&self.hdr()[HDROFF_BUF_ALLOC..])
    }

    pub fn set_buf_alloc(&mut self, buf_alloc: u32) -> &mut Self {
        byte_order::write_le_u32(&mut self.hdr_mut()[HDROFF_BUF_ALLOC..], buf_alloc);
        self
    }

    pub fn fwd_cnt(&self) -> u32 {
        byte_order::read_le_u32(&self.hdr()[HDROFF_FWD_CNT..])
    }

    pub fn set_fwd_cnt(&mut self, fwd_cnt: u32) -> &mut Self {
        byte_order::write_le_u32(&mut self.hdr_mut()[HDROFF_FWD_CNT..], fwd_cnt);
        self
    }

    pub fn sa_family(&self) -> Option<u16> {
        if self.buf_size >= 2 {
            Some(byte_order::read_le_u16(&self.buf().unwrap()[0..]))
        } else {
            None
        }
    }

    pub fn inet_port(&self) -> Option<u16> {
        if self.buf_size >= 4 {
            Some(byte_order::read_be_u16(&self.buf().unwrap()[2..]))
        } else {
            None
        }
    }

    pub fn inet_addr(&self) -> Option<[u8; 4]> {
        if self.buf_size >= 8 {
            let ptr = &self.buf().unwrap()[4];
            let slice = unsafe { std::slice::from_raw_parts(ptr as *const u8, 4) };
            slice[0..4].try_into().ok()
        } else {
            None
        }
    }

    pub fn unix_path(&self) -> Option<&str> {
        if self.buf_size >= 108 {
            // `sun_path` is not guaranteed to end in a NUL: stop at the end of the buffer.
            let path = &self.buf().unwrap()[2..108];
            CStr::from_bytes_until_nul(path).ok()?.to_str().ok()
        } else {
            None
        }
    }

    #[cfg(target_os = "linux")]
    fn parse_address(buf: &[u8], addr_len: u32) -> Option<SockaddrStorage> {
        // The guest chose `addr_len`; the address must lie inside the buffer.
        if addr_len as usize > buf.len() || buf.is_empty() {
            return None;
        }
        let sockaddr: SockaddrStorage = unsafe {
            SockaddrStorage::from_raw(&buf[0] as *const _ as *const sockaddr, Some(addr_len))?
        };

        match sockaddr.family() {
            Some(AddressFamily::Inet) => debug!("parse_address: AF_INET"),
            Some(AddressFamily::Inet6) => debug!("parse_address: AF_INET6"),
            Some(AddressFamily::Unix) => debug!("parse_address: AF_UNIX"),
            _ => {
                if let Some(family) = sockaddr.family() {
                    warn!("parse_address: unsupported family {family:?}");
                } else {
                    warn!("parse_address: error parsing family");
                }
                return None;
            }
        }

        Some(sockaddr)
    }

    #[cfg(target_os = "macos")]
    fn parse_address(buf: &[u8], addr_len: u32) -> Option<SockaddrStorage> {
        if addr_len as usize > buf.len() || buf.len() < 2 {
            return None;
        }
        let buf = &buf[..addr_len as usize];
        let family: u16 = byte_order::read_le_u16(&buf[0..2]);

        match family {
            defs::LINUX_AF_INET => {
                debug!("parse_address: AF_INET");
                if buf.len() < 8 {
                    return None;
                }
                let in_port: u16 = byte_order::read_be_u16(&buf[2..4]);
                let in_addr = Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]);
                Some(SocketAddrV4::new(in_addr, in_port).into())
            }
            defs::LINUX_AF_INET6 => {
                debug!("parse_address: AF_INET6");
                if buf.len() < 28 {
                    return None;
                }
                let in_port: u16 = byte_order::read_be_u16(&buf[2..4]);
                let flowinfo: u32 = byte_order::read_be_u32(&buf[4..8]);
                let in6_addr = Ipv6Addr::new(
                    byte_order::read_be_u16(&buf[8..10]),
                    byte_order::read_be_u16(&buf[10..12]),
                    byte_order::read_be_u16(&buf[12..14]),
                    byte_order::read_be_u16(&buf[14..16]),
                    byte_order::read_be_u16(&buf[16..18]),
                    byte_order::read_be_u16(&buf[18..20]),
                    byte_order::read_be_u16(&buf[20..22]),
                    byte_order::read_be_u16(&buf[22..24]),
                );
                let scope_id: u32 = byte_order::read_be_u32(&buf[24..28]);
                Some(SocketAddrV6::new(in6_addr, in_port, flowinfo, scope_id).into())
            }
            defs::LINUX_AF_UNIX => {
                // On macOS, SockaddrStorage doesn't implement `from_raw` for
                // Unix sockets, nor a way to cast an UnixPath to it.
                error!("AF_UNIX sockets aren't yet supported on macOS");
                None
            }
            _ => None,
        }
    }

    #[cfg(unix)]
    pub fn read_proxy_create(&self) -> Option<TsiProxyCreate> {
        if self.buf_size >= 8 {
            let peer_port: u32 = byte_order::read_le_u32(&self.buf().unwrap()[0..]);
            let family: u16 = byte_order::read_le_u16(&self.buf().unwrap()[4..]);
            let _type: u16 = byte_order::read_le_u16(&self.buf().unwrap()[6..]);

            Some(TsiProxyCreate {
                peer_port,
                family,
                _type,
            })
        } else {
            None
        }
    }

    #[cfg(unix)]
    pub fn read_connect_req(&self) -> Option<TsiConnectReq> {
        if self.buf_size >= 8 {
            let buf = self.buf().unwrap();
            let peer_port: u32 = byte_order::read_le_u32(&buf[0..]);
            let addr_len: u32 = byte_order::read_le_u32(&buf[4..]);
            let addr = Self::parse_address(&buf[8..], addr_len)?;

            Some(TsiConnectReq { peer_port, addr })
        } else {
            None
        }
    }

    #[cfg(unix)]
    pub fn write_connect_rsp(&mut self, rsp: TsiConnectRsp) {
        if self.buf_size >= 4 {
            if let Some(buf) = self.buf_mut() {
                byte_order::write_le_u32(&mut buf[0..], rsp.result as u32);
            }
        }
    }

    #[cfg(unix)]
    pub fn read_getname_req(&self) -> Option<TsiGetnameReq> {
        if self.buf_size >= 12 {
            let peer_port: u32 = byte_order::read_le_u32(&self.buf().unwrap()[0..]);
            let local_port: u32 = byte_order::read_le_u32(&self.buf().unwrap()[4..]);
            let peer: u32 = byte_order::read_le_u32(&self.buf().unwrap()[8..]);
            Some(TsiGetnameReq {
                peer_port,
                local_port,
                peer,
            })
        } else {
            None
        }
    }

    #[cfg(unix)]
    pub fn write_getname_rsp(&mut self, rsp: TsiGetnameRsp) {
        if self.buf_size >= 132 {
            if let Some(buf) = self.buf_mut() {
                byte_order::write_le_u32(&mut buf[0..], rsp.result as u32);
                byte_order::write_le_u32(&mut buf[4..], rsp.addr_len);
                let addr_ptr = rsp.addr.as_ptr();
                let slice = unsafe {
                    std::slice::from_raw_parts(addr_ptr as *const u8, rsp.addr.len() as usize)
                };
                buf[8..(rsp.addr.len() + 8) as usize].copy_from_slice(slice);

                // On macOS, convert BSD sockaddr (u8 sa_len + u8 sa_family) to
                // Linux wire format (u16 sa_family). Also translate macOS AF_*
                // values to their Linux equivalents (e.g. AF_INET6: 30 → 10).
                #[cfg(target_os = "macos")]
                {
                    let bsd_family = buf[9];
                    let linux_family: u16 = match bsd_family as i32 {
                        libc::AF_INET => defs::LINUX_AF_INET,
                        libc::AF_INET6 => defs::LINUX_AF_INET6,
                        _ => 0, // AF_UNSPEC
                    };
                    byte_order::write_le_u16(&mut buf[8..], linux_family);
                }
            }
        }
    }

    #[cfg(unix)]
    pub fn read_sendto_addr(&self) -> Option<TsiSendtoAddr> {
        if self.buf_size >= 8 {
            let buf = self.buf().unwrap();
            let peer_port: u32 = byte_order::read_le_u32(&buf[0..]);
            let addr_len: u32 = byte_order::read_le_u32(&buf[4..]);
            let addr = Self::parse_address(&buf[8..], addr_len)?;

            Some(TsiSendtoAddr { peer_port, addr })
        } else {
            None
        }
    }

    #[cfg(unix)]
    pub fn read_listen_req(&self) -> Option<TsiListenReq> {
        if self.buf_size >= 16 {
            let buf = self.buf().unwrap();
            let peer_port: u32 = byte_order::read_le_u32(&buf[0..]);
            let vm_port: u32 = byte_order::read_le_u32(&buf[4..]);
            let backlog: u32 = byte_order::read_le_u32(&buf[8..]);
            let addr_len: u32 = byte_order::read_le_u32(&buf[12..]);
            let addr = Self::parse_address(&buf[16..], addr_len)?;

            Some(TsiListenReq {
                peer_port,
                vm_port,
                backlog: backlog as i32,
                addr,
            })
        } else {
            None
        }
    }

    #[cfg(unix)]
    pub fn write_listen_rsp(&mut self, rsp: TsiListenRsp) {
        if self.buf_size >= 4 {
            if let Some(buf) = self.buf_mut() {
                byte_order::write_le_u32(&mut buf[0..], rsp.result as u32);
            }
        }
    }

    #[cfg(unix)]
    pub fn read_accept_req(&self) -> Option<TsiAcceptReq> {
        if self.buf_size >= 8 {
            let peer_port: u32 = byte_order::read_le_u32(&self.buf().unwrap()[0..]);
            let flags: u32 = byte_order::read_le_u32(&self.buf().unwrap()[4..]);

            Some(TsiAcceptReq { peer_port, flags })
        } else {
            None
        }
    }

    #[cfg(unix)]
    pub fn write_accept_rsp(&mut self, rsp: TsiAcceptRsp) {
        if self.buf_size >= 4 {
            if let Some(buf) = self.buf_mut() {
                byte_order::write_le_u32(&mut buf[0..], rsp.result as u32);
            }
        }
    }

    #[cfg(unix)]
    pub fn read_release_req(&self) -> Option<TsiReleaseReq> {
        if self.buf_size >= 8 {
            let peer_port: u32 = byte_order::read_le_u32(&self.buf().unwrap()[0..]);
            let local_port: u32 = byte_order::read_le_u32(&self.buf().unwrap()[4..]);
            Some(TsiReleaseReq {
                peer_port,
                local_port,
            })
        } else {
            None
        }
    }

    pub fn write_time_sync(&mut self, time: u64) {
        if self.buf_size >= 8 {
            if let Some(buf) = self.buf_mut() {
                byte_order::write_le_u64(&mut buf[0..], time);
            }
        }
    }
}

/// A guest buffer that ends exactly at an inaccessible page, so a parser that reads past the
/// descriptor faults instead of reading its neighbour.
#[cfg(all(unix, any(test, feature = "fuzzing")))]
pub(crate) mod guarded_buf {
    const PAGE: usize = 4096;

    pub(crate) struct GuardedBuf {
        base: *mut u8,
        pub(crate) start: *mut u8,
        pub(crate) len: usize,
    }

    impl GuardedBuf {
        /// `contents` must be at most one page.
        pub(crate) fn new(contents: &[u8]) -> Self {
            assert!(contents.len() <= PAGE);
            // SAFETY: a private anonymous mapping of two pages, unmapped in `drop`; the second
            // page is made inaccessible before any access.
            unsafe {
                let base = libc::mmap(
                    std::ptr::null_mut(),
                    2 * PAGE,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                )
                .cast::<u8>();
                assert_ne!(base.cast(), libc::MAP_FAILED);
                assert_eq!(
                    libc::mprotect(base.add(PAGE).cast(), PAGE, libc::PROT_NONE),
                    0
                );
                let start = base.add(PAGE - contents.len());
                std::ptr::copy_nonoverlapping(contents.as_ptr(), start, contents.len());
                Self {
                    base,
                    start,
                    len: contents.len(),
                }
            }
        }

        /// The packet a TX descriptor of this buffer yields (header unused by the parsers).
        pub(crate) fn packet(&self, hdr: &mut [u8; 44]) -> super::VsockPacket {
            super::VsockPacket {
                hdr: hdr.as_mut_ptr(),
                buf: Some(self.start),
                buf_size: self.len,
                owned_buf: None,
            }
        }
    }

    impl Drop for GuardedBuf {
        fn drop(&mut self) {
            // SAFETY: the mapping made in `new`.
            unsafe { libc::munmap(self.base.cast(), 2 * PAGE) };
        }
    }
}

/// Fuzz entry point for the TSI request parsers (feature `fuzzing`).
#[cfg(all(unix, feature = "fuzzing"))]
pub mod fuzzing {
    use super::guarded_buf::GuardedBuf;

    /// Every TSI request parser over one guest buffer that ends at an inaccessible page.
    ///
    /// The muxer reaches these parsers only with TSI on, and acting on a parsed request opens
    /// host sockets, so the target stops at the parsers and uses what they return.
    pub fn vsock_tsi(data: &[u8]) {
        let payload = &data[..data.len().min(2048)];
        let buf = GuardedBuf::new(payload);
        let mut hdr = [0u8; 44];
        let pkt = buf.packet(&mut hdr);
        if let Some(req) = pkt.read_proxy_create() {
            let _ = (req.peer_port, req.family, req._type);
        }
        if let Some(req) = pkt.read_connect_req() {
            let _ = (req.peer_port, format!("{:?}", req.addr));
        }
        if let Some(req) = pkt.read_sendto_addr() {
            let _ = (req.peer_port, format!("{:?}", req.addr));
        }
        if let Some(req) = pkt.read_listen_req() {
            let _ = (req.peer_port, req.vm_port, format!("{:?}", req.addr));
        }
        let _ = pkt.read_getname_req().map(|r| (r.peer_port, r.local_port));
        let _ = pkt.read_accept_req().map(|r| (r.peer_port, r.flags));
        let _ = pkt.read_release_req().map(|r| (r.peer_port, r.local_port));
        let _ = pkt.unix_path();
    }
}

#[cfg(all(test, unix))]
mod tsi_parser_tests {
    use super::guarded_buf::GuardedBuf;

    fn le32(v: u32) -> [u8; 4] {
        v.to_le_bytes()
    }

    #[test]
    fn unix_path_without_a_nul_stays_inside_the_buffer() {
        let mut contents = vec![b'a'; 108];
        contents[..2].copy_from_slice(&1u16.to_le_bytes());
        let buf = GuardedBuf::new(&contents);
        let mut hdr = [0u8; 44];
        assert_eq!(buf.packet(&mut hdr).unix_path(), None);
    }

    #[test]
    fn short_requests_are_refused_not_indexed() {
        let mut hdr = [0u8; 44];
        // proxy create reads 8 bytes, connect and sendto 8 plus the address, listen 16 plus it.
        for len in 0..8 {
            let buf = GuardedBuf::new(&vec![0u8; len]);
            assert!(buf.packet(&mut hdr).read_proxy_create().is_none(), "{len}");
        }
        for len in 0..=8 {
            let mut contents = vec![0u8; len];
            if len >= 8 {
                contents[4..8].copy_from_slice(&le32(16));
            }
            let buf = GuardedBuf::new(&contents);
            assert!(buf.packet(&mut hdr).read_connect_req().is_none(), "{len}");
            assert!(buf.packet(&mut hdr).read_sendto_addr().is_none(), "{len}");
        }
        for len in 0..=16 {
            let mut contents = vec![0u8; len];
            if len >= 16 {
                contents[12..16].copy_from_slice(&le32(16));
            }
            let buf = GuardedBuf::new(&contents);
            assert!(buf.packet(&mut hdr).read_listen_req().is_none(), "{len}");
        }
    }

    #[test]
    fn an_address_longer_than_the_buffer_is_refused() {
        let mut hdr = [0u8; 44];
        // An AF_INET sockaddr (16 bytes) announced, 6 bytes present.
        let mut contents = vec![0u8; 8 + 6];
        contents[4..8].copy_from_slice(&le32(16));
        contents[8..10].copy_from_slice(&2u16.to_ne_bytes());
        let buf = GuardedBuf::new(&contents);
        assert!(buf.packet(&mut hdr).read_connect_req().is_none());
        assert!(buf.packet(&mut hdr).read_sendto_addr().is_none());
    }

    #[test]
    fn a_complete_connect_request_still_parses() {
        let mut hdr = [0u8; 44];
        let mut contents = vec![0u8; 8 + 16];
        contents[0..4].copy_from_slice(&le32(1234));
        contents[4..8].copy_from_slice(&le32(16));
        contents[8..10].copy_from_slice(&2u16.to_ne_bytes());
        contents[10..12].copy_from_slice(&80u16.to_be_bytes());
        contents[12..16].copy_from_slice(&[10, 0, 0, 1]);
        let buf = GuardedBuf::new(&contents);
        let req = buf.packet(&mut hdr).read_connect_req().unwrap();
        assert_eq!(req.peer_port, 1234);
    }
}

#[cfg(test)]
mod tests {
    use vm_memory::{Bytes, GuestMemoryMmap};

    use super::*;
    use crate::virtio::Descriptor;

    const DESC_TABLE: u64 = 0x1000;
    const HEADER: u64 = 0x2000;
    const MEM_SIZE: usize = 0x40000;
    const NEXT: u16 = 1;

    /// Writes a TX chain of `descs` (address, length) with a header declaring `declared_len`
    /// bytes at `HEADER`, and parses it the way the device's TX queue does.
    fn parse_tx(
        mem: &GuestMemoryMmap,
        declared_len: u32,
        descs: &[(u64, u32)],
    ) -> Result<VsockPacket> {
        for (i, &(addr, len)) in descs.iter().enumerate() {
            let last = i + 1 == descs.len();
            mem.write_obj(
                Descriptor {
                    addr,
                    len,
                    flags: if last { 0 } else { NEXT },
                    next: if last { 0 } else { i as u16 + 1 },
                },
                GuestAddress(DESC_TABLE + 16 * i as u64),
            )
            .unwrap();
        }
        let mut header = [0u8; VSOCK_PKT_HDR_SIZE];
        header[HDROFF_LEN..HDROFF_LEN + 4].copy_from_slice(&declared_len.to_le_bytes());
        mem.write_slice(&header, GuestAddress(HEADER)).unwrap();
        let head = DescriptorChain::checked_new(mem, GuestAddress(DESC_TABLE), 16, 0).unwrap();
        VsockPacket::from_tx_virtq_head(&head)
    }

    /// Bytes that differ per offset, so a dropped or reordered fragment changes the result.
    fn pattern(len: usize, seed: u8) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8 ^ seed).collect()
    }

    fn memory() -> GuestMemoryMmap {
        GuestMemoryMmap::from_ranges(&[(GuestAddress(0), MEM_SIZE)]).unwrap()
    }

    /// Linux 6.12.y sends a write of over about 32 KiB as a nonlinear skb: the header in one
    /// descriptor and the data in one descriptor per page fragment.
    #[test]
    fn a_payload_split_over_several_descriptors_is_gathered_in_order() {
        let mem = memory();
        let (a, b) = (pattern(0x8000, 1), pattern(0x8000, 2));
        mem.write_slice(&a, GuestAddress(0x10000)).unwrap();
        mem.write_slice(&b, GuestAddress(0x4000)).unwrap();

        let pkt = parse_tx(
            &mem,
            0x10000,
            &[
                (HEADER, VSOCK_PKT_HDR_SIZE as u32),
                (0x10000, 0x8000),
                (0x4000, 0x8000),
            ],
        )
        .unwrap();

        assert_eq!(pkt.payload().unwrap(), [a, b].concat());
    }

    #[test]
    fn data_after_the_header_in_the_head_descriptor_is_part_of_the_payload() {
        let mem = memory();
        let (inline, rest) = (pattern(100, 3), pattern(900, 4));
        mem.write_slice(&inline, GuestAddress(HEADER + VSOCK_PKT_HDR_SIZE as u64))
            .unwrap();
        mem.write_slice(&rest, GuestAddress(0x4000)).unwrap();

        let combined = parse_tx(&mem, 100, &[(HEADER, VSOCK_PKT_HDR_SIZE as u32 + 100)]).unwrap();
        assert_eq!(combined.payload().unwrap(), &inline[..]);

        let both = parse_tx(
            &mem,
            1000,
            &[(HEADER, VSOCK_PKT_HDR_SIZE as u32 + 100), (0x4000, 900)],
        )
        .unwrap();
        assert_eq!(both.payload().unwrap(), [inline, rest].concat());
    }

    /// Only the declared length is read: a descriptor past it is never touched, even one
    /// that points outside guest memory.
    #[test]
    fn descriptors_past_the_declared_length_are_not_read() {
        let mem = memory();
        let data = pattern(0x3000, 5);
        mem.write_slice(&data, GuestAddress(0x4000)).unwrap();

        let pkt = parse_tx(
            &mem,
            0x3000,
            &[
                (HEADER, VSOCK_PKT_HDR_SIZE as u32),
                (0x4000, 0x1000),
                (0x5000, 0x8000),
                (MEM_SIZE as u64 * 4, 0x10000),
            ],
        )
        .unwrap();

        assert_eq!(pkt.payload().unwrap(), &data[..]);
    }

    #[test]
    fn a_chain_shorter_than_the_declared_length_is_refused() {
        let mem = memory();

        let short = parse_tx(
            &mem,
            0x10000,
            &[
                (HEADER, VSOCK_PKT_HDR_SIZE as u32),
                (0x4000, 0x8000),
                (0x10000, 0x7fff),
            ],
        );
        assert!(matches!(short, Err(VsockError::BufDescTooSmall)));

        let missing = parse_tx(&mem, 16, &[(HEADER, VSOCK_PKT_HDR_SIZE as u32)]);
        assert!(matches!(missing, Err(VsockError::BufDescMissing)));
    }

    #[test]
    fn a_writable_data_descriptor_is_refused() {
        let mem = memory();
        mem.write_obj(
            Descriptor {
                addr: HEADER,
                len: VSOCK_PKT_HDR_SIZE as u32,
                flags: NEXT,
                next: 1,
            },
            GuestAddress(DESC_TABLE),
        )
        .unwrap();
        mem.write_obj(
            Descriptor {
                addr: 0x4000,
                len: 0x100,
                flags: NEXT,
                next: 2,
            },
            GuestAddress(DESC_TABLE + 16),
        )
        .unwrap();
        mem.write_obj(
            Descriptor {
                addr: 0x5000,
                len: 0x100,
                flags: 2,
                next: 0,
            },
            GuestAddress(DESC_TABLE + 32),
        )
        .unwrap();
        let mut header = [0u8; VSOCK_PKT_HDR_SIZE];
        header[HDROFF_LEN..HDROFF_LEN + 4].copy_from_slice(&0x200u32.to_le_bytes());
        mem.write_slice(&header, GuestAddress(HEADER)).unwrap();
        let head = DescriptorChain::checked_new(&mem, GuestAddress(DESC_TABLE), 16, 0).unwrap();

        assert!(matches!(
            VsockPacket::from_tx_virtq_head(&head),
            Err(VsockError::UnreadableDescriptor)
        ));
    }
}

/// A TX packet builder shared by the proxy tests.
#[cfg(test)]
pub(crate) mod test_util {
    use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

    use super::*;
    use crate::virtio::{Descriptor, DescriptorChain};

    /// Header descriptor plus one data descriptor holding all of `descriptor`, while the header
    /// declares only `declared_len` bytes (a guest may declare less than the descriptor holds).
    pub(crate) fn tx_packet(
        mem: &GuestMemoryMmap,
        declared_len: u32,
        descriptor: &[u8],
    ) -> VsockPacket {
        const DESC_TABLE: u64 = 0x1000;
        const HEADER: u64 = 0x2000;
        const PAYLOAD: u64 = 0x3000;

        mem.write_obj(
            Descriptor {
                addr: HEADER,
                len: VSOCK_PKT_HDR_SIZE as u32,
                flags: 1,
                next: 1,
            },
            GuestAddress(DESC_TABLE),
        )
        .unwrap();
        mem.write_obj(
            Descriptor {
                addr: PAYLOAD,
                len: descriptor.len() as u32,
                flags: 0,
                next: 0,
            },
            GuestAddress(DESC_TABLE + 16),
        )
        .unwrap();
        let mut header = [0u8; VSOCK_PKT_HDR_SIZE];
        header[HDROFF_LEN..HDROFF_LEN + 4].copy_from_slice(&declared_len.to_le_bytes());
        mem.write_slice(&header, GuestAddress(HEADER)).unwrap();
        mem.write_slice(descriptor, GuestAddress(PAYLOAD)).unwrap();

        let head = DescriptorChain::checked_new(mem, GuestAddress(DESC_TABLE), 2, 0).unwrap();
        VsockPacket::from_tx_virtq_head(&head).unwrap()
    }
}
