use super::{
    defs::{self, uapi},
    proxy::{ProxyRemoval, RecvPkt},
};

use nix::errno::Errno;
use nix::fcntl::{fcntl, FcntlArg, OFlag};
use nix::sys::socket::{
    accept, bind, connect, getsockopt, listen, recv, send, shutdown, socket, sockopt,
    AddressFamily, Backlog, MsgFlags, Shutdown, SockFlag, SockType, UnixAddr,
};
use std::collections::HashMap;
use std::collections::VecDeque;
use std::io;
use std::num::Wrapping;
use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

#[cfg(target_os = "macos")]
use super::super::linux_errno::linux_errno_raw;
use super::super::Queue as VirtQueue;
use super::muxer::{push_packet, MuxerRx};
use super::muxer_rxq::MuxerRxQ;
use super::packet::{TsiAcceptReq, TsiConnectReq, TsiListenReq, TsiSendtoAddr, VsockPacket};
use super::proxy::{NewProxyType, Proxy, ProxyError, ProxyStatus, ProxyUpdate};
use utils::epoll::EventSet;

use vm_memory::GuestMemoryMmap;

pub struct UnixProxy {
    id: u64,
    cid: u64,
    endpoint: StreamEndpoint,
    pub status: ProxyStatus,
    mem: GuestMemoryMmap,
    queue: Arc<Mutex<VirtQueue>>,
    rxq: Arc<Mutex<MuxerRxQ>>,
    path: PathBuf,
    peer_port: u32,
    local_port: u32,
    control_port: u32,
    peer_fwd_cnt: Wrapping<u32>,
    peer_buf_alloc: u32,
    tx_cnt: Wrapping<u32>,
    last_tx_cnt_sent: Wrapping<u32>,
    push_cnt: Wrapping<u32>,
    rx_cnt: Wrapping<u32>,
    pending_write: VecDeque<u8>,
    /// A guest shutdown that arrived while `pending_write` still held bytes. Shutting the socket
    /// down first would drop them, so it waits until they are out.
    pending_shutdown: Option<Shutdown>,
    /// The guest released the connection while `pending_write` still held bytes it was credited
    /// for. The proxy stays, only to write them out, and is removed once they are gone.
    guest_closed: bool,
}

enum StreamEndpoint {
    Unix(OwnedFd),
}

impl StreamEndpoint {
    fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Unix(fd) => recv(fd.as_raw_fd(), buf, MsgFlags::MSG_DONTWAIT)
                .map_err(|err| io::Error::from_raw_os_error(err as i32)),
        }
    }

    fn write(&self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Self::Unix(fd) => {
                #[cfg(target_os = "macos")]
                let flags = MsgFlags::empty();
                #[cfg(target_os = "linux")]
                let flags = MsgFlags::MSG_NOSIGNAL;
                send(fd.as_raw_fd(), buf, flags)
                    .map_err(|err| io::Error::from_raw_os_error(err as i32))
            }
        }
    }

    fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        match self {
            Self::Unix(fd) => shutdown(fd.as_raw_fd(), how)
                .map_err(|err| io::Error::from_raw_os_error(err as i32)),
        }
    }
}

impl AsRawFd for StreamEndpoint {
    fn as_raw_fd(&self) -> RawFd {
        match self {
            Self::Unix(fd) => fd.as_raw_fd(),
        }
    }
}

fn proxy_fd_create(id: u64) -> Result<OwnedFd, ProxyError> {
    let fd = socket(
        AddressFamily::Unix,
        SockType::Stream,
        SockFlag::empty(),
        None,
    )
    .map_err(ProxyError::CreatingSocket)?;

    // macOS forces us to do this here instead of just using SockFlag::SOCK_NONBLOCK above.
    match fcntl(&fd, FcntlArg::F_GETFL) {
        Ok(flags) => match OFlag::from_bits(flags) {
            Some(flags) => {
                if let Err(e) = fcntl(&fd, FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK)) {
                    warn!("error switching to non-blocking: id={id}, err={e}");
                }
            }
            None => error!("invalid fd flags id={id}"),
        },
        Err(e) => error!("couldn't obtain fd flags id={id}, err={e}"),
    };

    #[cfg(target_os = "macos")]
    {
        // nix doesn't provide an abstraction for SO_NOSIGPIPE, fall back to libc.
        let option_value: libc::c_int = 1;
        unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_NOSIGPIPE,
                &option_value as *const _ as *const libc::c_void,
                std::mem::size_of_val(&option_value) as libc::socklen_t,
            )
        };
    }

    Ok(fd)
}

impl UnixProxy {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: u64,
        cid: u64,
        local_port: u32,
        control_port: u32,
        mem: GuestMemoryMmap,
        queue: Arc<Mutex<VirtQueue>>,
        rxq: Arc<Mutex<MuxerRxQ>>,
        path: PathBuf,
    ) -> Result<Self, ProxyError> {
        let fd = proxy_fd_create(id)?;

        Ok(UnixProxy {
            id,
            cid,
            local_port,
            peer_port: 0,
            control_port,
            endpoint: StreamEndpoint::Unix(fd),
            status: ProxyStatus::Idle,
            mem,
            queue,
            rxq,
            peer_buf_alloc: 0,
            peer_fwd_cnt: Wrapping(0),
            path,
            tx_cnt: Wrapping(0),
            last_tx_cnt_sent: Wrapping(0),
            push_cnt: Wrapping(0),
            rx_cnt: Wrapping(0),
            pending_write: VecDeque::new(),
            pending_shutdown: None,
            guest_closed: false,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_reverse(
        id: u64,
        cid: u64,
        local_port: u32,
        peer_port: u32,
        fd: OwnedFd,
        mem: GuestMemoryMmap,
        queue: Arc<Mutex<VirtQueue>>,
        rxq: Arc<Mutex<MuxerRxQ>>,
    ) -> Self {
        debug!("new_reverse: id={id} local_port={local_port} peer_port={peer_port}");
        // Accepted sockets are not guaranteed to inherit O_NONBLOCK. Keeping
        // them nonblocking prevents a slow peer from stalling the muxer.
        if let Ok(flags) = fcntl(&fd, FcntlArg::F_GETFL) {
            if let Some(flags) = OFlag::from_bits(flags) {
                if let Err(err) = fcntl(&fd, FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK)) {
                    warn!("failed to make reverse Unix vsock nonblocking: {err}");
                }
            }
        }
        UnixProxy {
            id,
            cid,
            local_port,
            peer_port,
            control_port: 0,
            endpoint: StreamEndpoint::Unix(fd),
            status: ProxyStatus::ReverseInit,
            mem,
            queue,
            rxq,
            rx_cnt: Wrapping(0),
            tx_cnt: Wrapping(0),
            last_tx_cnt_sent: Wrapping(0),
            peer_buf_alloc: 0,
            peer_fwd_cnt: Wrapping(0),
            push_cnt: Wrapping(0),
            path: Default::default(),
            pending_write: VecDeque::new(),
            pending_shutdown: None,
            guest_closed: false,
        }
    }

    fn switch_to_connected(&mut self) {
        self.status = ProxyStatus::Connected;
    }

    /// Connect a typed AF_VSOCK route without emitting TSI control packets.
    pub fn connect_vsock(&mut self) -> Result<ProxyUpdate, i32> {
        let addr = UnixAddr::new(&self.path).map_err(|_| -libc::EINVAL)?;
        let mut update = ProxyUpdate::default();

        match connect(self.endpoint.as_raw_fd(), &addr) {
            Ok(()) => self.switch_to_connected(),
            Err(Errno::EINPROGRESS) => self.status = ProxyStatus::Connecting,
            Err(err) => {
                #[cfg(target_os = "macos")]
                return Err(-linux_errno_raw(err as i32));
                #[cfg(target_os = "linux")]
                return Err(-(err as i32));
            }
        }

        update.polling = Some((
            self.id,
            self.endpoint.as_raw_fd(),
            if self.status == ProxyStatus::Connecting {
                EventSet::IN | EventSet::OUT
            } else {
                EventSet::IN
            },
        ));
        Ok(update)
    }

    /// Record peer flow-control state while a nonblocking route connect is pending.
    pub fn prepare_vsock_connect(&mut self, pkt: &VsockPacket) {
        self.peer_buf_alloc = pkt.buf_alloc();
        self.peer_fwd_cnt = Wrapping(pkt.fwd_cnt());
        self.local_port = pkt.dst_port();
        self.peer_port = pkt.src_port();
    }

    /// Confirm a completed route connection to the guest.
    pub fn confirm_vsock_connect(&mut self, pkt: &VsockPacket) {
        self.prepare_vsock_connect(pkt);
        self.push_vsock_connect_response();
    }

    fn push_vsock_connect_response(&self) {
        let rx = MuxerRx::OpResponse {
            local_port: self.local_port,
            peer_port: self.peer_port,
        };
        push_packet(self.cid, rx, &self.rxq, &self.queue, &self.mem);
    }

    fn push_connect_rsp(&self, result: i32) {
        debug!(
            "push_connect_rsp: id: {}, control_port: {}, result: {}",
            self.id, self.control_port, result
        );

        // This response goes to the control port (DGRAM).
        let rx = MuxerRx::ConnResponse {
            local_port: 1025,
            peer_port: self.control_port,
            result,
        };
        push_packet(self.cid, rx, &self.rxq, &self.queue, &self.mem);
    }

    fn push_reset(&self) {
        debug!(
            "push_reset: id: {}, peer_port: {}, local_port: {}",
            self.id, self.peer_port, self.local_port
        );

        let rx = MuxerRx::Reset {
            local_port: self.local_port,
            peer_port: self.peer_port,
        };

        push_packet(self.cid, rx, &self.rxq, &self.queue, &self.mem);
    }

    fn peer_avail_credit(&self) -> usize {
        (Wrapping(self.peer_buf_alloc) - (self.rx_cnt - self.peer_fwd_cnt)).0 as usize
    }

    fn recv_to_pkt(&self, pkt: &mut VsockPacket) -> RecvPkt {
        if let Some(buf) = pkt.buf_mut() {
            let peer_credit = self.peer_avail_credit();
            let max_len = std::cmp::min(buf.len(), peer_credit);

            debug!(
                "recv_to_pkt: peer_avail_credit={}, buf.len={}, max_len={}",
                self.peer_avail_credit(),
                buf.len(),
                max_len
            );

            if max_len == 0 {
                return RecvPkt::WaitForCredit;
            }

            match self.endpoint.read(&mut buf[..max_len]) {
                Ok(cnt) => {
                    if cnt > max_len {
                        warn!(
                            "vsock backend returned invalid read length: count={cnt}, capacity={max_len}"
                        );
                        return RecvPkt::Error;
                    }
                    debug!("recv cnt={cnt}");
                    if cnt > 0 {
                        debug!("recv rx_cnt={}", self.rx_cnt);
                        RecvPkt::Read(cnt)
                    } else {
                        RecvPkt::Close
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => RecvPkt::Error,
                Err(e) => {
                    debug!("recv_pkt: recv error: {e:?}");
                    RecvPkt::Error
                }
            }
        } else {
            debug!("recv_pkt: pkt without buf");
            RecvPkt::Error
        }
    }

    fn recv_pkt(&mut self) -> (bool, bool) {
        let mut have_used = false;
        let mut wait_credit = false;
        let mut queue = self.queue.lock().unwrap();

        while let Some(head) = queue.pop(&self.mem) {
            let len = match VsockPacket::from_rx_virtq_head(&head) {
                Ok(mut pkt) => match self.recv_to_pkt(&mut pkt) {
                    RecvPkt::WaitForCredit => {
                        wait_credit = true;
                        0
                    }
                    RecvPkt::Read(cnt) => {
                        self.rx_cnt += Wrapping(cnt as u32);
                        self.init_data_pkt(&mut pkt);
                        pkt.set_len(cnt as u32);
                        pkt.hdr().len() + cnt
                    }
                    RecvPkt::Close => {
                        self.status = ProxyStatus::Closed;
                        0
                    }
                    RecvPkt::Error => 0,
                },
                Err(e) => {
                    debug!("recv_pkt: RX queue error: {e:?}");
                    0
                }
            };

            if len == 0 {
                queue.undo_pop();
                break;
            } else {
                have_used = true;
                self.push_cnt += Wrapping(len as u32);
                debug!(
                    "recv_pkt: pushing packet with {} bytes, push_cnt={}",
                    len, self.push_cnt
                );
                if let Err(e) = queue.add_used(&self.mem, head.index, len as u32) {
                    error!("failed to add used elements to the queue: {e:?}");
                }
            }
        }

        debug!("recv_pkt: have_used={have_used}");
        (have_used, wait_credit)
    }

    fn flush_pending_write(&mut self) -> io::Result<()> {
        while !self.pending_write.is_empty() {
            let (front, back) = self.pending_write.as_slices();
            let buf = if front.is_empty() { back } else { front };
            match self.endpoint.write(buf) {
                Ok(0) => return Err(io::Error::from(io::ErrorKind::WriteZero)),
                Ok(written) => {
                    if written > buf.len() {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "vsock backend returned a write length larger than its input",
                        ));
                    }
                    self.pending_write.drain(..written);
                }
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                Err(err) => return Err(err),
            }
        }
        Ok(())
    }

    /// Shut the socket down once every accepted byte has been written to it.
    fn apply_pending_shutdown(&mut self) {
        if !self.pending_write.is_empty() {
            return;
        }
        if let Some(how) = self.pending_shutdown.take() {
            if let Err(e) = self.endpoint.shutdown(how) {
                warn!("error sending shutdown to socket: {e}");
            }
        }
    }

    fn connected_poll_events(&self) -> EventSet {
        if self.guest_closed {
            // Nobody is left to read what the socket sends.
            EventSet::OUT
        } else if self.pending_write.is_empty() {
            EventSet::IN
        } else {
            EventSet::IN | EventSet::OUT
        }
    }

    fn init_data_pkt(&self, pkt: &mut VsockPacket) {
        debug!(
            "init_data_pkt: id={}, local_port={}, peer_port={}",
            self.id, self.local_port, self.peer_port
        );

        pkt.set_op(uapi::VSOCK_OP_RW)
            .set_src_cid(uapi::VSOCK_HOST_CID)
            .set_dst_cid(self.cid)
            .set_src_port(self.local_port)
            .set_dst_port(self.peer_port)
            .set_type(uapi::VSOCK_TYPE_STREAM)
            .set_buf_alloc(defs::CONN_TX_BUF_SIZE as u32)
            .set_fwd_cnt(self.tx_cnt.0);
    }
}

impl Proxy for UnixProxy {
    fn id(&self) -> u64 {
        self.id
    }

    fn pollable(&self) -> RawFd {
        self.as_raw_fd()
    }

    fn status(&self) -> ProxyStatus {
        self.status
    }

    fn connect(&mut self, _pkt: &VsockPacket, _req: TsiConnectReq) -> ProxyUpdate {
        let mut update = ProxyUpdate::default();

        let addr = match UnixAddr::new(&self.path) {
            Ok(addr) => addr,
            Err(err) => {
                warn!(
                    "invalid Unix socket path for vsock route {:?}: {err}",
                    self.path
                );
                self.push_connect_rsp(-libc::EINVAL);
                update.signal_queue = true;
                update.remove_proxy = ProxyRemoval::Immediate;
                return update;
            }
        };

        let result = match connect(self.endpoint.as_raw_fd(), &addr) {
            Ok(()) => {
                debug!("connect: Connected");
                self.switch_to_connected();
                0
            }
            Err(nix::errno::Errno::EINPROGRESS) => {
                debug!("connect: Connecting");
                self.status = ProxyStatus::Connecting;
                0
            }
            Err(e) => {
                debug!("Error connecting: {e}");
                #[cfg(target_os = "macos")]
                let errno = -linux_errno_raw(Errno::last_raw());
                #[cfg(target_os = "linux")]
                let errno = -Errno::last_raw();
                errno
            }
        };

        if self.status == ProxyStatus::Connecting {
            update.polling = Some((
                self.id,
                self.endpoint.as_raw_fd(),
                EventSet::IN | EventSet::OUT,
            ));
        } else {
            if self.status == ProxyStatus::Connected {
                update.polling = Some((self.id, self.endpoint.as_raw_fd(), EventSet::IN));
            }
            self.push_connect_rsp(result);
        }

        update
    }

    fn confirm_connect(&mut self, pkt: &VsockPacket) -> Option<ProxyUpdate> {
        debug!(
            "confirm_connect: local_port={} peer_port={}, src_port={}, dst_port={}",
            pkt.dst_port(),
            pkt.src_port(),
            self.local_port,
            self.peer_port,
        );

        self.confirm_vsock_connect(pkt);

        None
    }

    fn getpeername(&mut self, _pkt: &VsockPacket) {
        todo!();
    }

    fn sendmsg(&mut self, pkt: &VsockPacket) -> ProxyUpdate {
        let mut update = ProxyUpdate::default();

        let ret = if let Some(buf) = pkt.tx_data() {
            // Credit is returned when bytes enter this bounded proxy queue;
            // readiness drives later partial flushes without blocking a VMM thread.
            self.pending_write.extend(buf);
            self.tx_cnt += Wrapping(buf.len() as u32);
            if let Err(err) = self.flush_pending_write() {
                warn!("vsock backend write failed: {err}");
                self.push_reset();
                self.status = ProxyStatus::Closed;
                update.signal_queue = true;
                update.remove_proxy = ProxyRemoval::Deferred;
            }
            update.polling = Some((
                self.id,
                self.endpoint.as_raw_fd(),
                self.connected_poll_events(),
            ));
            buf.len() as i32
        } else {
            -libc::EINVAL
        };

        if ret > 0
            && (self.tx_cnt - self.last_tx_cnt_sent).0 as usize >= (defs::CONN_TX_BUF_SIZE / 2)
        {
            debug!(
                "sending credit update: id={}, tx_cnt={}, last_tx_cnt={}",
                self.id, self.tx_cnt, self.last_tx_cnt_sent
            );
            self.last_tx_cnt_sent = self.tx_cnt;

            let rx = MuxerRx::CreditUpdate {
                local_port: pkt.dst_port(),
                peer_port: pkt.src_port(),
                fwd_cnt: self.tx_cnt.0,
            };

            push_packet(self.cid, rx, &self.rxq, &self.queue, &self.mem);
            update.signal_queue = true;
        }

        debug!("sendmsg ret={ret}");

        update
    }

    fn sendto_addr(&mut self, _req: TsiSendtoAddr) -> ProxyUpdate {
        todo!();
    }

    fn listen(
        &mut self,
        _pkt: &VsockPacket,
        _req: TsiListenReq,
        _host_port_map: &Option<HashMap<u16, u16>>,
    ) -> ProxyUpdate {
        todo!();
    }

    fn accept(&mut self, _req: TsiAcceptReq) -> ProxyUpdate {
        todo!();
    }

    fn update_peer_credit(&mut self, pkt: &VsockPacket) -> ProxyUpdate {
        debug!(
            "update_credit: buf_alloc={} rx_cnt={} fwd_cnt={}",
            pkt.buf_alloc(),
            self.rx_cnt,
            pkt.fwd_cnt()
        );
        self.peer_buf_alloc = pkt.buf_alloc();
        self.peer_fwd_cnt = Wrapping(pkt.fwd_cnt());

        self.status = ProxyStatus::Connected;
        self.kick();

        ProxyUpdate {
            polling: Some((
                self.id,
                self.endpoint.as_raw_fd(),
                self.connected_poll_events(),
            )),
            ..Default::default()
        }
    }

    fn push_op_request(&self) {
        debug!(
            "push_op_request: id={}, local_port={} peer_port={}",
            self.id, self.local_port, self.peer_port
        );

        // This packet goes to the connection.
        let rx = MuxerRx::OpRequest {
            local_port: self.local_port,
            peer_port: self.peer_port,
        };
        push_packet(self.cid, rx, &self.rxq, &self.queue, &self.mem);
    }

    fn process_op_response(&mut self, pkt: &VsockPacket) -> ProxyUpdate {
        debug!(
            "process_op_response: id={} src_port={} dst_port={}",
            self.id,
            pkt.src_port(),
            pkt.dst_port()
        );

        self.peer_buf_alloc = pkt.buf_alloc();
        self.peer_fwd_cnt = Wrapping(pkt.fwd_cnt());

        self.switch_to_connected();

        ProxyUpdate {
            polling: Some((
                self.id,
                self.endpoint.as_raw_fd(),
                self.connected_poll_events(),
            )),
            ..Default::default()
        }
    }

    fn enqueue_accept(&mut self) {
        todo!();
    }

    fn shutdown(&mut self, pkt: &VsockPacket) {
        let recv_off = pkt.flags() & uapi::VSOCK_FLAGS_SHUTDOWN_RCV != 0;
        let send_off = pkt.flags() & uapi::VSOCK_FLAGS_SHUTDOWN_SEND != 0;

        let how = if recv_off && send_off {
            Shutdown::Both
        } else if recv_off {
            Shutdown::Read
        } else {
            Shutdown::Write
        };

        if how == Shutdown::Read {
            // The write side stays open, so queued bytes are not at risk.
            if let Err(e) = self.endpoint.shutdown(how) {
                warn!("error sending shutdown to socket: {e}");
            }
            return;
        }
        // The guest sends SHUTDOWN after its last data packet, but the socket may not have taken
        // all of it yet. Keep the order: data first.
        self.pending_shutdown = Some(match self.pending_shutdown {
            Some(earlier) if earlier != how => Shutdown::Both,
            _ => how,
        });
        self.apply_pending_shutdown();
    }

    fn release(&mut self) -> ProxyUpdate {
        debug!(
            "release: id={}, tx_cnt={}, last_tx_cnt={}",
            self.id, self.tx_cnt, self.last_tx_cnt_sent
        );
        if !self.pending_write.is_empty()
            && matches!(
                self.status,
                ProxyStatus::Connected | ProxyStatus::WaitingCreditUpdate
            )
        {
            // Dropping the proxy now would close the socket with the tail unsent.
            self.guest_closed = true;
            return ProxyUpdate {
                polling: Some((
                    self.id,
                    self.endpoint.as_raw_fd(),
                    self.connected_poll_events(),
                )),
                ..Default::default()
            };
        }
        let remove_proxy = ProxyRemoval::Deferred;

        ProxyUpdate {
            remove_proxy,
            ..Default::default()
        }
    }

    fn process_event(&mut self, evset: EventSet) -> ProxyUpdate {
        let mut update = ProxyUpdate::default();

        if evset.contains(EventSet::HANG_UP) {
            debug!("process_event: HANG_UP");

            self.push_reset();

            self.status = ProxyStatus::Closed;
            update.polling = Some((self.id, self.endpoint.as_raw_fd(), EventSet::empty()));
            update.signal_queue = true;
            update.remove_proxy = ProxyRemoval::Deferred;

            return update;
        }

        if evset.contains(EventSet::IN) && !self.guest_closed {
            debug!("process_event: IN");
            if self.status == ProxyStatus::Connected {
                if !self.pending_write.is_empty() {
                    if let Err(err) = self.flush_pending_write() {
                        warn!("vsock backend write failed: {err}");
                        self.push_reset();
                        self.status = ProxyStatus::Closed;
                        update.signal_queue = true;
                        update.remove_proxy = ProxyRemoval::Deferred;
                        return update;
                    }
                }
                let (signal_queue, wait_credit) = self.recv_pkt();
                update.signal_queue = signal_queue;

                if wait_credit && self.status != ProxyStatus::WaitingCreditUpdate {
                    self.status = ProxyStatus::WaitingCreditUpdate;
                    let rx = MuxerRx::CreditRequest {
                        local_port: self.local_port,
                        peer_port: self.peer_port,
                        fwd_cnt: self.tx_cnt.0,
                    };
                    update.push_credit_req = Some(rx);
                }

                if self.status == ProxyStatus::Closed {
                    debug!(
                        "process_event: endpoint closed, sending reset: id={}",
                        self.id
                    );

                    self.push_reset();
                    update.signal_queue = true;
                    update.polling =
                        Some((self.id(), self.endpoint.as_raw_fd(), EventSet::empty()));
                    return update;
                } else if self.status == ProxyStatus::WaitingCreditUpdate {
                    debug!("process_event: WaitingCreditUpdate");
                    update.polling =
                        Some((self.id(), self.endpoint.as_raw_fd(), EventSet::empty()));
                }
            } else {
                debug!("EventSet::IN while not connected: {:?}", self.status);
            }
        }

        if evset.contains(EventSet::OUT) {
            debug!("process_event: OUT");
            if self.status == ProxyStatus::Connecting {
                let connect_error = match &self.endpoint {
                    StreamEndpoint::Unix(fd) => {
                        getsockopt(fd, sockopt::SocketError).unwrap_or(libc::EIO)
                    }
                };
                if connect_error != 0 {
                    warn!("Unix vsock connect failed asynchronously: errno {connect_error}");
                    self.push_reset();
                    self.status = ProxyStatus::Closed;
                    update.signal_queue = true;
                    update.remove_proxy = ProxyRemoval::Deferred;
                    update.polling =
                        Some((self.id(), self.endpoint.as_raw_fd(), EventSet::empty()));
                    return update;
                }
                self.switch_to_connected();
                self.push_vsock_connect_response();
                update.signal_queue = true;
                if let Err(err) = self.flush_pending_write() {
                    warn!("vsock backend write failed after connect: {err}");
                    self.push_reset();
                    self.status = ProxyStatus::Closed;
                    update.remove_proxy = ProxyRemoval::Deferred;
                }
                update.polling = Some((
                    self.id(),
                    self.endpoint.as_raw_fd(),
                    self.connected_poll_events(),
                ));
            } else if self.status == ProxyStatus::Connected {
                if let Err(err) = self.flush_pending_write() {
                    warn!("vsock backend write failed: {err}");
                    self.pending_write.clear();
                    if !self.guest_closed {
                        self.push_reset();
                        update.signal_queue = true;
                    }
                    self.status = ProxyStatus::Closed;
                    update.remove_proxy = ProxyRemoval::Deferred;
                } else {
                    self.apply_pending_shutdown();
                    if self.guest_closed && self.pending_write.is_empty() {
                        self.status = ProxyStatus::Closed;
                        update.remove_proxy = ProxyRemoval::Deferred;
                    }
                }
                let events = if self.status == ProxyStatus::Closed {
                    EventSet::empty()
                } else {
                    self.connected_poll_events()
                };
                update.polling = Some((self.id(), self.endpoint.as_raw_fd(), events));
            } else {
                error!("EventSet::OUT in unexpected state: {:?}", self.status);
            }
        }

        update
    }
}

impl AsRawFd for UnixProxy {
    fn as_raw_fd(&self) -> RawFd {
        self.endpoint.as_raw_fd()
    }
}

pub struct UnixAcceptorProxy {
    id: u64,
    fd: OwnedFd,
    peer_port: u32,
}

impl UnixAcceptorProxy {
    pub fn new(id: u64, path: &PathBuf, peer_port: u32) -> Result<Self, ProxyError> {
        let fd = socket(
            AddressFamily::Unix,
            SockType::Stream,
            SockFlag::empty(),
            None,
        )
        .map_err(ProxyError::CreatingSocket)?;
        bind(
            fd.as_raw_fd(),
            &UnixAddr::new(path).map_err(ProxyError::CreatingSocket)?,
        )
        .map_err(ProxyError::CreatingSocket)?;
        listen(&fd, Backlog::new(5).map_err(ProxyError::CreatingSocket)?)
            .map_err(ProxyError::CreatingSocket)?;
        Ok(UnixAcceptorProxy { id, fd, peer_port })
    }
}

impl Proxy for UnixAcceptorProxy {
    fn id(&self) -> u64 {
        self.id
    }
    fn pollable(&self) -> RawFd {
        self.as_raw_fd()
    }
    fn status(&self) -> ProxyStatus {
        ProxyStatus::WaitingOnAccept
    }
    fn connect(&mut self, _: &VsockPacket, _: TsiConnectReq) -> ProxyUpdate {
        unreachable!()
    }
    fn getpeername(&mut self, _: &VsockPacket) {
        unreachable!()
    }
    fn sendmsg(&mut self, _: &VsockPacket) -> ProxyUpdate {
        unreachable!()
    }
    fn sendto_addr(&mut self, _: TsiSendtoAddr) -> ProxyUpdate {
        unreachable!()
    }
    fn listen(
        &mut self,
        _: &VsockPacket,
        _: TsiListenReq,
        _: &Option<HashMap<u16, u16>>,
    ) -> ProxyUpdate {
        unreachable!()
    }
    fn accept(&mut self, _: TsiAcceptReq) -> ProxyUpdate {
        unreachable!()
    }
    fn update_peer_credit(&mut self, _: &VsockPacket) -> ProxyUpdate {
        unreachable!()
    }
    fn process_op_response(&mut self, _: &VsockPacket) -> ProxyUpdate {
        unreachable!()
    }
    fn release(&mut self) -> ProxyUpdate {
        unreachable!()
    }
    fn process_event(&mut self, evset: EventSet) -> ProxyUpdate {
        let mut update = ProxyUpdate::default();

        if evset.contains(EventSet::HANG_UP) {
            debug!("process_event: HANG_UP");
            update.polling = Some((self.id, self.fd.as_raw_fd(), EventSet::empty()));
            update.signal_queue = true;
            update.remove_proxy = ProxyRemoval::Deferred;
            return update;
        }
        if evset.contains(EventSet::IN) {
            match accept(self.fd.as_raw_fd()) {
                Ok(accept_fd) => {
                    // Safe because we've just obtained the FD from the `accept` call above.
                    let new_fd = unsafe { OwnedFd::from_raw_fd(accept_fd) };
                    update.new_proxy = Some((
                        self.peer_port,
                        new_fd,
                        AddressFamily::Unix,
                        NewProxyType::Unix,
                    ));
                }
                Err(e) => warn!("error accepting connection: id={}, err={}", self.id, e),
            };
            update.signal_queue = true;
        }
        update
    }
}

impl AsRawFd for UnixAcceptorProxy {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

#[cfg(test)]
mod tests {
    use vm_memory::{GuestAddress, GuestMemoryMmap};

    use super::super::defs::uapi;
    use super::super::packet::test_util::tx_packet;
    use super::*;

    /// Bytes queued for the host socket and counted as credit are the declared length.
    #[test]
    fn sendmsg_queues_only_the_declared_length() {
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        let mut proxy = UnixProxy::new(
            1,
            3,
            5000,
            1234,
            mem.clone(),
            Arc::new(Mutex::new(VirtQueue::new(256))),
            Arc::new(Mutex::new(MuxerRxQ::new())),
            PathBuf::from("/nonexistent/krun-t954"),
        )
        .unwrap();
        let pkt = tx_packet(&mem, 1, b"a-secret-tail");

        proxy.sendmsg(&pkt);

        assert_eq!(proxy.tx_cnt.0, 1);
    }

    /// A proxy in the connected state whose socket took only part of a 32 KiB write.
    fn proxy_with_tail(
        mem: &GuestMemoryMmap,
    ) -> (UnixProxy, std::os::unix::net::UnixStream, Vec<u8>) {
        use nix::sys::socket::{setsockopt, sockopt};

        const LEN: usize = 32 * 1024;
        let mut proxy = UnixProxy::new(
            1,
            3,
            5000,
            1234,
            mem.clone(),
            Arc::new(Mutex::new(VirtQueue::new(256))),
            Arc::new(Mutex::new(MuxerRxQ::new())),
            PathBuf::from("/nonexistent/krun-t1052"),
        )
        .unwrap();
        let (host, peer) = std::os::unix::net::UnixStream::pair().unwrap();
        setsockopt(&host, sockopt::SndBuf, &4096).unwrap();
        host.set_nonblocking(true).unwrap();
        peer.set_nonblocking(true).unwrap();
        proxy.endpoint = StreamEndpoint::Unix(host.into());
        proxy.status = ProxyStatus::Connected;
        let payload: Vec<u8> = (0..LEN).map(|i| (i % 251) as u8).collect();
        proxy.sendmsg(&tx_packet(mem, LEN as u32, &payload));
        assert!(
            !proxy.pending_write.is_empty(),
            "the socket must refuse part of the write"
        );
        (proxy, peer, payload)
    }

    fn drain(
        proxy: &mut UnixProxy,
        peer: &mut std::os::unix::net::UnixStream,
    ) -> (Vec<u8>, bool, ProxyUpdate) {
        use std::io::Read;

        let mut got = Vec::new();
        let mut buf = [0u8; 8192];
        let mut last = ProxyUpdate::default();
        for _ in 0..1000 {
            loop {
                match peer.read(&mut buf) {
                    Ok(0) => return (got, true, last),
                    Ok(n) => got.extend_from_slice(&buf[..n]),
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) => panic!("read: {e}"),
                }
            }
            if !proxy.pending_write.is_empty() {
                last = proxy.process_event(EventSet::OUT);
            }
        }
        (got, false, last)
    }

    fn shutdown_packet(mem: &GuestMemoryMmap, flags: u32) -> VsockPacket {
        let mut pkt = tx_packet(mem, 0, b"");
        pkt.set_flags(flags);
        pkt
    }

    /// The short-write path already queues the tail; this pins that it arrives whole and in order.
    #[test]
    fn a_short_write_is_delivered_whole() {
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        let (mut proxy, mut peer, payload) = proxy_with_tail(&mem);
        proxy.sendmsg(&tx_packet(&mem, 3, b"zzz"));

        let (mut got, _, _) = drain(&mut proxy, &mut peer);
        // Stop at the data: the peer is still open, so the drain ran out of rounds.
        let mut expected = payload;
        expected.extend_from_slice(b"zzz");
        got.truncate(expected.len());

        assert_eq!(got, expected);
    }

    /// SHUTDOWN follows the guest's last data packet; the tail still waiting for the socket must
    /// go out before the socket is shut down.
    #[test]
    fn shutdown_waits_for_the_pending_tail() {
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        let (mut proxy, mut peer, payload) = proxy_with_tail(&mem);

        proxy.shutdown(&shutdown_packet(&mem, uapi::VSOCK_FLAGS_SHUTDOWN_SEND));
        let (got, eof, _) = drain(&mut proxy, &mut peer);

        assert_eq!(got, payload);
        assert!(eof, "the write side must be shut down once the tail is out");
    }

    /// A release while the tail waits keeps the proxy until the tail is out, then removes it.
    #[test]
    fn release_keeps_the_proxy_until_the_tail_is_out() {
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        let (mut proxy, mut peer, payload) = proxy_with_tail(&mem);

        let update = proxy.release();
        assert!(matches!(update.remove_proxy, ProxyRemoval::Keep));
        let (got, _, last) = drain(&mut proxy, &mut peer);

        assert_eq!(got, payload);
        assert!(matches!(last.remove_proxy, ProxyRemoval::Deferred));
    }
}
