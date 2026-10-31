// SPDX-License-Identifier: Apache-2.0
//! Fuzz entry point for the FUSE request dispatcher (feature `fuzzing`, Linux).

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::AtomicI32;
use std::sync::Arc;

use vm_memory::{Bytes, GuestAddress};

use super::fuse::{InHeader, InitInCompat, Opcode};
use super::passthrough::{Config, PassthroughFs};
use super::server::Server;
use crate::virtio::descriptor_utils::{Reader, Writer};
use crate::virtio::fuzzing::{le16, take};
use crate::virtio::{Descriptor, DescriptorChain};

const REQUEST_AT: u64 = 0x1000;
const REPLY_AT: u64 = 0x2_0000;
const MEMORY: usize = 0x4_0000;

/// Caps what a guest-driven fuzz run may write on the host: a file can grow to 8 MiB, and a
/// write past that fails with EFBIG instead of killing the process or filling the disk.
fn limit_host_writes() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let limit = libc::rlimit {
            rlim_cur: 8 << 20,
            rlim_max: 8 << 20,
        };
        // SAFETY: plain libc calls with valid arguments, made once before any request runs.
        unsafe {
            libc::signal(libc::SIGXFSZ, libc::SIG_IGN);
            libc::setrlimit(libc::RLIMIT_FSIZE, &limit);
        }
    });
}

/// A small tree to serve, unique to one run and removed at its end.
struct Tree(PathBuf);

impl Tree {
    fn new() -> Self {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let base = std::env::var_os("FUZZ_FUSE_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let root = base.join(format!("krun-fuse-fuzz-{}-{n}", std::process::id()));
        fs::create_dir_all(root.join("dir/sub")).expect("create the served tree");
        fs::write(root.join("file"), b"hello fuzz").expect("seed file");
        fs::write(root.join("dir/inner"), b"inner").expect("seed file");
        let _ = std::os::unix::fs::symlink("file", root.join("link"));
        let _ = std::os::unix::fs::symlink("../../outside", root.join("dir/sub/escape"));
        Tree(root)
    }
}

impl Drop for Tree {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn dispatch(
    server: &Server<PassthroughFs>,
    mem: &vm_memory::GuestMemoryMmap,
    request: &[u8],
    reply_len: u32,
) {
    let n = request.len().min(REPLY_AT as usize - REQUEST_AT as usize);
    let _ = mem.write_slice(&request[..n], GuestAddress(REQUEST_AT));
    let descs = [
        Descriptor {
            addr: REQUEST_AT,
            len: n as u32,
            flags: 1,
            next: 1,
        },
        Descriptor {
            addr: REPLY_AT,
            len: reply_len,
            flags: 2,
            next: 0,
        },
    ];
    for (i, d) in descs.iter().enumerate() {
        let _ = mem.write_obj(*d, GuestAddress(16 * i as u64));
    }
    let Some(chain) = DescriptorChain::checked_new(mem, GuestAddress(0), 8, 0) else {
        return;
    };
    let (Ok(r), Ok(w)) = (Reader::new(mem, chain.clone()), Writer::new(mem, chain)) else {
        return;
    };
    let _ = server.handle_message(r, w, &None, &Arc::new(AtomicI32::new(0)));
}

/// FUSE requests as the guest kernel's driver queues them, served by the Linux passthrough
/// backend over a fresh small tree.
///
/// Input: records of a 16-bit request length, the request (an `InHeader` and its body) and a
/// 16-bit reply buffer size. A FUSE_INIT is sent first so the session is up.
pub fn fuse_requests(data: &[u8]) {
    limit_host_writes();
    let tree = Tree::new();
    let cfg = Config {
        root_dir: tree.0.to_string_lossy().into_owned(),
        ..Config::default()
    };
    let fs = PassthroughFs::new(cfg).expect("passthrough over the served tree");
    let server = Server::new(Arc::new(fs), 0);
    let mem = vm_memory::GuestMemoryMmap::from_ranges(&[(GuestAddress(0), MEMORY)])
        .expect("anonymous region");

    let init_body = InitInCompat {
        major: 7,
        minor: 38,
        max_readahead: 0x20000,
        flags: 0,
    };
    let header = InHeader {
        len: (std::mem::size_of::<InHeader>() + std::mem::size_of::<InitInCompat>()) as u32,
        opcode: Opcode::Init as u32,
        unique: 1,
        ..Default::default()
    };
    let mut init = vm_memory::ByteValued::as_slice(&header).to_vec();
    init.extend_from_slice(vm_memory::ByteValued::as_slice(&init_body));
    dispatch(&server, &mem, &init, 0x1000);

    let mut data = data;
    for _ in 0..32 {
        let Some(len) = take(&mut data, 2).map(le16) else {
            return;
        };
        let n = usize::from(len).min(data.len()).min(0x8000);
        let Some(request) = take(&mut data, n) else {
            return;
        };
        let reply = take(&mut data, 2).map(le16).unwrap_or(0x1000);
        dispatch(&server, &mem, request, u32::from(reply).min(0x1_0000));
    }
}
