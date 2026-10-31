// SPDX-License-Identifier: Apache-2.0
//! Replays every input under `fuzz/corpus/<target>/` through the fuzz entry points on stable, so
//! a fixed finding stays fixed without a nightly toolchain (`cargo test --features fuzzing`).

use std::fs;
use std::path::PathBuf;

fn replay(target: &str, run: fn(&[u8])) {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fuzz/corpus")
        .join(target);
    let mut names: Vec<_> = fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("corpus {}: {e}", dir.display()))
        .map(|entry| entry.expect("corpus entry").path())
        .collect();
    names.sort();
    assert!(names.len() >= 10, "{target}: the seed corpus is missing");
    for path in names {
        let bytes = fs::read(&path).expect("read corpus input");
        run(&bytes);
    }
}

#[test]
fn virtqueue_chain_corpus() {
    replay("virtqueue_chain", msb_krun_devices::virtqueue_chain);
}

#[test]
fn balloon_queues_corpus() {
    replay("balloon_queues", msb_krun_devices::balloon_queues);
}

#[test]
fn vsock_packets_corpus() {
    replay("vsock_packets", msb_krun_devices::vsock_packets);
}

#[cfg(target_os = "linux")]
#[test]
fn fuse_requests_corpus() {
    replay("fuse_requests", msb_krun_devices::fuse_requests);
}
