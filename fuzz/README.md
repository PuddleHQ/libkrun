# Fuzz targets

cargo-fuzz targets for what a guest reaches through the virtio devices of `msb_krun_devices`.
They need a nightly toolchain, so this crate is outside the workspace. Each target calls an
entry point of the crate's `fuzzing` feature, which builds guest memory and a queue the way a
driver would and runs the device's own handler.

| Target | What it feeds |
|---|---|
| `virtqueue_chain` | descriptor tables and available rings: `Queue::is_valid`, `pop`, `DescriptorChain`, `Reader`, `Writer`, `add_used` |
| `vsock_packets` | guest packets (header, payload, chain shape) into the muxer's stream and datagram paths and its RX side |
| `balloon_queues` | all five balloon queues: free page reports, stats buffers, kicks on the unused queues |
| `fuse_requests` | FUSE requests into the dispatcher over the Linux passthrough backend on a small tree |
| `fuse_worker` | the FUSE worker over a guest-laid-out queue (ring memory and request memory), one kick; fails if the worker panics or does not return within 10 s |
| `vsock_tsi` | the TSI request parsers over one buffer that ends at an inaccessible page (the muxer's TSI handlers open host sockets, so the target stops at the parsers) |

Seed inputs under `corpus/<target>/` are made by `gen_seeds.py` and checked in; each name says
what the input is. `src/devices/tests/fuzz_corpus.rs` replays every file on stable:

```sh
cargo test --locked -p msb_krun_devices --features fuzzing --test fuzz_corpus
```

## Running

```sh
cargo install cargo-fuzz --locked
rustup toolchain install nightly --profile minimal
cd fuzz
cargo +nightly fuzz run --target x86_64-unknown-linux-gnu virtqueue_chain -- \
    -max_total_time=600 -max_len=16384 -rss_limit_mb=2048
```

`--target x86_64-unknown-linux-gnu` is needed with the prebuilt cargo-fuzz, which defaults to
the musl target. Run one job at a time. On a small machine also cap virtual memory with
`ulimit -v 8000000` and add `-s none`: the address sanitizer reserves terabytes of address
space and fails under that limit. `fuse_requests` serves a throw-away tree under
`$FUZZ_FUSE_ROOT` (default: the temp dir) and caps file sizes at 8 MiB for the process.

libFuzzer adds new inputs to the first corpus folder it is given, so run with a scratch folder
first (`... run virtqueue_chain /scratch/work corpus/virtqueue_chain`) to keep the seeds clean.

## Nightly run

`.github/workflows/fuzz.yml` runs each target for ten minutes every night and on demand, the
same shape as the other fuzz workflow of this project. It gates nothing. A crash fails the run
and uploads the input; the fix is the finding's regression test: copy the input from
`fuzz/artifacts/<target>/` into `corpus/<target>/` as `crash-<what>` and the stable replay test
keeps it fixed. This fork has GitHub Actions disabled at the time of writing (a dispatch answers
HTTP 422), so the workflow runs only after someone re-enables them in the repository settings.
Until then run the targets by hand as above.

## Findings

- `fuse_requests`: a guest read of the virtual init file at or past its end underflowed in the
  Linux passthrough backend (`init-inode-read-past-end`); fixed.
- `fuse_worker`: the worker unwrapped `Reader::new`, `Writer::new` and the notification calls, so
  a descriptor outside guest memory panicked its thread; and a head `pop` refused (an index past
  the queue size) made it spin forever, because `pop` leaves such a head in place. Both fixed
  (`avail-head-refused-by-pop`, `avail-idx-far-ahead-of-queue`, the `*-in-hole` seeds). The
  notification-call unwraps cannot fail on a validated ring; they are changed by reading.
- `vsock_tsi`: the parsers indexed past short requests, trusted a guest `addr_len` and read a
  path without a NUL past the buffer; fixed (`connect-four-bytes`, `unix-path-no-nul` and the
  others named for the case). TSI is off unless the VMM enables it.
- `get_extensions` split a FUSE extension longer than its request body. Linux backends never
  negotiate the security context, so no target reaches it; a unit test in `fs/server.rs` pins it.
