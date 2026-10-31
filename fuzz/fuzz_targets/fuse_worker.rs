#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| msb_krun_devices::fuse_worker(data));
