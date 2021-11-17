# Orca: Blocklisting in Sender-Anonymous Messaging

_Rust implementation of the Orca sender blocklisting protocol_

**USENIX Security 2022:**
Nirvan Tyagi, Julia Len, Ian Miers, Thomas Ristenpart. _Orca: Blocklisting in Sender-Anonymous Messaging_. USENIX Security 2022.

## Overview

This repository is organized as a Rust package including three main source files and two benchmarks.
* [`src/algmac.rs`](src/algmac.rs): Implementation of the GGM algebraic MAC from [[CMZ CCS'14]](https://eprint.iacr.org/2013/516).
* [`src/groupsig.rs`](src/groupsig.rs): Implementation of the core group signature from Orca.
* [`src/token.rs`](src/token.rs): Implementation of the one-time-use anonymous token extension from Orca.
* [`benches/microbenchmarks.rs`](benches/microbenchmarks.rs): Microbenchmarks for the cryptographic operations of Orca.
* [`benches/platform.rs`](benches/platform.rs): Multi-threaded platform macrobenchmark for running Orca.

## Prerequisites
You will need a machine running Ubuntu. If using AWS EC2, we suggest using Ubuntu Server LTS 20.04 on a t2.micro. **Important**: You will need about 12GB of storage capacity on your machine. If you are creating an EC2 instance, you will need to increase the volume from the default size.

## Installation/Build

The library is easy to compile from source using an older version of the `nightly` toolchain of the Rust compiler.
Install the Rust toolchain manager `rustup` by following the instructions [here](https://rustup.rs/). **Note**: Do not install using `apt install cargo`.

If you run into compilation errors for `libc`, then you can run the following:
```
sudo apt-get update
sudo apt install build-essential
```

Clone the repository:
```bash
git clone https://github.com/nirvantyagi/orca.git
cd orca/
```

Build using `cargo`:
```bash
cargo build
```

## Tests and Benchmarks

The `orca` library comes with a suite of tests along with two benchmarks.

To run the tests:
```bash
cargo test
```

### Microbenchmarks

The first benchmark binary measures the running time of core cryptographic algorithms of Orca.
It is run as follows and produces the results reported in Figure 5 of [TLMR USENIX Sec'22]:
```bash
cargo bench --bench microbenchmarks
```
Part of the reported results in Figure 5 involved running the above microbenchmark on an Android mobile device, for which some additional setup is required.
First ensure that the mobile device has USB debugging connected (instructions found [here](https://developer.android.com/studio/debug/dev-options#enable)).
Connect it to the computer used to run the experiment and run
```bash
adb devices
```
to ensure it is connected. Then install the cargo extension that enables building a Rust codebase for Android as well as the toolchains to be used:
```bash
cargo install cargo-ndk
rustup target add \
    aarch64-linux-android \
    armv7-linux-androideabi \
    x86_64-linux-android \
    i686-linux-android
```
Download Android NDK version r22b [here](https://github.com/android/ndk/wiki/Unsupported-Downloads) and then set the following environment variable:
```bash
export ANDROID_NDK_HOME="/location/of/android-ndk"
```
Then build the microbenchmarks codebase with the following:
```bash
cargo ndk --platform 21 --target armv7-linux-androideabi  build --bench microbenchmarks --release
```

The resulting executable should be called `microbenchmarks-HASH`, where `HASH` is some hash value. It should be located in the directory `orca/target/armv7-linux-androideabi/release/deps`. Check to make sure it is there and then push the executable to the Android device in directory `/data/local/tmp/mb`:
```bash
adb -d push /location/of/executable /data/local/tmp/mb
```
Lastly, run the executable:
```bash
adb -d shell /data/local/tmp/mb
```

### Platform Throughput Benchmark

The second benchmark binary measures the platform throughput of handling token mint requests and message send requests over differing levels of hardware parallelism.
In this benchmark, the platform stores the strikelist in an in-memory Redis store.
To run the benchmark, you must first have a Redis server running and listening on port 6379 (default configuration).
Redis can be installed following the instructions [here](https://redis.io/topics/quickstart), and a default server can be spun up by running the command ``redis-server``.
(Note: if running on an AWS EC2 instance, Redis may already by installed by default and a server may be listening on port 6379.)
```bash
cargo bench --bench platform -- <num_cores> <num_requests> <size_blacklist> <size_strikelist> <num_users>
```

To reproduce Figure 6 in [TLMR USENIX Sec'22], the benchmark was run with 200 requests for a blacklist size of 100, a strikelist size of 1400, and one million users, while varying the number of cores.
Note that these parameters require a system with memory of at least 64 GB.
One can reduce the number of users to get comparable benchmark times without incurring large in-memory costs.
