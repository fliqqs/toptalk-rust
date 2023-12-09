# toptalk-rust

A rust-ebpf program inspired by https://github.com/acooks/toptalk

This tool aims to monitor packets and generate network 'flows' with details about packets and send them to user space to be displayed.

Currently captures ip4 src and dst address but will be expanded.

Which aims to capture the same functionality but written in rust and using ebpf.

## Prerequisites

1. Install bpf-linker: `cargo install bpf-linker`

## Build eBPF

```bash
cargo xtask build-ebpf
```

To perform a release build you can use the `--release` flag.
You may also change the target architecture with the `--target` flag.

## Build Userspace

```bash
cargo build
```

## Run

```bash
RUST_LOG=info cargo xtask run
```
