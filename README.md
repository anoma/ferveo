![ci-badge](https://github.com/heliaxdev/ferveo/actions/workflows/build.yaml/badge.svg)

# Ferveo
A DKG protocol for front-running protection on public blockchains.

## Documentation

Documentation can be found [here](docs/).
It is recommended to use [pandoc](https://pandoc.org/) to render the docs.

## Build

A rust toolchain with version `>= 1.52.0` is required.
Installation via [rustup](https://rustup.rs/) is recommended.

Run `cargo build --release` to build.
Please note that performance may be significantly poorer when compiling in `Debug` mode.

## Testing

Run `cargo test --release` to run tests. Please note that performance may be significantly poorer when testing in `Debug` mode.

## Benchmarks

Run `cargo bench --benches` to run benchmarks.
