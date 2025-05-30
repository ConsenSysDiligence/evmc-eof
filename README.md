# EVMC

[![chat: on gitter][gitter badge]][Gitter]
[![readme style: standard][readme style standard badge]][standard readme]

> Ethereum Client-VM Connector API

The EVMC is the low-level ABI between Ethereum Virtual Machines (EVMs) and
Ethereum Clients. On the EVM side it supports classic EVM1 and [ewasm].
On the Client-side it defines the interface for EVM implementations
to access Ethereum environment and state.


## Usage

### Build
1. run `cmake . -DCMAKE_BUILD_TYPE=Release -DCMAKE_TOOLCHAIN_FILE=../cmake/cable/toolchains/cxx17.cmake -DCMAKE_COMPILE_WARNING_AS_ERROR=TRUE -DHUNTER_ENABLED=ON -B build`
2. run `cmake --build build -- -j4`

### Usage
1. Download evmone vm from [Releases](https://github.com/ethereum/evmone/releases) or compile one for yourself.
2. compile smart contract in eof format
3. run evmc `build/bin/evmc run --vm <libevmone.so path> --rev 14 "<bytecode or path starting with @>" --create --input "<ABI Encoded call>" --storage-dump-file "<path to file with storage dump>" --logs-dump-file "<path to file with logs dump>"`
4. Running command above will get you storage and logs dump in paths you specified.

### Documentation

Please visit the [documentation].

### Languages support

| Language                      | Supported Versions   | Supported Compilers          | Feature Support   |
|-------------------------------|----------------------|------------------------------|-------------------|
| **C**                         | C99, C11             | GCC 8+, clang 9+, MSVC 2017+ | Host- and VM-side |
| **C++**                       | C++17                | GCC 8+, clang 9+, MSVC 2017+ | Host- and VM-side |
| **Go** _(bindings)_           | 1.11+ (with modules) |                              | Host-side only    |
| **Rust** _(bindings)_[¹](#n1) | 2018 edition         | 1.47.0 and newer             | VM-side only      |
| **Java** _(bindings)_[²](#n2) | 11                   |                              | Host-side only    |

1. <sup id="n1">↑</sup> Rust support is limited and not complete yet, but it is mostly functional already. Breaking changes are possible at this stage.
2. <sup id="n2">↑</sup> Java support is in progress and the interface remains in flux. Breaking changes are possible at this stage.

### Testing tools

* **evmc run** ([tools/evmc]) — executes bytecode in any EVMC-compatible VM implementation.
* **evmc-vmtester** ([tools/vmtester]) — can test any EVM implementation for compatibility with EVMC.


## Related projects

### EVMs

- [aleth-interpreter]
- [Daytona]
- [eip1962-evmc] (EIP-2003 style precompile)
- [evmjit]
- [evmone]
- [Hera]
- [Hera.rs]
- [ssvm-evmc]

### Clients

- [aleth]
- [core-geth] (in progress)
- [erigon] (with silkworm)
- [evmc-js]
- [go-ethereum] (in progress)
- [nim-evmc]
- [phant] (in progress)
- [pyevm] (in progress)
- [pyethereum] (abandoned)
- [rust-ssvm] (Rust Host-side)
- [silkworm]
- [Solidity] (for integration testing)

## Maintainers

- Alex Beregszaszi [@axic]
- Paweł Bylica [@chfast]

See also the list of [EVMC Authors](AUTHORS.md).

## Contributing

[![chat: on gitter][gitter badge]][Gitter]

Talk with us on the [EVMC Gitter chat][Gitter].

## License

[![license badge]][Apache License, Version 2.0]

Licensed under the [Apache License, Version 2.0].

## Internal

### Making new release

1. Update [CHANGELOG.md](CHANGELOG.md), put the release date, update release link.
2. `git add CHANGELOG.md`.
3. Tag new release: `bumpversion --allow-dirty prerel`.
4. Prepare CHANGELOG for next release: add unreleased section and link.
5. `git add CHANGELOG.md`.
6. Start new release series: `bumpversion --allow-dirty --no-tag minor`.


[@axic]: https://github.com/axic
[@chfast]: https://github.com/chfast
[Apache License, Version 2.0]: LICENSE
[documentation]: https://ethereum.github.io/evmc
[ewasm]: https://github.com/ewasm/design
[evmjit]: https://github.com/ethereum/evmjit
[evmone]: https://github.com/ethereum/evmone
[Hera]: https://github.com/ewasm/hera
[Hera.rs]: https://github.com/ewasm/hera.rs
[Daytona]: https://github.com/axic/daytona
[eip1962-evmc]: https://github.com/axic/eip1962-evmc
[erigon]: https://github.com/erigontech/erigon
[ssvm-evmc]: https://github.com/second-state/ssvm-evmc
[Gitter]: https://gitter.im/ethereum/evmc
[aleth-interpreter]: https://github.com/ethereum/aleth/tree/master/libaleth-interpreter
[aleth]: https://github.com/ethereum/aleth
[Solidity]: https://github.com/ethereum/solidity
[nim-evmc]: https://github.com/status-im/nim-evmc
[go-ethereum]: https://github.com/ethereum/go-ethereum/pull/17954
[phant]: https://github.com/jsign/phant
[pyevm]: https://github.com/ethereum/py-evm
[pyethereum]: https://github.com/ethereum/pyethereum/pull/406
[silkworm]: https://github.com/erigontech/silkworm
[core-geth]: https://github.com/etclabscore/core-geth/issues/55
[evmc-js]: https://github.com/RainBlock/evmc-js
[rust-ssvm]: https://github.com/second-state/rust-ssvm
[standard readme]: https://github.com/RichardLitt/standard-readme
[tools/evmc]: https://github.com/ethereum/evmc/tree/master/tools/evmc
[tools/vmtester]: https://github.com/ethereum/evmc/tree/master/tools/vmtester

[gitter badge]: https://img.shields.io/gitter/room/ethereum/evmc.svg
[license badge]: https://img.shields.io/github/license/ethereum/evmc.svg?logo=apache
[readme style standard badge]: https://img.shields.io/badge/readme%20style-standard-brightgreen.svg
