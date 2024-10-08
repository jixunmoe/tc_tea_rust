# tc_tea

Rusty implementation of _Tencent modified TEA_ (tc_tea).

Test data generated using its C++ implementation: [tc_tea.cpp][tc_tea_cpp] (BSD-3-Clause).

Code implemented according to the spec described in
[iweizime/StepChanger:腾讯 TEA 加密算法][tc_tea_spec].

## Features

* `random` (default: `on`): Enable RNG when generating padding bytes for tc_tea.
* `random_secure` (default: `on`): Use a _secure_ RNG when generating padding bytes for tc_tea.

If you don't expect to encrypt anything, you can specify `default-features = false` to drop RNG support.
In this case, it will use a [pre-generated deterministic salt](https://xkcd.com/221/).

## Install

Add the following to `[dependencies]` section in your `Cargo.toml` file:

```toml
tc_tea = "0.2"
```

## Usage

```rust
use tc_tea;

fn hello_tc_tea() {
    let key = b"12345678ABCDEFGH";
    let encrypted = tc_tea::encrypt(&"hello", &key).unwrap();
    let decrypted = tc_tea::decrypt(&encrypted, &key).unwrap();
    assert_eq!("hello", std::str::from_utf8(&decrypted).unwrap());
}
```

## License

Dual licensed under MIT OR Apache-2.0 license.

```license
SPDX-License-Identifier: MIT OR Apache-2.0
```

[tc_tea_cpp]: https://github.com/TarsCloud/TarsCpp/blob/a6d5ed8/util/src/tc_tea.cpp

[tc_tea_spec]: https://github.com/iweizime/StepChanger/wiki/%E8%85%BE%E8%AE%AFTEA%E5%8A%A0%E5%AF%86%E7%AE%97%E6%B3%95
