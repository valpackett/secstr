[![crates.io](https://img.shields.io/crates/v/secstr.svg)](https://crates.io/crates/secstr)
[![API Docs](https://docs.rs/secstr/badge.svg)](https://docs.rs/secstr/)
[![Build Status](https://img.shields.io/travis/myfreeweb/secstr.svg?style=flat)](https://travis-ci.org/myfreeweb/secstr)
[![unlicense](https://img.shields.io/badge/un-license-green.svg?style=flat)](http://unlicense.org)

# secstr

A [Rust] library that implements a data type (wrapper around `Vec<u8>`) suitable for storing sensitive information such as passwords and private keys in memory.
Inspired by Haskell [securemem] and .NET [SecureString].

Featuring:

- constant time comparison (does not short circuit on the first different character; but terminates instantly if strings have different length)
- automatically zeroing out in the destructor
- `mlock` and `madvise` protection if possible
- formatting as `***SECRET***` to prevent leaking into logs
- (optionally) using libsodium (through [sodiumoxide]'s [libsodium-sys]) for zeroing, comparison, and hashing (`std::hash::Hash`)
- (optionally) de/serializable into anything [Serde] supports as a byte string
- (optionally) compile-time checked [preconditions] for the public `unsafe` API

[Rust]: https://www.rust-lang.org
[securemem]: https://hackage.haskell.org/package/securemem
[SecureString]: http://msdn.microsoft.com/en-us/library/system.security.securestring%28v=vs.110%29.aspx
[sodiumoxide]: https://crates.io/crates/sodiumoxide
[libsodium-sys]: https://crates.io/crates/libsodium-sys
[Serde]: https://serde.rs/
[preconditions]: https://crates.io/crates/pre

## Usage

```rust
extern crate secstr;
use secstr::*;

let pw = SecStr::from("correct horse battery staple");

// Compared in constant time:
// (Obviously, you should store hashes in real apps, not plaintext passwords)
let are_pws_equal = pw == SecStr::from("correct horse battery staple".to_string()); // true

// Formatting, printing without leaking secrets into logs
let text_to_print = format!("{}", SecStr::from("hello")); // "***SECRET***"

// Clearing memory
// THIS IS DONE AUTOMATICALLY IN THE DESTRUCTOR
// (but you can force it)
let mut my_sec = SecStr::from("hello");
my_sec.zero_out();
assert_eq!(my_sec.unsecure(), b"\x00\x00\x00\x00\x00");
```

Be careful with `SecStr::from`: if you have a borrowed string, it will be copied.  
Use `SecStr::new` if you have a `Vec<u8>`.

## Contributing

Please feel free to submit pull requests!

By participating in this project you agree to follow the [Contributor Code of Conduct](http://contributor-covenant.org/version/1/4/) and to release your contributions under the Unlicense.

[The list of contributors is available on GitHub](https://github.com/myfreeweb/secstr/graphs/contributors).

## License

This is free and unencumbered software released into the public domain.  
For more information, please refer to the `UNLICENSE` file or [unlicense.org](http://unlicense.org).
