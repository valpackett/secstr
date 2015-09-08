# secstr [![unlicense](https://img.shields.io/badge/un-license-green.svg?style=flat)](http://unlicense.org)

A [Rust] library that implements a data type suitable for storing sensitive information such as passwords and private keys in memory.
Inspired by Haskell [securemem] and .NET [SecureString].

[Rust]: http://www.rust-lang.org
[securemem]: https://hackage.haskell.org/package/securemem
[SecureString]: http://msdn.microsoft.com/en-us/library/system.security.securestring%28v=vs.110%29.aspx

## Usage

```rust
extern crate secstr;
use secstr::*;

let pw1 = SecStr::new("correct horse battery staple".to_string());
let pw2 = SecStr::new_from_slice("correct horse battery staple");

// Compared in constant time:
// (Obviously, you should store hashes in real apps, not plaintext passwords)
let are_pws_equal = pw1 == pw2; // true

// With normal strings:
let are_pws_equal_2 = pw1.equiv(&"correct horse battery staple".to_string());

// Formatting, printing
let text_to_print = format!("{}", SecStr::new_from_slice("hello")); // ***SECRET***

// Clearing memory
// THIS IS DONE AUTOMATICALLY IN THE DESTRUCTOR
let mut my_sec = SecStr::new_from_slice("hello");
my_sec.zero_out();
assert_eq!(my_sec.content, "\x00\x00\x00\x00\x00".to_string());
```

## Contributing

Please feel free to submit pull requests!
Bugfixes and simple non-breaking improvements will be accepted without any questions :-)

By participating in this project you agree to follow the [Contributor Code of Conduct](http://contributor-covenant.org/version/1/2/0/).

[The list of contributors is available on GitHub](https://github.com/myfreeweb/secstr/graphs/contributors).

## License

This is free and unencumbered software released into the public domain.  
For more information, please refer to the `UNLICENSE` file or [unlicense.org](http://unlicense.org).
