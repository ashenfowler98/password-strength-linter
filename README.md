# passlint

A command-line linter for password lists. Give it a file with one password
per line (or pipe one in), and it reports which lines fail basic strength
rules — too short, missing a character class, a known-common password, a
repeated or sequential run of characters.

## Why

I keep ending up with files of candidate passwords to sanity-check before
they go anywhere real: default credentials for a batch of devices, a set of
generated passphrases, an export I'm about to import into a password manager.
Eyeballing a few hundred lines by hand misses things. `passlint` is the check
I run first.

It deliberately never prints the password back — only the line number,
severity, and which rule fired. The point of a linter for passwords is to
stop them showing up somewhere they shouldn't; echoing them into your
terminal scrollback or a CI log would defeat that.

## Usage

Build it:

```
cargo build --release
```

Run it against a file:

```
$ ./target/release/passlint passwords.txt
2: [warn] too short (7 < 12 characters)
2: [warn] missing an uppercase letter
2: [info] missing a symbol
5: [warn] matches a well-known common password
9: [warn] contains a repeated character run ('a' x4)
14: [warn] contains a sequential run (e.g. "abcd" or "4321")
```

Or pipe input in:

```
$ printf 'Tr0ub4dor&3\nqwerty\n' | ./target/release/passlint
2: [warn] too short (6 < 12 characters)
2: [warn] missing an uppercase letter
2: [warn] missing a digit
2: [warn] missing a symbol
2: [warn] matches a well-known common password
```

Exit status is `1` if any line produced a finding, `0` if every password
passed, `2` on an I/O error.

## Design note: streaming

Password lists can be large — a breach corpus or a bulk export can run into
the gigabytes — so `passlint` never reads the whole input into memory. It
uses `BufRead::read_line` with a single reusable `String` buffer, checks one
line, clears the buffer, and moves to the next. Memory use stays flat no
matter how many lines the file has.

## Rules so far

- minimum length (12 characters)
- character class coverage: lowercase, uppercase, digit, symbol
- membership in a small built-in list of common passwords
- repeated-character runs (`aaaa`)
- sequential runs, ascending or descending (`abcd`, `4321`)

## License

MIT, see LICENSE.
