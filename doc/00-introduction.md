# Introduction

A cryptographic api for Clojure.

This library includes:

- cryptographic hash algorithms (digest)
- key derivation algorithms (kdf)
- digital signatures
- message authentication (mac)
- block ciphers
- stream ciphers
- padding schemes
- nonces and salts
- X.509 certificates
- ...


## Project Maturity

Since _buddy-core_ is a young project there can be some API breakage.


## Install

The simplest way to use _buddy-core_ in a clojure project, is by including it in the
dependency vector on your *_project.clj_* file:

```clojure
[buddy/buddy-core "1.10.413"]
```

Or deps.edn:

```clojure
buddy/buddy-core {:mvn/version "1.10.413"}
```

And is tested under JDK >= 8.


## Source Code

_buddy-core_ is open source and can be found on [github](https://github.com/funcool/buddy-core).

You can clone the public repository with this command:

```bash
git clone https://github.com/funcool/buddy-core
```

## Run tests

For running tests just execute this:

```bash
clojure -X:dev:test
```

## License

_buddy-core_ is licensed under Apache 2.0 License. You can see the
complete text of the license on the root of the repository on
`LICENSE` file.



