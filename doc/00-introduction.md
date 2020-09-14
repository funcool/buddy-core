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
[buddy/buddy-core "1.7.1"]
```

Or deps.edn: 

```clojure
buddy/buddy-core {:mvn/version "1.7.1"}
```

And is tested under JDK>=8.


