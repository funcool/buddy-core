# Changelog

## Version 1.11.423

Date: 2023-06-28

- Update dependencies
- Add some improvements to codecs ns


## Version 1.11.418

Date: 2023-05-20

- Update dependencies
- Update documentation.


## Version 1.10.413

Date: 2021-01-13

- Dependencies update.
- Convert to deps+tools.build


## Version 1.10.1

Date: 2021-05-02

- Change the jvm build target to 1.8


## Version 1.10.0

Date: 2021-05-01

- Update BC to 1.68
- Update other dependencies.


## Version 1.9.0

Date: 2020-12-03

- Update dsa code (now used bouncy castle native function instead of third party dep).
- Reflection fixes.
- Update BC to 1.67


## Version 1.8.0

Date: 2020-09-15

- Add `bytes->b64` function to `buddy.core.codecs`.
- Add `bytes->b64u` function to `buddy.core.codecs`.
- Add `b64->bytes` function to `buddy.core.codecs`.
- Add `b64u->bytes` function to `buddy.core.codecs`.
- Deprecate `buddy.core.codecs.base64`.


## Version 1.7.1

Date: 2020-09-14

- Minor documentation changes.


## Version 1.7.0

Date: 2020-09-14

- Update BC to 1.66
- Update commons-codec to 1.15
- Update cheshire to 5.10.0
- Minor improvement on curve detecton on jwk (thanks to Denis Shilov).


## Version 1.6.0

Date: 2019-06-28

- Update bouncy castle to 1.62


## Version 1.5.0

Date: 2018-06-02

- Update bouncy castle to 1.59
- Add JWK reading and conversion to JCA (thanks to Denis Shilov).
- Add JWK loading and exporting support (thanks to Denis Shilov).


## Version 1.4.0

Date: 2017-08-29

- Update bouncy castle to 1.58


## Version 1.3.0

Date: 2017-08-08

- Update bouncy castle to 1.57
- Autoclose files after digest.

## Version 1.2.0

Date: 2017-01-24

- Update bouncy castle to 1.56
- Add certificates handling (thanks @ryfow).


## Version 1.1.1

Date: 2016-10-24

- Fix regression introduced in previous version.


## Version 1.1.0

Date: 2016-10-23

- Add support for zlib bytes of stream to deflate ns.
- Add support for specify the buffer size for `uncompress` function.

## Version 1.0.0

Date: 2016-08-28

- Fix wrong parameters names on `buddy.core.bytes/fill!` function
  (that can lead to unnecesary confusions). Backward compatibility is
  preserved.
- Fix warnings with clojure 1.9.x.
- Update bouncycastle to 1.55.
- Add support to read public keys from X509Certificate (thanks @tmcf).


## Version 0.13.0

Date: 2016-06-09

- Fix unexpected exception on `buddy.core.bytes/equals?` predicate
  when two zero-length arrays are compared.
- Reimplement *deflate* helpers under `buddy.util.deflate` namespace
  in order to fix unexpected exception when `uncompress` function is
  used with any input and start use safer idioms for treat internal
  streams.
- Add ripemd-128, ripemd-160, ripemd-256 and ripemd-320 hash
  functions.
- Add whirlpool hash function.


## Version 0.12.1

Date: 2016-04-08

- Unmark deprecation metadata for `sha1` and `md5` hashes (thanks
  @dottedmag).


## Version 0.12.0

Date: 2016-04-08

- Overhaul codecs api (breaking changes).
- Overhaul crypto api (breaking changes).
- Add specific base64 namespace for better and more idiomatic api.

Notes about breaking changes on crypto ns:

- `process-bytes!` is no longer alias to `process-block!` and it only
  works with aead or stream ciphers.
- `calculate-authtag!` is removed and `end!` is added in its place.
- In highlevel crypto api `:algorithm` option becomes `:alg` for
  consistency with the rest of the library.


## Version 0.11.0

Date: 2016-03-27

- Add pbkdf2 kdf (thanks to @dottedmag).


## Version 0.10.0

Date: 2016-03-26

- Add support for pkcs8 keys (thanks to @dottedmag).
- Minor fixes on codecs ns.


## Version 0.9.0

Date: 2016-01-06

- Make encrypt-cbc, decrypt-cbc, encrypt-gcm and decrypt-gcm public.
- Improve perfmance of `encrypt-*` and `split-by-blocksize` functions.
- Make available blake2b-128 and blake2b-256.
- Make some private api of mac ns as public.
- Update bouncycastle to 1.54.


## Version 0.8.2

Date: 2015-12-17

- Add the ability to build provate key from string (thanks to @dannc).


## Version 0.8.1

Date: 2015-11-15

- Add more clear exception when no passwor is provided for encrypted
  private key.


## Version 0.8.0

Date: 2015-11-08

- Fix unexpected exception on sha3-384 hasher.
- Add blake2b hash engine.
- Add skein hash engine.
- BREAKING CHANGE: the hash api has ben notably changed for improve
  consistency and usability.
- BREAKING CHANGE: unify MAC impl under one unique namespace and make
  the api more flexible.
- BREAKING CHANGE: the digital signatures algorithm api has been
  rewritten and unified under `buddy.core.dsa` ns.
- BREAKING CHANGE: the kdf api has been rewritten for to be more
  accurate and more human friendly.
- The crypto internal api is changed for consistency with mac, hash
  and dsa changes.


## Version 0.7.0

Date: 2015-09-19

- Set default clojure version to 1.7.0
- Remove slinghsot dependency. buddy.core.crypto ns now raises plain
  instances of clojure.lang.ExceptionInfo.


## Version 0.6.0

Date: 2015-06-28

- Replace `unpad!` function with `unpad` on padding namespace.  The
  removed function had wrong name and wrong implementation (instead of
  removing padding, as it name was indicating, it replaces the
  previous padding with zeropading).
- Add `pad` function to paddings namespace.
  This is a side effect free version of the `pad!`.
- Add high level interface for encrypt arbitrary length data using an
  encryption scheme. A initial supported encryption schemes are:
  - `:aes128-cbc-hmac-sha256`
  - `:aes192-cbc-hmac-sha384`
  - `:aes256-cbc-hmac-sha512`
  - `:aes128-gcm`
  - `:aes192-gcm`
  - `:aes256-gcm`


## Version 0.5.0

Date: 2015-04-02

- General code refactoring on crypto ns.
- Add support for AEAD block cipher modes.
- Add helper for split data by block size.
- Add support for deflate compression algorithm.
- Add support for AES Key Wrap algorithm.
- Add several fixes on asymetric key reading functions.
- Fix wrong behavior of bytes? predicate.
- Fix unexpected behavior of `count` function of padding algorithms.


## Version 0.4.2

Date: 2015-03-14

- Update bouncycastle version from 1.51 to 1.52


## Version 0.4.1

Date: 2015-02-26

- Remove override warnings on hash and mac related ns (thanks
  @geraldodev for report it)


## Version 0.4.0

Date: 2015-02-15

New features:

- Add buddy.core.nonce namespace with functions for generate secure
  random ivs and secure nonces.
- Add buddy.core.padding namespace with interface to common padding
  algorithms.

Changes with backward compatibility:

- Replace record usage in kdf ns with reify.
- Rename kdf protocol method names to more consistent ones.
- Add partial support for nio ByteBuffer for kdf.
- Add common protocol for mac "engine" (this allows low level clojure
  friendly access to the mac algoritm engine) and add implementations
  of that for hmac and poly1305.
- Add common protocol for hash "engine" (this like mac, allows low
  level clojure friendly access to hash algorithm engines).
- Improve naming on hmac, shmac and poly1305 namespaces using `hash`
  function instead of algorithm name for mac calculation function.
- Unify digital signature function names to: `sign` and `verify`.

Backward incompatible changes:

- Rename kdf protocol from KDFType to IKDF.
- Remove make-random-bytes function from buddy.core.keys ns.
- Improve consistency naming on hash related protocol and its method.
- Remove iv parameter on poly1305 high level abstraction (still
  available on "engine" constructor).


## Version 0.3.0

Date: 2015-01-18

- First version splitted from monolitic buddy package.
