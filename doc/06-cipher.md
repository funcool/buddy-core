# Ciphers

Ciphers support in buddy-core is available on `buddy.core.crypto`
namespace.


## Block Ciphers

In cryptography, a block cipher is a deterministic algorithm operating
on fixed-length groups of bits, called blocks, with an unvarying
transformation that is specified by a symmetric key.

This is a table of currently supported block ciphers in buddy-core:

|Algorithm name | Keywords |
|---|---|
| AES | `:aes` |
| Twofish | `:twofish` |
| Blowfish | `:blowfish` |

Additionally, for good security, is mandatory to combine a block
cipher with some cipher mode of operation.

This is a table of currently supported of cipher mode of operation:

|Algorithm name | Keywords |
|---|---|
| SIC (CTR) | `:ctr`, `:sic` |
| CBC | `:cbc` |
| OFB | `:ofb` |
| GCM | `:gcm` |

**NOTE**: currently buddy comes with limited number of ciphers and
modes, but in near future more many more options should be added.

Example encrypt:

```clojure
(require '[buddy.core.crypto :as crypto])
(require '[buddy.core.nonce :as nonce])
(require '[buddy.core.codecs :as codecs])

(let [eng   (crypto/block-cipher :twofish :cbc)
      iv16  (nonce/random-nonce 16)
      key32 (nonce/random-nonce 32)
      data  (codecs/hex->bytes "000000000000000000000000000000AA")]
  (crypto/init! eng {:key key32 :iv iv16 :op :encrypt})
  (crypto/process-block! eng data))

;; => #<byte[] [B@efadff9>
```

AEAD mode of operations also exposes additional function for caluclate
the total size of the output including the authentication tag:
`output-size`.


## Stream Ciphers

Stream ciphers differ from block ciphers, in that they works with
arbitrary length input and do not require any additional mode of
operation.

This is a table of currently supported of stream ciphers in buddy:

|Algorithm name | Keywords |
|---|---|
| ChaCha | `:chacha` |


Example encrypt:

```clojure
(require '[buddy.core.crypto :as crypto])
(require '[buddy.core.codecs :as codecs])
(require '[buddy.core.nonce :as nonce])

(let [eng   (crypto/stream-cipher :chacha)
      iv8   (nonce/random-nonce 8)
      key32 (nonce/random-nonce 32)
      data  (codecs/hex->bytes "0011")]
  (crypto/init! eng {:key key32 :iv iv8 :op :encrypt})
  (crypto/process-bytes! eng data))

;; => #<byte[] [B@efadff9>
```

**NOTE:** the iv and key size depends estrictly on cipher engine, in
this case, chacha engine requires 8 bytes iv.

**NOTE:** for decrypt, only change `:op` value to `:decrypt`

**NOTE:** You can call `crypto/initialize!` any times as you want, it
simply reinitializes the engine.


## High level encryption schemes

Since version 0.6.0, _buddy-core_ comes with high level crypto interface that allows user
encrypt arbitrary length data using one of the well established encryption schemes.

The api consists in two simple functions. Let see an example of how to encrypt arbitrary
length text and decrypt it:

```clojure
(require '[buddy.core.crypto :as crypto])
(require '[buddy.core.codecs :as codecs])
(require '[buddy.core.nonce :as nonce])
(require '[buddy.core.hash :as hash])

(def original-text
  (codecs/to-bytes "Hello World."))

(def iv (nonce/random-bytes 16))   ;; 16 bytes random iv
(def key (hash/sha256 "mysecret")) ;; 32 bytes key

;; Encrypt the original-text content using previously
;; declared iv and key.
(def encrypted (crypto/encrypt original-text key iv
                               {:alg :aes128-cbc-hmac-sha256}))

;; And now, decrypt it using the same parameters:
(-> (crypto/decrypt encrypted key iv {:alg :aes128-cbc-hmac-sha256})
    (codecs/bytes->str))
;; => "Hello World."
```

This is a complete list of supported encryption schemes:

* `:aes128-cbc-hmac-sha256` (default)
* `:aes192-cbc-hmac-sha384`
* `:aes256-cbc-hmac-sha512`
* `:aes128-gcm`
* `:aes192-gcm`
* `:aes256-gcm`

