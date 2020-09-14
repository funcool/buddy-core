# MAC algorithms

Buddy comes with three mac implementations: *hmac*, *shmac* and *poly1305*; and
all them are located under `buddy.core.mac` namespace.

## HMac

Is a specific construction for calculating a message authentication code (MAC)
involving a cryptographic hash function in combination with a secret cryptographic
key.

Any cryptographic hash function, such as MD5 or SHA-1, may be used in the
calculation of an HMAC; the resulting MAC algorithm is termed HMAC-MD5 or
HMAC-SHA1 accordingly. The cryptographic strength of the HMAC depends upon
the cryptographic strength of the underlying hash function, the size of its
hash output, and on the size and quality of the key.

Example generate a hmac from plain string using sha256 digest


```clojure
;; Import required namespaces
(require '[buddy.core.mac :as mac])
(require '[buddy.core.codecs :as codecs])

;; Generate sha256 hmac over string
(-> (mac/hash "foo bar" {:key "mysecretkey" :alg :hmac+sha256})
    (codecs/bytes->hex))
;; => "61849448bdbb67b39d609471eead667e65b0d1b9e01b1c3bf7aa56b83e9c8083"
```

Example verifying a hmac


```clojure
(mac/verify "foo bar" (codecs/hex->bytes "61849448bdbb67b...")
            {:key "mysecretkey" :alg :hmac+sha256})
;; => true
```

The key parameter can be any type that implements the *ByteArray*
protocol defined in the `buddy.core.codecs` namespace. It comes with
default implementations for `byte[]` and `java.lang.String` and `nil`.


## Poly1305

Poly1305 is a cryptographic message authentication code (MAC) written
by Daniel J. Bernstein. It can be used to verify the data integrity
and the authenticity of a message.

The security of Poly1305 is very close to the block cipher
algorithm. As a result, the only way for an attacker to break Poly1305
is to break the cipher.

Poly1305 offers cipher replaceability. If anything goes wrong with
one, it can be substituted by another with identical security
guarantees.

Unlike *hmac*, it requires an initialization vector (IV). An IV is
like a salt.  It should be generated using a strong random number
generator for security guarantees. Also, the IV should be of the same
length as the chosen cipher block size.

Example using poly1305 mac algorithm for generate mac from string:

```clojure
(require '[buddy.core.codecs :as codecs])
(require '[buddy.core.mac :as mac])
(require '[buddy.core.nonce :as nonce])

(def key (nonce/random-bytes 32))
(def iv (nonce/random-bytes 32))

(-> (mac/hash "some-data" {:key key :iv iv :alg :poly1305+aes})
    (codecs/bytes->hex))
;; => "1976b1c490c306e7304a59dfacee4207"
```

The default specification talks about AES as default block cipher but the algorith
in fact can work other block ciphers without any problem. So you can use `serpent`
and twofish among the default aes:

```clojure
(-> (mac/hash "some-data" {:key key :iv iv :alg :poly1305+twofish})
    (codecs/bytes->hex))
;; => "6e7304a59dfacee42071976b1c490c30"
```

## Advanced Usage

### Generate mac for file like objects

Like with hash functions, you can use String, byte[], *File*, *URL*, *URI* and
*InputStream* as input value for mac functions:

Example generating hmac from input stream:

```clojure
(require '[clojure.java.io :as io])

;; Generate hmac for file
(-> (io/input-stream "/tmp/somefile")
    (mac/hash {:key "mysecretkey" :alg :hmac-sha256})
    (codecs/bytes->hex))
;; => "4cb793e600848da205323800..."
```

### Low-Level Api

Behind the scenes of the high level api, a low level api is already
defined with protocols and you can use it for your purposes:


```clojure
(let [engine (mac/-engine {:alg :hnac+sha256})]
  (mac/-update engine (codecs/str->bytes "hello") 0 5)
  (codecs/bytes->hex (mac/-end engine)))
;; "924c4b82a56c0115eb9..."
```

This also applies to the rest of mac implementations found in
*buddy-core* library.

