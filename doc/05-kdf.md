# Key Derivation Functions (KDF)

Key derivation functions are often used in conjunction with non-secret
parameters to derive one or more keys from a common secret value.

*buddy* commes with several of them:

| Name | `:alg` value | Description |
|---|---|---|
| HKDF | `:hkdf+sha256`, `:hkdf+sha384`, `:hkdf+sha512` |  HMAC-based Extract-and-Expand Key Derivation Function |
| KDF1 | `:kdf1+sha256`, `:kdf1+sha384`, `:kdf1+sha512` | KDF v1 |
| KDF2 | `:kdf2+sha256`, `:kdf2+sha384`, `:kdf2+sha512` | KDF v2 |
| CMKDF | `:cmkdf+sha256`, `:cmkdf+sha384`, `:cmkdf+sha512` | Counter-Mode key derivation function (as defined in NIST SP800-108) |
| FMKDF | `:fmkdf+sha256`, `:fmkdf+sha384`, `:fmkdf+sha512` | Feedback-Mode key derivation function (as defined in NIST SP800-108) |
| DPIMKDF | `:dpimkdf+sha256`, `:dpimkdf+sha384`, `:dpimkdf+sha512` | Double-Pipeline Iteration Mode key derivation function (as defined in NIST SP800-108) |
| PBKDF2 | `:pbkdf2+sha256`, `:pbkdf2+sha384`, `:pbkdf2+sha512` | Password-Based Key Derivation Function 2 (a.k.a. `RSA PKCS #5 v2.0`, also published in RFC 2898) |


Example using KDF with HKDF key derivation function:

```clojure
(require '[buddy.core.codecs :as codecs])
(require '[buddy.core.kdf :as kdf])

;; Using hkdf derivation functions. It requires a
;; key, salt and optionally info field that can
;; contain any random data.

(def hkdf (kdf/engine {:alg :hkdf+sha256
                       :key "mysecret"
                       :salt "mysalt"}))

(-> (kdf/get-bytes hkdf 8)
    (codecs/bytes->hex))
;; => "0faba553152fce4f"


;; Or using different digest algorithm:

(def hkdf (kdf/engine {:alg :hkdf
                       :digest :blake2b-512
                       :key "test"
                       :salt "test"}))

(-> (kdf/get-bytes hkdf 8)
    (codecs/bytes->hex))
;; => "9d22728d54e549a6"
```

Example using PBKDF2 with sha256:

```clojure
(def pbkdf2 (kdf/engine {:key "my password"
                         :salt (nonce/random-bytes 8)
                         :alg :pbkdf2
                         :digest :sha256
                         :iterations 1}))

(-> (kdf/get-bytes pbkdf2 8)
    (codecs/bytes->hex))
;; => "26606ebf3a4bb4b3"
```

**WARNING:** PBKDF2 works slightly different to the rest of KDF
implementations. You should pass the number of iterations explicltly
and `get-bytes` always returns the same value in contrast to the
others where `get-bytes` works as consumer of infinite stream.


```clojure
;; Note the same output for multiple requests:

(-> (kdf/get-bytes pbkdf2 8)
    (codecs/bytes->hex))
;; => "26606ebf3a4bb4b3"

(-> (kdf/get-bytes pbkdf2 8)
    (codecs/bytes->hex))
;; => "26606ebf3a4bb4b3"

;; Note that each request returns the next
;; bytes of the stream:

(-> (kdf/get-bytes hkdf 8)
    (codecs/bytes->hex))
;; => "d42edcfc40c860ce"

(-> (kdf/get-bytes hkdf 8)
    (codecs/bytes->hex))
;; => "353ce2240159c094"
```

**WARNING**: This is a *low-level* kdf primitive and if you want a
password hasher, please use `buddy-hashers` library instead of this.

