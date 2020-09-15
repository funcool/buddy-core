# Nonces and Salts

This library comes with helpers for generate random salts and
cryptographically secure nonces:

Generate a cryptographically secure nonce:

```clojure
(require '[buddy.core.nonce :as nonce])

(vec (nonce/random-nonce 16))
;; => [0 0 1 75 -114 49 -91 107 67 -124 -49 -2 -96 100 42 18]

(vec (nonce/random-nonce 16))
;; => [0 0 1 75 -114 49 -88 -102 92 88 111 69 46 93 1 -86]


The `random-nonce` function returns a byte array with minimum length
of 8 bytes, because is the size of the current time in miliseconds.

Generate a cryptographically secure salt:

```clojure
(require '[buddy.core.nonce :as nonce])

(vec (nonce/random-bytes 16))
;; =>[-50 20 -120 -38 -32 -121 -15 109 86 -99 85 -73 28 -92 -67 -64]

(vec (nonce/random-bytes 16))
;; => [84 -88 51 120 122 -30 78 -31 -96 -22 119 122 29 -54 -64 -73]
```

Like `random-nonce` function, `random-bytes` returns a byte array but
it not have the limitation of minimum 8 bytes of size.

