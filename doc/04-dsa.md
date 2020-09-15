# Digital Signatures

Digital Signature algorithms has similar purposes that MAC but comes
with some tradeoffs such as them provides additional security feature
(Non-repudiation) with cost in the performance. You can read a great
explanation about the differences with MAC
[here](http://crypto.stackexchange.com/a/5647).

Example signing string using rsassa-pss+sha256:

```clojure
(require '[buddy.core.keys :as keys])
(require '[buddy.core.dsa :as dsa])

;; Read private key
(def privkey (keys/private-key "test/_files/privkey.3des.rsa.pem" "secret"))

;; Make signature
(def signature (dsa/sign "foo" {:key privkey :alg :rsassa-pss+sha256}))

;; Now signature contains a byte[] with signature of "foo" string
```

Example verifying signature:

```clojure
;; Read public key
(def pubkey (keys/public-key "test/_files/pubkey.3des.rsa.pem"))

;; Make verification
(dsa/verify "foo" signature {:key pubkey :alg :rsassa-pss+sha256})
;; => true
```

Here is a table with complete list of supported algorithms and its variants:

| Algorithm name  | `:alg` keyword value
| --- | --- |
| RSASSA-PSS | `:rsassa-pss+sha256`, `:rsassa-pss+sha384`, `:rsassa-pss+sha512` |
| RSASSA-PKCS 1.5 | `:rsassa-pkcs15+sha256`, `:rsassa-pkcs15+sha384`, `:rsassa-pkcs15+sha512` |
| ECDSA           | `:ecdsa+sha256`, `:ecdsa+sha384`, `:ecdsa+sha512` |


**NOTE**: *ECDSA* algorithm requires EC type of asymentric key pair.

