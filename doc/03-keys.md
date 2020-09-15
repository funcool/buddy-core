# Keys

## Reading PEM formatted keys

Before explaining digital signatures, you need to read public/private
keypairs and convert them to usable objects. Buddy has limited support
for reading:

- RSA keypair
- ECDSA keypair


### RSA Keypair

An RSA keypair is obviously used for RSA encryption/decryption, but it
is also used for making digital signatures with RSA-derived
algorithms.

Read keys:

```clojure
(require '[buddy.core.keys :as keys])

;; The last parameter is optional and is only mandatory
;; if a private key is encrypted.
(def privkey (keys/private-key "test/_files/privkey.3des.rsa.pem" "secret")
(def pubkey (keys/public-key "test/_files/pubkey.3des.rsa.pem"))
```

Generate a RSA Keypair using openssl:

```bash
# Generate AES-256 encrypted private key
openssl genrsa -aes256 -out privkey.pem 2048

# Generate public key from previously created private key.
openssl rsa -pubout -in privkey.pem -out pubkey.pem
```


### ECDSA Keypair

Like RSA keypairs, ECDSA is also used for making digital signatures
and can be read like in the RSA examples.

Read keys:

```clojure
(require '[buddy.core.keys :as keys])

;; The last parameter is optional and is only mandatory
;; if a private key is encrypted.
(def privkey (keys/private-key "test/_files/privkey.ecdsa.pem" "secret")
(def pubkey (keys/public-key "test/_files/pubkey.ecdsa.pem"))
```

Generate a ECDSA Keypair using openssl:

```bash
# Generate a params file
openssl ecparam -name prime256v1 -out ecparams.pem

# Generate a private key from params file
openssl ecparam -in ecparams.pem -genkey -noout -out ecprivkey.pem

# Generate a public key from private key
openssl ec -in ecprivkey.pem -pubout -out ecpubkey.pem
```

## Json Web Key (JWK)

A JSON Web Key (JWK) is a JavaScript Object Notation (JSON) data
structure that represents a cryptographic key of different types.

_buddy-core_ provides functions for reading and saving JCA keys in JWK
format

Currently supported JWK key types are

* RSA key pairs (No RSA-CRT support yet)
* OKP key pairs (Ed25519)
* EC key pairs (P-256, P-384, P-521 curves)

Example of JWS signing for Ed25519 keys:

```clojure
(require '[buddy.core.keys :as keys])

(def edkey {:kty "OKP",
            :crv "Ed25519",
            :d "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",
            :x "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"})

(def privkey (keys/jwk->private-key edkey))
```

You can also convert from PEM to JWK like this:

```clojure
(require '[buddy.core.keys :as keys])

(def prv (keys/private-key "private.pem"))
(def pub (keys/public-key "public.pem"))

;; JWK requires both public and private keys for export
(def jwk (keys/jwk prv pub))
(def jwk-pub (keys/public-key->jwk pub))
```

Also, you can generate and save keys in JWK format like this

```clojure
(require '[buddy.core.keys :as keys])
(import 'java.security.KeyPairGenerator)
(import 'java.security.SecureRandom)

(defn generate-keypair-ed25519
  []
  (let [kg (KeyPairGenerator/getInstance "EdDSA" "EdDSA")]
    (.initialize kg
                 256
                 ;; JDK8 only, use getInstance on JDK7 (make sure it's true random source)
                 (SecureRandom/getInstanceStrong))
    (.genKeyPair kg)))

(let [pair (generate-keypair-ed25519)]
  (keys/jwk (.getPrivate pair) (.getPublic pair)))

;; =>
;; {:kty "OKP",
;;  :crv "Ed25519",
;;  :d "5q3yhCdSDMj9Za9jJE0vhfExlTV8JeSe6XnfblAFkPY",
;;  :x "JbbhB16SaghHiGHx3FutVMfVTgu9-SCtZGfZyoDZSbQ"}
```

You can also calculate JWK thumbprint using `jwk-thumbprint` function


```clojure
(require '[buddy.core.keys :as keys])
(require '[buddy.core.codecs :as codecs])

(def edkey {:kty "OKP",
            :crv "Ed25519",
            :d "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",
            :x "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"})

(-> (keys/jwk-thumbprint edkey)
    (codecs/bytes->hex))

;; => "90facafea9b1556698540f70c0117a22ea37bd5cf3ed3c47093c1707282b4b89"
```
