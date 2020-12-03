;; Copyright 2014-2018 Andrey Antukh <niwi@niwi.nz>
;; Copyright 2017-2018 Denis Shilov <sxp@bk.ru>
;;
;; Licensed under the Apache License, Version 2.0 (the "License")
;; you may not use this file except in compliance with the License.
;; You may obtain a copy of the License at
;;
;;     http://www.apache.org/licenses/LICENSE-2.0
;;
;; Unless required by applicable law or agreed to in writing, software
;; distributed under the License is distributed on an "AS IS" BASIS,
;; WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
;; See the License for the specific language governing permissions and
;; limitations under the License.

(ns buddy.core.keys-jwk-tests
  (:require [clojure.test :refer :all]
            [buddy.core.keys :as keys]
            [buddy.core.keys.jwk.proto :as proto]
            [buddy.core.codecs.base64 :as b64]
            [buddy.core.codecs :as codecs]
            [buddy.core.dsa :as dsa]
            [buddy.util.ecdsa :refer [transcode-to-der]]
            [buddy.core.keys.jwk.eddsa :refer [bc-ed-private-key bc-ed-public-key pkcs8-key x509-key]])
  (:import (org.bouncycastle.jcajce.provider.asymmetric.edec BCEdDSAPrivateKey BCEdDSAPublicKey)
           (org.bouncycastle.crypto.params Ed25519PrivateKeyParameters Ed25519PublicKeyParameters
                                           Ed448PrivateKeyParameters Ed448PublicKeyParameters)
           (java.security.interfaces ECPublicKey ECPrivateKey RSAPrivateKey RSAPublicKey)
           (java.util Arrays)
           (org.bouncycastle.util BigIntegers)))

;; Ed25519
;; From RFC8037

(def ed25519-jwk-key
  {:kty "OKP"
   :crv "Ed25519"
   :d "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"
   :x "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"})

(def ed448-jwk-key
  {:kty "OKP"
   :crv "Ed448"
   :d "ZXIvEfZfm7XeT-kYVnwfIftaRZgz8Bo3b19BGMSJ2fdLaW4SRXH2sZjs2Arc8ewN3fuzWRjev3rs"
   :x "l1kFulHU9ZNQSbIxY7sYt6NCmg1S1UMm_LGJhx36fE5koFG_6esy9wX5Pt-J0xsK6aB4JFHxT3CA"})

(defn- load-pair [jwk]
  [(keys/jwk->public-key jwk)
   (keys/jwk->private-key jwk)])

(deftest ed25519-pem->jca->jwk
  ; Key generation requires openssl >= 1.1.1
  ; openssl genpkey -algorithm ED25519 > private.pem
  ; openssl pkey -in ec_private.pem -pubout -out public.pem
  (let [public (keys/public-key "test/_files/pubkey.ed25519.pem")
        private (keys/private-key "test/_files/privkey.ed25519.pem")
        jwk (keys/jwk private public)]
    (is (map? jwk))
    (is (= "OKP" (:kty jwk)))
    (is (= "Ed25519" (:crv jwk)))
    (let [public2 (keys/jwk->public-key jwk)
          private2 (keys/jwk->private-key jwk)
          jwk2 (keys/jwk private2 public2)]
      (is (= jwk jwk2)))))

(deftest ed25519-encoding
  (testing "Private key .getEncoded"
    (let [buf (-> (:d ed25519-jwk-key) (b64/decode))
          params (Ed25519PrivateKeyParameters. buf 0)
          key (bc-ed-private-key params)
          buf2 (.getEncoded key)
          buf3 (pkcs8-key buf2 32)]
      (is (Arrays/equals buf buf3))))
  (testing "Public key .getEncoded"
    (let [buf (-> (:x ed25519-jwk-key) (b64/decode))
          params (Ed25519PublicKeyParameters. buf 0)
          key (bc-ed-public-key params)
          buf2 (.getEncoded key)
          buf3 (x509-key buf2 32)]
      (is (Arrays/equals buf buf3)))))

(deftest ed25519-jwk->jca->jwk
  (let [[public private] (load-pair ed25519-jwk-key)]

    (is (instance? BCEdDSAPrivateKey private))
    (is (instance? BCEdDSAPublicKey public))

    (is (= ed25519-jwk-key (keys/jwk private public)))

    (is (= (dissoc ed25519-jwk-key :d)
           (keys/public-key->jwk public)))))

(deftest ed25519-thumbprint
  (let [th (keys/jwk-thumbprint ed25519-jwk-key)]
    (is (= "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
           (-> (b64/encode th true)
               (codecs/bytes->str))))))

(deftest ed25519-load-sign-verify
  (let [[public private] (load-pair ed25519-jwk-key)
        ;; Example from RFC
        payload "eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc"
        signature (dsa/sign payload {:alg :eddsa :key private})]
    (is (= "hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg"
           (codecs/bytes->str (b64/encode signature true))))
    (is (dsa/verify payload signature {:alg :eddsa :key public}))))

(deftest ed448-encoding
  (testing "Private key .getEncoded"
    (let [buf (-> (:d ed448-jwk-key) (b64/decode))
          params (Ed448PrivateKeyParameters. buf 0)
          key (bc-ed-private-key params)
          buf2 (.getEncoded key)
          buf3 (pkcs8-key buf2 57)]
      (is (Arrays/equals buf buf3))))
  (testing "Public key .getEncoded"
    (let [buf (-> (:x ed448-jwk-key) (b64/decode))
          params (Ed448PublicKeyParameters. buf 0)
          key (bc-ed-public-key params)
          buf2 (.getEncoded key)
          buf3 (x509-key buf2 57)]
      (is (Arrays/equals buf buf3)))))

(deftest ed448-pem->jca->jwk
  ; Key generation requires openssl >= 1.1.1
  ; openssl genpkey -algorithm ED448 > private.pem
  ; openssl pkey -in ec_private.pem -pubout -out public.pem
  (let [public (keys/public-key "test/_files/pubkey.ed448.pem")
        private (keys/private-key "test/_files/privkey.ed448.pem")
        jwk (keys/jwk private public)
        sig1 (dsa/sign "ABC" {:alg :eddsa :key private})]
    (is (map? jwk))
    (is (= "OKP" (:kty jwk)))
    (is (= "Ed448" (:crv jwk)))
    (is (dsa/verify "ABC" sig1 {:alg :eddsa :key public}))
    (let [public2 (keys/jwk->public-key jwk)
          private2 (keys/jwk->private-key jwk)
          jwk2 (keys/jwk private2 public2)
          private3 (keys/jwk->private-key jwk2)
          sig2 (dsa/sign "ABC" {:alg :eddsa :key private3})]
      (is (dsa/verify "ABC" sig2 {:alg :eddsa :key public}))
      (is (= jwk jwk2)))))

(deftest ed448-load-sign-verify
  (let [[public private] (load-pair ed448-jwk-key)
        payload "Buddy Loves Christmas!"
        signature (dsa/sign payload {:alg :eddsa :key private})]
    (is (= "mFUWr_F-Xgk0B53Ede9Z7nLOjIdlt5XapOV-BPtLQfznfqoW0ALfrFkaocWKvAV0ytRhTlvLSKiA_rxy6EuvyImPERv0duTf-HwF1gwULvH1MUQQ5Yr8nyymrJTBSHT1aDOCiXm8hCtPHTUbgnBQ0SgA"
          (codecs/bytes->str (b64/encode signature true))))
    (is (dsa/verify payload signature {:alg :eddsa :key public}))))

(deftest bi-encoding
  (testing "simple case"
    (let [ba ^bytes (b64/decode "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A")
          bi (BigIntegers/fromUnsignedByteArray ba)
          l (proto/calc-byte-length bi)]
      (is (= 32 l))
      (is (= (seq ba) (seq (BigIntegers/asUnsignedByteArray l bi))))))

  (testing "leading zeros"
    (let [by ^bytes (b64/decode "ADSmRA43Z1DSNx_RvcLI87cdL07l6jQyyBXMoxVg_l2Th-x3S1WDhjDly79ajL4Kkd0AZMaZmh9ubmf63e3kyMj2")
          bx ^bytes (b64/decode "AekpBQ8ST8a8VcfVOTNl353vSrDCLLJXmPk06wTjxrrjcBpXp5EOnYG_NjFZ6OvLFV1jSfS9tsz4qUxcWceqwQGk")
          bi (BigIntegers/fromUnsignedByteArray by)
          l (proto/calc-byte-length (BigIntegers/fromUnsignedByteArray bx))]
      (is (= 66 l))
      (is (= (seq by) (seq (BigIntegers/asUnsignedByteArray l bi)))))))

;; RSA
;; https://tools.ietf.org/html/rfc7515#appendix-A.2
(def rsa2048-jwk-key
  {:kty "RSA",
   :n "ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ"
   :e "AQAB"
   :d "Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97IjlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYTCBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLhBOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ"})

(deftest rsa-jwk->jca->jwk
  (let [[public private] (load-pair rsa2048-jwk-key)]

    (is (instance? RSAPrivateKey private))
    (is (instance? RSAPublicKey public))

    (is (= rsa2048-jwk-key (keys/jwk private public)))
    (is (= (dissoc rsa2048-jwk-key :d) (keys/public-key->jwk public)))))

(deftest rsa-load-sign-verify
  (let [[public private] (load-pair rsa2048-jwk-key)
        ;; Example from RFC
        payload "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
        signature (dsa/sign payload {:alg :rsassa-pkcs15+sha256 :key private})]

    (is (= "cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw"
           (codecs/bytes->str (b64/encode signature true))))
    (is (dsa/verify payload signature {:alg :rsassa-pkcs15+sha256 :key public}))))

;; https://tools.ietf.org/html/rfc7638#section-3.1
(def rsa-jwk-pubkey
  {:kty "RSA",
   :n "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
   :e "AQAB"
   :alg "RS256"
   :kid "2011-04-29"})

(deftest rsa-thumbprint
  (let [th (keys/jwk-thumbprint rsa-jwk-pubkey)]
    (is (= "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
           (-> (b64/encode th true)
               (codecs/bytes->str))))))

;; ECDSA
;; https://tools.ietf.org/html/rfc7515#appendix-A.3
(def ec256-jwk-key
  {:kty "EC",
   :crv "P-256",
   :x "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
   :y "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
   :d "jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"})

(deftest ec256-jwk->jca->jwk
  (let [[public private] (load-pair ec256-jwk-key)]

    (is (instance? ECPublicKey public))
    (is (instance? ECPrivateKey private))

    (is (= ec256-jwk-key (keys/jwk private public)))
    (is (= (dissoc ec256-jwk-key :d) (keys/public-key->jwk public)))))

(deftest ec256-load-sign-verify
  (let [[public private] (load-pair ec256-jwk-key)
        payload "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
        signature (dsa/sign payload {:alg :ecdsa+sha256 :key private})

        rfcsig (transcode-to-der
                (b64/decode "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q"))]

    (is (dsa/verify payload signature {:alg :ecdsa+sha256 :key public}))

    ;; we can't just check output because signature is different every time
    ;; but we can check validity of RFC-specified signature
    (is (dsa/verify payload rfcsig {:alg :ecdsa+sha256 :key public}))))

;; https://tools.ietf.org/html/rfc7515#appendix-A.3
(def ec521-jwk-key
  {:kty "EC",
   :crv "P-521",
   :x "AekpBQ8ST8a8VcfVOTNl353vSrDCLLJXmPk06wTjxrrjcBpXp5EOnYG_NjFZ6OvLFV1jSfS9tsz4qUxcWceqwQGk",
   :y "ADSmRA43Z1DSNx_RvcLI87cdL07l6jQyyBXMoxVg_l2Th-x3S1WDhjDly79ajL4Kkd0AZMaZmh9ubmf63e3kyMj2",
   :d "AY5pb7A0UFiB3RELSD64fTLOSV_jazdF7fLYyuTw8lOfRhWg6Y6rUrPAxerEzgdRhajnu0ferB0d53vM9mE15j2C"})

(deftest ec521-jwk-jca-jwk
  (let [[public private] (load-pair ec521-jwk-key)]
    (is (instance? ECPublicKey public))
    (is (instance? ECPrivateKey private))

    (is (= ec521-jwk-key (keys/jwk private public)))
    (is (= (dissoc ec521-jwk-key :d) (keys/public-key->jwk public)))))

(deftest ec521-load-sign-verify
  (let [[public private] (load-pair ec521-jwk-key)
        payload "eyJhbGciOiJFUzUxMiJ9.UGF5bG9hZA"
        signature (dsa/sign payload {:alg :ecdsa+sha512 :key private})

        rfcsig (transcode-to-der
                 (b64/decode "AdwMgeerwtHoh-l192l60hp9wAHZFVJbLfD_UxMi70cwnZOYaRI1bKPWROc-mZZqwqT2SI-KGDKB34XO0aw_7XdtAG8GaSwFKdCAPZgoXD2YBJZCPEX3xKpRwcdOO8KpEHwJjyqOgzDO7iKvU8vcnwNrmxYbSW9ERBXukOXolLzeO_Jn"))]

    (is (dsa/verify payload signature {:alg :ecdsa+sha512 :key public}))
    (is (dsa/verify payload rfcsig {:alg :ecdsa+sha512 :key public}))))
