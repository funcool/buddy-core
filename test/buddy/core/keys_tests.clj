;; Copyright 2014-2015 Andrey Antukh <niwi@niwi.nz>
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

(ns buddy.core.keys-tests
  (:require [clojure.test :refer :all]
            [buddy.core.codecs :refer :all]
            [buddy.core.nonce :as nonce]
            [buddy.core.bytes :as bytes]
            [buddy.core.keys :as keys]))

(deftest read-asynmetric-encryption-keys
  (testing "Read rsa priv key"
    (let [pkey (keys/private-key "test/_files/privkey.3des.rsa.pem" "secret")]
      (is (= (type pkey) org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPrivateCrtKey))))

  (testing "Read rsa priv key without password"
    (is (thrown? clojure.lang.ExceptionInfo (keys/private-key "test/_files/privkey.3des.rsa.pem")))
    (let [pkey (keys/private-key "test/_files/privkey.rsa.pem")]
      (is (= (type pkey) org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPrivateCrtKey))))

  (testing "Read rsa PKCS#8 priv key"
    (let [pkey (keys/private-key "test/_files/privkey.pkcs8.3des.rsa.pem" "secret")]
      (is (= (type pkey) org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPrivateCrtKey))))

  (testing "Read rsa PKCS#8 priv key without password"
    (is (thrown? clojure.lang.ExceptionInfo (keys/private-key "test/_files/privkey.pkcs8.3des.rsa.pem")))
    (let [pkey (keys/private-key "test/_files/privkey.pkcs8.rsa.pem")]
      (is (= (type pkey) org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPrivateCrtKey))))

  (testing "Read dsa priv key"
    (let [pkey (keys/private-key "test/_files/privkey.3des.dsa.pem" "secret")]
      (is (= (type pkey) org.bouncycastle.jcajce.provider.asymmetric.dsa.BCDSAPrivateKey))))

  (testing "Read rsa priv key with bad password"
    (is (thrown? org.bouncycastle.openssl.EncryptionException
                (keys/private-key "test/_files/privkey.3des.rsa.pem" "secret2"))))

  (testing "Read dsa priv key with bad password"
    (is (thrown? org.bouncycastle.openssl.EncryptionException
                (keys/private-key "test/_files/privkey.3des.dsa.pem" "secret2"))))

  (testing "Read ecdsa priv key"
    (let [pkey (keys/private-key "test/_files/privkey.ecdsa.pem" "secret")]
      (is (= (type pkey) org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey))
      (is (keys/private-key? pkey))))

  (testing "Read rsa pub key"
    (let [pkey (keys/public-key "test/_files/pubkey.3des.rsa.pem")]
      (is (= (type pkey) org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPublicKey))))

  (testing "Read X.509 rsa pub key"
    (let [pkey (keys/public-key "test/_files/pubkey.X509.rsa.pem")]
      (is (= (type pkey) org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPublicKey))))

  (testing "Read dsa pub key"
    (let [pkey (keys/public-key "test/_files/pubkey.3des.dsa.pem")]
      (is (keys/public-key? pkey))
      (is (= (type pkey) org.bouncycastle.jcajce.provider.asymmetric.dsa.BCDSAPublicKey))))

  (testing "Read ec pub key"
    (let [pkey (keys/public-key "test/_files/pubkey.ecdsa.pem")]
      (is (= (type pkey) org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey))))

  (testing "Read public key from string."
    (let [keystr (slurp "test/_files/pubkey.ecdsa.pem")
          pkey (keys/str->public-key keystr)]
      (is (= (type pkey) org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey))
      (is (keys/public-key? pkey))))

  (testing "Read ecdsa priv key from string."
    (let [keystr (slurp "test/_files/privkey.ecdsa.pem")
          pkey (keys/str->private-key keystr)]
      (is (= (type pkey) org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey))
      (is (keys/private-key? pkey))))

  (testing "Read rsa priv key from string"
    (let [keystr (slurp "test/_files/privkey.3des.rsa.pem")
          pkey (keys/str->private-key keystr "secret")]
      (is (= (type pkey) org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPrivateCrtKey))
      (is (keys/private-key? pkey))))

  (testing "Read rsa priv key from string without password."
    (is (thrown? clojure.lang.ExceptionInfo
                 (let [keystr (slurp "test/_files/privkey.3des.rsa.pem")
                       pkey (keys/str->private-key keystr)])))
    (let [keystr (slurp "test/_files/privkey.rsa.pem")
          pkey (keys/str->private-key keystr)]
      (is (= (type pkey) org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPrivateCrtKey))
      (is (keys/private-key? pkey))))

  (testing "Read rsa priv key from string with bad password"
    (is (thrown? org.bouncycastle.openssl.EncryptionException
                 (let [keystr (slurp "test/_files/privkey.3des.rsa.pem")
                       pkey (keys/str->private-key keystr "secret2")]
                   (is (= (type pkey) org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPrivateCrtKey))))))
)

(deftest key-wrapping-algorithms
  (let [secret16 (nonce/random-bytes 16)
        secret24 (nonce/random-bytes 24)
        secret32 (nonce/random-bytes 32)
        secret64 (nonce/random-bytes 64)
        cek (nonce/random-bytes 32)
        cek' (nonce/random-bytes 31)]

    (testing "Wrap and unwrap a cek using aes128kw"
      (let [result (keys/wrap cek secret16)
            result' (keys/unwrap result secret16)]
        (is (bytes/equals? result' cek))))

    (testing "Wrap and unwrap a cek using aes192kw"
      (let [result (keys/wrap cek secret24)
            result' (keys/unwrap result secret24)]
        (is (bytes/equals? result' cek))))

    (testing "Wrap and unwrap a cek using aes256kw"
      (let [result (keys/wrap cek secret32)
            result' (keys/unwrap result secret32)]
        (is (bytes/equals? result' cek))))

    (testing "Wrap with wrong secret size"
      (is (thrown? AssertionError (keys/wrap cek secret64))))

    (testing "Wrap with wrong length cek"
      (is (thrown? org.bouncycastle.crypto.DataLengthException (keys/wrap cek' secret16))))
))
