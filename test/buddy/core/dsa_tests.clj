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

(ns buddy.core.dsa-tests
  (:require [clojure.test :refer :all]
            [buddy.core.codecs :as codecs :refer :all]
            [buddy.core.bytes :as bytes]
            [buddy.core.keys :refer :all]
            [buddy.core.dsa :as dsa]
            [clojure.java.io :as io]))

(deftest low-level-sign
  (let [rsa-privkey (private-key "test/_files/privkey.3des.rsa.pem" "secret")
        rsa-pubkey  (public-key "test/_files/pubkey.3des.rsa.pem")
        ec-privkey  (private-key "test/_files/privkey.ecdsa.pem")
        ec-pubkey   (public-key "test/_files/pubkey.ecdsa.pem")]

    (testing "Multiple sign using rsassa-pkcs"
      (let [opts {:key rsa-privkey :alg :rsassa-pkcs15+sha256}]
        (is (bytes/equals? (dsa/sign "foobar" opts)
                           (dsa/sign "foobar" opts)))))

    (testing "Sign/Verify using rsassa-pkcs"
      (let [sign-opts {:key rsa-privkey :alg :rsassa-pkcs15+sha256}
            verify-opts {:key rsa-pubkey :alg :rsassa-pkcs15+sha256}
            sig (dsa/sign "foobar" sign-opts)]
        (is (dsa/verify "foobar" sig verify-opts))))

    (testing "Multiple sign using rsassa-pss"
      (let [opts {:key rsa-privkey :alg :rsassa-pss+sha256}]
        (is (not (bytes/equals? (dsa/sign "foobar" opts)
                                (dsa/sign "foobar" opts))))))

    (testing "Sign/Verify using rsassa-pss"
      (let [sign-opts {:key rsa-privkey :alg :rsassa-pss+sha256}
            verify-opts {:key rsa-pubkey :alg :rsassa-pss+sha256}
            sig (dsa/sign "foobar" sign-opts)]
        (is (dsa/verify "foobar" sig verify-opts))))



    (testing "Multiple sign using ecdsa"
      (let [opts {:key ec-privkey :alg :ecdsa+sha256}]
        (is (not (bytes/equals? (dsa/sign "foobar" opts)
                                (dsa/sign "foobar" opts))))))

    (testing "Sign/Verify using ecdsa"
      (let [sign-opts {:key ec-privkey :alg :ecdsa+sha256}
            verify-opts {:key ec-pubkey :alg :ecdsa+sha256}
            sig (dsa/sign "foobar" sign-opts)]
        (is (dsa/verify "foobar" sig verify-opts))))

    (testing "Sign/Verify input stream"
      (let [sign-opts {:key ec-privkey :alg :ecdsa+sha384}
            verify-opts {:key ec-pubkey :alg :ecdsa+sha384}
            path "test/_files/pubkey.ecdsa.pem"
            sig  (dsa/sign (io/input-stream path) sign-opts)]
        (is (dsa/verify (io/input-stream path) sig verify-opts))))

    (testing "Sign/Verify file"
      (let [sign-opts {:key ec-privkey :alg :ecdsa+sha512}
            verify-opts {:key ec-pubkey :alg :ecdsa+sha512}
            path "test/_files/pubkey.ecdsa.pem"
            sig  (dsa/sign (java.io.File. path) sign-opts)]
        (is (dsa/verify (java.io.File. path) sig verify-opts))))

    (testing "Sign/Verify URL"
      (let [sign-opts {:key ec-privkey :alg :ecdsa+sha512}
            verify-opts {:key ec-pubkey :alg :ecdsa+sha512}
            path "test/_files/pubkey.ecdsa.pem"
            sig  (dsa/sign (.toURL (java.io.File. path)) sign-opts)]
        (is (dsa/verify (.toURL (java.io.File. path)) sig verify-opts))))

    (testing "Sign/Verify URI"
      (let [sign-opts {:key ec-privkey :alg :ecdsa+sha512}
            verify-opts {:key ec-pubkey :alg :ecdsa+sha512}
            path "test/_files/pubkey.ecdsa.pem"
            sig  (dsa/sign (.toURI (java.io.File. path)) sign-opts)]
        (is (dsa/verify (.toURI (java.io.File. path)) sig verify-opts))))
    ))
