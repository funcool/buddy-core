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

(ns buddy.core.certificates-tests
  (:require [clojure.test :refer :all]
            [buddy.core.codecs :refer :all]
            [buddy.core.nonce :as nonce]
            [buddy.core.bytes :as bytes]
            [buddy.core.certificates :as certificates]
            [buddy.core.keys :as keys]))

(deftest read-certs
  (is (instance?
       org.bouncycastle.cert.X509CertificateHolder
       (certificates/certificate "test/_files/ca-cert.rsa.pem")))
  (is (instance?
       org.bouncycastle.cert.X509CertificateHolder
       (certificates/certificate "test/_files/cert.rsa.pem")))
  (is (instance?
       org.bouncycastle.cert.X509CertificateHolder
       (certificates/str->certificate (slurp "test/_files/cert.rsa.pem")))))

(deftest verify-signature
  (let [cert (certificates/certificate "test/_files/cert.rsa.pem")
        ca-cert (certificates/certificate "test/_files/ca-cert.rsa.pem")]
    (testing "cert is signed by ca"
      (is (certificates/verify-signature cert
                                         (keys/public-key "test/_files/ca-cert.rsa.pem"))))
    (testing "cert is signed by ca with certificate"
      (is (certificates/verify-signature cert
                                         (certificates/certificate "test/_files/ca-cert.rsa.pem"))))
    (testing "cert is not self signed"
      (is (not (certificates/verify-signature cert
                                              (keys/public-key "test/_files/cert.rsa.pem")))))
    (testing "cert is not self signed by certificate"
      (is (not (certificates/verify-signature cert
                                              (certificates/certificate "test/_files/cert.rsa.pem")))))))
(deftest date-handling
    (let [expired (certificates/certificate "test/_files/expired-rsa.crt")]
      (is (= #inst "2016-12-01T16:18:40.000-00:00" (certificates/not-before expired)))
      (is (= #inst "2016-12-02T16:18:40.000-00:00" (certificates/not-after expired)))
      (is (not (certificates/valid-on-date? expired)))
      (is (certificates/valid-on-date? expired #inst "2016-12-02T16:18:40.000-00:00"))
      (is (certificates/valid-on-date? expired #inst "2016-12-02T16:17:40.000-00:00"))
      (is (not (certificates/valid-on-date? expired #inst "2016-12-01T16:17:40.000-00:00")))
      (is (not (certificates/valid-on-date? expired #inst "2016-12-03T16:17:40.000-00:00"))) ))


(deftest subject
  (is (= "C=AU,ST=Some-State,O=Internet Widgits Pty Ltd"
         (certificates/subject (certificates/certificate "test/_files/cert.rsa.pem")))))
