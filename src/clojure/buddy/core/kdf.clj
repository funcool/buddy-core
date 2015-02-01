(ns buddy.core.kdf
  "Key derivation function interface."
  (:require [buddy.core.hash :as hash])
  (:import org.bouncycastle.crypto.generators.KDF1BytesGenerator
           org.bouncycastle.crypto.generators.KDF2BytesGenerator
           org.bouncycastle.crypto.generators.HKDFBytesGenerator
           org.bouncycastle.crypto.generators.KDFCounterBytesGenerator
           org.bouncycastle.crypto.generators.KDFFeedbackBytesGenerator
           org.bouncycastle.crypto.generators.KDFDoublePipelineIterationBytesGenerator
           org.bouncycastle.crypto.params.HKDFParameters
           org.bouncycastle.crypto.params.KDFParameters
           org.bouncycastle.crypto.params.KDFCounterParameters
           org.bouncycastle.crypto.params.KDFFeedbackParameters
           org.bouncycastle.crypto.params.KDFDoublePipelineIterationParameters
           org.bouncycastle.crypto.macs.HMac
           org.bouncycastle.crypto.Mac
           java.nio.ByteBuffer
           clojure.lang.Keyword))

(defprotocol IKDF
  "Generic type that unify access to any implementation
  of kdf implemented in buddy."
  (generate-byte-array! [_ length] "Generate byte array of specified length.")
  (generate-byte-buffer! [_ length] "Generate byte buffer of specified length."))

(defn generate-bytes!
  "Generate a byte array of specified length.
  WARNING: this method is deprecated but maintained
  untile next version for backward compatibility."
  [impl ^long length]
  (generate-byte-array! impl length))

(defn- generate-byte-array
  [impl length]
  (let [buffer (byte-array length)]
    (.generateBytes impl buffer 0 length)
    buffer))

(defn- generate-byte-buffer
  [impl length]
  (let [buffer (generate-byte-array impl length)]
    (ByteBuffer/wrap buffer)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; HKDF interface
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn hkdf
  "HMAC-based Extract-and-Expand Key Derivation Function (HKDF) implemented
  according to IETF RFC 5869, May 2010 as specified by H. Krawczyk, IBM
  Research &amp; P. Eronen, Nokia. It uses a HMac internally to compute de OKM
  (output keying material) and is likely to have better security properties
  than KDF's based on just a hash function."
  [^bytes keydata ^bytes salt ^bytes info ^Keyword alg]
  (let [params  (HKDFParameters. keydata salt info)
        digest  (hash/resolve-digest alg)
        kdfimpl (HKDFBytesGenerator. digest)]
    (.init kdfimpl params)
    (reify
      IKDF
      (generate-byte-array! [_ length]
        (generate-byte-array kdfimpl length))

      (generate-byte-buffer! [_ length]
        (generate-byte-buffer kdfimpl length)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; KDF1/2 interface
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn kdf1
  "DF2 generator for derived keys and ivs as defined by IEEE P1363a/ISO 18033"
  [^bytes keydata ^bytes salt ^Keyword alg]
  (let [params  (KDFParameters. keydata salt)
        digest  (hash/resolve-digest alg)
        kdfimpl (KDF1BytesGenerator. digest)]
    (.init kdfimpl params)
    (reify
      IKDF
      (generate-byte-array! [_ length]
        (generate-byte-array kdfimpl length))

      (generate-byte-buffer! [_ length]
        (generate-byte-buffer kdfimpl length)))))

(defn kdf2
  "DF2 generator for derived keys and ivs as defined by IEEE P1363a/ISO 18033"
  [^bytes keydata ^bytes salt ^Keyword alg]
  (let [params  (KDFParameters. keydata salt)
        digest  (hash/resolve-digest alg)
        kdfimpl (KDF2BytesGenerator. digest)]
    (.init kdfimpl params)
    (reify
      IKDF
      (generate-byte-array! [_ length]
        (generate-byte-array kdfimpl length))

      (generate-byte-buffer! [_ length]
        (generate-byte-buffer kdfimpl length)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Counter mode KDF
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn cmkdf
  "Counter mode KDF defined by the publicly available
  NIST SP 800-108 specification."
  [^bytes keydata ^bytes salt ^Keyword alg & [{:keys [r] :or {r 32}}]]
  (let [params  (KDFCounterParameters. keydata salt r)
        digest  (hash/resolve-digest alg)
        mac     (HMac. digest)
        kdfimpl (KDFCounterBytesGenerator. mac)]
    (.init kdfimpl params)
    (reify
      IKDF
      (generate-byte-array! [_ length]
        (generate-byte-array kdfimpl length))

      (generate-byte-buffer! [_ length]
        (generate-byte-buffer kdfimpl length)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Feedback mode KDF
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn fmkdf
  "Counter mode KDF defined by the publicly available
  NIST SP 800-108 specification."
  [^bytes keydata ^bytes salt ^Keyword alg & [{:keys [r use-counter] :or {r 32 use-counter true}}]]
  ;; KDFFeedbackParameters takes iv and salt as parameter but
  ;; at this momment, iv is totally ignored:
  ;; https://github.com/bcgit/bc-java/../generators/KDFFeedbackBytesGenerator.java#L137
  (let [params  (if use-counter
                  (KDFFeedbackParameters/createWithCounter keydata salt salt r)
                  (KDFFeedbackParameters/createWithoutCounter keydata salt salt))
        digest  (hash/resolve-digest alg)
        mac     (HMac. digest)
        kdfimpl (KDFFeedbackBytesGenerator. mac)]
    (.init kdfimpl params)
    (reify
      IKDF
      (generate-byte-array! [_ length]
        (generate-byte-array kdfimpl length))

      (generate-byte-buffer! [_ length]
        (generate-byte-buffer kdfimpl length)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Feedback mode KDF
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn dpimkdf
  "Double-Pipeline Iteration Mode KDF defined by the publicly
available NIST SP 800-108 specification."
  [^bytes keydata ^bytes salt ^Keyword alg & [{:keys [r use-counter] :or {r 32 use-counter true}}]]
  (let [params  (if use-counter
                  (KDFDoublePipelineIterationParameters/createWithCounter keydata salt r)
                  (KDFDoublePipelineIterationParameters/createWithoutCounter keydata salt))
        digest  (hash/resolve-digest alg)
        mac     (HMac. digest)
        kdfimpl (KDFDoublePipelineIterationBytesGenerator. mac)]
    (.init kdfimpl params)
    (reify
      IKDF
      (generate-byte-array! [_ length]
        (generate-byte-array kdfimpl length))

      (generate-byte-buffer! [_ length]
        (generate-byte-buffer kdfimpl length)))))
