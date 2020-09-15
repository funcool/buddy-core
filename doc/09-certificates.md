# Certificates (X.509)

Support for basic certificate handling is available in the
`buddy.core.certificates` namespace.

You can load certificates, check date validity, and check to see if a
certificate is signed by a known public key.

```clojure
(require '[buddy.core.certificates :as certs])

(def cert (certs/certificate "path/to/certificate.crt"))
;; => #object[org.bouncycastle.cert.X509CertificateHolder 0x2919034b "org.bouncycastle.cert.X509CertificateHolder@1612eab1"]
(certs/valid-on-date? cert)
;; => true if today is between not-before and not-after

(certs/verify-signature cert (certs/certificate "path/to/ca.crt"))
;; => true if cert is signed by public key in ca.crt
```

