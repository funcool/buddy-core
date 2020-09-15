# Paddings

Padding schemes are often used for fill the empty bytes of byte array
of data to an concrete blocksize.

This is a table of currently supported padding schemes:

|Algorithm name | Keywords |
|---|---|
| Zero Byte | `:zerobyte` |
| PKCS7 | `:pkcs7` |
| TBC | `:tbc` |

Let see an example on how to use it:

```clojure
(require '[buddy.core.padding :as padding])
(require '[buddy.core.bytes :as bytes])

(def data (byte-array 10))

;; Fill the array with byte value 10
(bytes/fill! data 10)

;; Add padding to the byte array with offset value: 7
;; This is a side effect and it will mutate the data
;; byte array.

(vec (padding/pad! data 7 :pkcs7))
;; =>[10 10 10 10 10 10 10 3 3 3]

;; Also it has the side effect free version of it, that
;; returns a new byte array.

(vec (padding/pad data 7 :pkcs7))
;; =>[10 10 10 10 10 10 10 3 3 3]


;; Show the size of applied padding
(padding/count data :pkcs7)
;; => 3

;; Remove the padding
(vec (padding/unpad data 7 :pkcs7))
;; =>[10 10 10 10 10 10 10 0 0 0]
```

The default padding scheme is `:pkcs7` and that parameter can be
ommited.
