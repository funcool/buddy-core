# Hash algorithms (digest)

All hash algorithms are located in the `buddy.core.hash` namespace.

Available hash algorithms:

| Hash algorithm name | Digest size                    |
|---------------------|--------------------------------|
| SHA1                | 160                            | 
| SHA2                | 256, 384, 512                  |
| SHA3                | 256, 384, 512                  |
| MD5                 | 128                            |
| Tiger               | 192                            |
| BLAKE2b             | 128, 256, 512                  |
| BLAKE3              | 256, arbitrary size            |
| Skein               | 256, 512, 1024, arbitrary size |
| Whirlpool           | 512                            |
| RIPEMD128           | 128                            |
| RIPEMD160           | 160                            |
| RIPEMD256           | 256                            |
| RIPEMD320           | 320                            |

## Basic usage

Import namespace example:

```clojure
(require '[buddy.core.hash :as hash])
(require '[buddy.core.codecs :refer :all])
```

Usage examples:

```clojure
(hash/sha256 "foo bar")
;; -> #<byte[] [B@162a657e>

(-> (hash/sha256 "foo bar")
    (bytes->hex))
;; -> "fbc1a9f858ea9e177916964bd88c3d37b91a1e84412765e29950777f265c4b75"
```

## Advanced usage

Hash functions are implemented using protocols and can be extended
to other types. The default implementations come with support
for file-like objects (*File*, *URL*, URI* and *InputStream*).

Make hash of file example:

```clojure
;; Additional import for easy open files
(require '[clojure.java.io :as io])

(-> (hash/sha256 (io/input-stream "/tmp/some-file"))
    (bytes->hex))
;; -> "bba878639499c8449f69efbfc699413eebfaf41d4b7a7faa560bfaf7e93a43dd"
```

You can extend it for your own types using the
*buddy.core.hash/IDigest* protocol:

```clojure
(defprotocol Digest
  (-digest [data engine]))
```

**NOTE**: Functions like *sha256* are aliases for the more generic
function *digest*.
