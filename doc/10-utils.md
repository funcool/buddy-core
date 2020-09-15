# Codecs & Bytes

This library comes with helpers for working with codecs (hex, base64,
...) and byte arrays.

This is a brief list of available functions:

| Namespace/Function | Description |
|---|---|
| `buddy.core.codecs/str->bytes` | Converts a string into byte array |
| `buddy.core.codecs/bytes->str` | Converts byte array to string using UTF8 encoding |
| `buddy.core.codecs/bytes->hex` | Converts byte array to hexadecimal string |
| `buddy.core.codecs/hex->bytes` | Converts hexadecimal strings into byte array |
| `buddy.core.codecs/bytes->b64` | Encodes byte array to base64 byte array |
| `buddy.core.codecs/b64->bytes` | Decodes base64 byte array into byte array |
| `buddy.core.codecs/bytes->b64u` | Encodes byte array to base64 byte array (using url-save variant) |
| `buddy.core.codecs/b64u->bytes` | Decodes base64 byte array into byte array (using url-safe variant) |
| `buddy.core.codecs/long->bytes` | Get byte array representation of long |
| `buddy.core.codecs/bytes->long` | Get long from byte array |
| `buddy.core.bytes/bytes?` | Predicate for test byte arrays |
| `buddy.core.bytes/fill!` | Fill byte array with data |
| `buddy.core.bytes/slice` | Create a new byte array as slice of other |
| `buddy.core.bytes/copy` | Copy the byte array |
| `buddy.core.bytes/equals?` | Constant time equals predicate for byte arrays |
| `buddy.core.bytes/concat` | Concat two or more byte arrays |

