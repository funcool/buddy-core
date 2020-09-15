# FAQ

## Buddy has own cryptographic algorithms implementations?

Mainly no, I'm not cryptography expert and for this I rely on the to
battle tested Bouncy Castle java library that's dedicated to this
purpose.


## Buddy will support pgp?

Surely not! Because there already exists one good
link:https://github.com/greglook/clj-pgp[library for that].


## Unexpected exceptions when application is run from uberjar?

This is known problem of BouncyCastle. This is because, some parts of
buddy uses the BC provider that BouncyCastle exposes. And any security
providers for the JDK should be signed. And if you repackage all
dependencies of your application in one unique jar, it will not match
the signature of BC provider, and then, jdk will silently rejects
adding it.

Take care that only very small part of buddy-core is subject to this
issue. Only the `buddy.core.dsa` and `buddy.core.keys` (partially) are
using the security provider. So if you are using it, you will need to
provide the bouncy castle dependency separatelly to your uberjar
bundle.

A common approach for this case, is just put `:uberjar-exclusions
[#"org/bouncycastle"]` on your `:uberjar` profile and then, download
the bouncycastle jars and expose them in the classpath. If you are
running your application directly from lein, you are not affected by
this issue.


