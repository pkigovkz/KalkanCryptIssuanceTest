### Chained certificates issuer

TestSuite to issue chain of certificates according to the chain of NCA certificates (default algorithm: GOST 34.10–2015 512 bits).

Entries of Root CA and Intermediate CA are stored in PKCS#12 keystore.

End-entity entries may be stored in any keystore supported by Kalkancrypt (PKCS#12 by default).

Simply run

`mvn package`
