# Crypto

**WARNING**: this is a not a serious project, all implementation will be following the specifications as close as possible but none of it will be security reviewed. **DO NOT USE THIS**

## Aims

Implement a TLS1.2 steam wrapper without using any cryptography libraries

## Layout

    Crypto/
      Certificates/ Certificate handling
      Encryption/   Asymmetric & symmetric encryption / decryption
      Hashing/      One way hash functions
      IO/           TLS functionality

## TODO

* Read / Write application records
* Handle & generate alerts 
* Implement more ciphers, digests, keyexchanges, etc
* Client
* Client certificate
* Extensions (HashAndSignature, SAN)