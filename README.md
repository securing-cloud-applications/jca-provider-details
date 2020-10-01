# jca-provider-details

Program to print out summary and details on the currently configured JCA providers


# Summary Info

Run the  `com.example.jca.SecurityProviderSummary` you will get output that is dependent on your 
JRE provider configuration. Below is example output with Java 11 on MacOS using AdoptOpenJDK.

```
13 providers found
 Provider: name=SUN, version=11, services=41, info=SUN (DSA key/parameter generation; DSA signing; SHA-1, MD5 digests; SecureRandom; X.509 certificates; PKCS12, JKS & DKS keystores; PKIX CertPathValidator; PKIX CertPathBuilder; LDAP, Collection CertStores, JavaPolicy Policy; JavaLoginConfig Configuration)
 Provider: name=SunRsaSign, version=11, services=15, info=Sun RSA signature provider
 Provider: name=SunEC, version=11, services=25, info=Sun Elliptic Curve provider (EC, ECDSA, ECDH)
 Provider: name=SunJSSE, version=11, services=30, info=Sun JSSE provider(PKCS12, SunX509/PKIX key/trust factories, SSLv3/TLSv1/TLSv1.1/TLSv1.2/TLSv1.3/DTLSv1.0/DTLSv1.2)
 Provider: name=SunJCE, version=11, services=136, info=SunJCE Provider (implements RSA, DES, Triple DES, AES, Blowfish, ARCFOUR, RC2, PBE, Diffie-Hellman, HMAC, ChaCha20)
 Provider: name=SunJGSS, version=11, services=2, info=Sun (Kerberos v5, SPNEGO)
 Provider: name=SunSASL, version=11, services=8, info=Sun SASL provider(implements client mechanisms for: DIGEST-MD5, EXTERNAL, PLAIN, CRAM-MD5, NTLM; server mechanisms for: DIGEST-MD5, CRAM-MD5, NTLM)
 Provider: name=XMLDSig, version=11, services=13, info=XMLDSig (DOM XMLSignatureFactory; DOM KeyInfoFactory; C14N 1.0, C14N 1.1, Exclusive C14N, Base64, Enveloped, XPath, XPath2, XSLT TransformServices)
 Provider: name=SunPCSC, version=11, services=1, info=Sun PC/SC provider
 Provider: name=JdkLDAP, version=11, services=1, info=JdkLDAP Provider (implements LDAP CertStore)
 Provider: name=JdkSASL, version=11, services=2, info=JDK SASL provider(implements client and server mechanisms for GSSAPI)
 Provider: name=Apple, version=11, services=1, info=Apple Provider
 Provider: name=SunPKCS11, version=11, services=0, info=Unconfigured and unusable PKCS11 provider
```


# Details Info

Run the  `com.example.jca.SecurityProviderDetails` you will get output that is dependent on your 
JRE provider configuration. Below is example output with Java 11 on MacOS using AdoptOpenJDK.

```
13 providers found
 Provider: name=SUN, version=11, services=41, info=SUN (DSA key/parameter generation; DSA signing; SHA-1, MD5 digests; SecureRandom; X.509 certificates; PKCS12, JKS & DKS keystores; PKIX CertPathValidator; PKIX CertPathBuilder; LDAP, Collection CertStores, JavaPolicy Policy; JavaLoginConfig Configuration)
  Service: name=SHA3-224, type=MessageDigest
  Service: name=NONEwithDSA, type=Signature
  Service: name=DSA, type=KeyFactory
  Service: name=JavaLoginConfig, type=Configuration
  Service: name=DSA, type=KeyPairGenerator
  Service: name=SHA3-384, type=MessageDigest
  Service: name=SHA3-256, type=MessageDigest
  Service: name=SHA1withDSA, type=Signature
  Service: name=SHA256withDSA, type=Signature
  Service: name=DSA, type=AlgorithmParameterGenerator
  Service: name=SHA-512, type=MessageDigest
  Service: name=X.509, type=CertificateFactory
  Service: name=NativePRNGNonBlocking, type=SecureRandom
  Service: name=SHA, type=MessageDigest
  Service: name=CaseExactJKS, type=KeyStore
  Service: name=PKCS12, type=KeyStore
  Service: name=SHA-512/256, type=MessageDigest
  Service: name=SHA224withDSAinP1363Format, type=Signature
  Service: name=SHA224withDSA, type=Signature
  Service: name=DRBG, type=SecureRandom
  Service: name=DKS, type=KeyStore
  Service: name=NativePRNGBlocking, type=SecureRandom
  Service: name=DSA, type=AlgorithmParameters
  Service: name=Collection, type=CertStore
  Service: name=SHA3-512, type=MessageDigest
  Service: name=SHA-384, type=MessageDigest
  Service: name=SHA-256, type=MessageDigest
  Service: name=com.sun.security.IndexedCollection, type=CertStore
  Service: name=SHA-512/224, type=MessageDigest
  Service: name=SHA-224, type=MessageDigest
  Service: name=JavaPolicy, type=Policy
  Service: name=JKS, type=KeyStore
  Service: name=MD5, type=MessageDigest
  Service: name=PKIX, type=CertPathBuilder
  Service: name=MD2, type=MessageDigest
  Service: name=PKIX, type=CertPathValidator
  Service: name=SHA1PRNG, type=SecureRandom
  Service: name=NONEwithDSAinP1363Format, type=Signature
  Service: name=SHA1withDSAinP1363Format, type=Signature
  Service: name=SHA256withDSAinP1363Format, type=Signature
  Service: name=NativePRNG, type=SecureRandom
 Provider: name=SunRsaSign, version=11, services=15, info=Sun RSA signature provider
  Service: name=RSASSA-PSS, type=KeyFactory
  Service: name=SHA256withRSA, type=Signature
  Service: name=RSA, type=KeyPairGenerator
  Service: name=RSASSA-PSS, type=KeyPairGenerator
  Service: name=SHA1withRSA, type=Signature
  Service: name=MD2withRSA, type=Signature
  Service: name=SHA224withRSA, type=Signature
  Service: name=RSASSA-PSS, type=Signature
  Service: name=RSA, type=KeyFactory
  Service: name=MD5withRSA, type=Signature
  Service: name=SHA512withRSA, type=Signature
  Service: name=SHA512/224withRSA, type=Signature
  Service: name=SHA384withRSA, type=Signature
  Service: name=RSASSA-PSS, type=AlgorithmParameters
  Service: name=SHA512/256withRSA, type=Signature
 Provider: name=SunEC, version=11, services=25, info=Sun Elliptic Curve provider (EC, ECDSA, ECDH)
  Service: name=SHA224withECDSA, type=Signature
  Service: name=SHA512withECDSA, type=Signature
  Service: name=NONEwithECDSAinP1363Format, type=Signature
  Service: name=SHA384withECDSA, type=Signature
  Service: name=NONEwithECDSA, type=Signature
  Service: name=SHA256withECDSA, type=Signature
  Service: name=XDH, type=KeyAgreement
  Service: name=XDH, type=KeyFactory
  Service: name=X448, type=KeyPairGenerator
  Service: name=SHA384withECDSAinP1363Format, type=Signature
  Service: name=SHA512withECDSAinP1363Format, type=Signature
  Service: name=SHA1withECDSA, type=Signature
  Service: name=X25519, type=KeyPairGenerator
  Service: name=EC, type=KeyPairGenerator
  Service: name=ECDH, type=KeyAgreement
  Service: name=SHA1withECDSAinP1363Format, type=Signature
  Service: name=X448, type=KeyAgreement
  Service: name=X25519, type=KeyAgreement
  Service: name=X25519, type=KeyFactory
  Service: name=EC, type=KeyFactory
  Service: name=X448, type=KeyFactory
  Service: name=EC, type=AlgorithmParameters
  Service: name=SHA224withECDSAinP1363Format, type=Signature
  Service: name=SHA256withECDSAinP1363Format, type=Signature
  Service: name=XDH, type=KeyPairGenerator
 Provider: name=SunJSSE, version=11, services=30, info=Sun JSSE provider(PKCS12, SunX509/PKIX key/trust factories, SSLv3/TLSv1/TLSv1.1/TLSv1.2/TLSv1.3/DTLSv1.0/DTLSv1.2)
  Service: name=RSASSA-PSS, type=KeyFactory
  Service: name=SHA256withRSA, type=Signature
  Service: name=RSASSA-PSS, type=KeyPairGenerator
  Service: name=SHA1withRSA, type=Signature
  Service: name=TLS, type=SSLContext
  Service: name=TLSv1, type=SSLContext
  Service: name=MD2withRSA, type=Signature
  Service: name=RSASSA-PSS, type=Signature
  Service: name=RSA, type=KeyFactory
  Service: name=MD5withRSA, type=Signature
  Service: name=PKCS12, type=KeyStore
  Service: name=SHA512withRSA, type=Signature
  Service: name=SunX509, type=TrustManagerFactory
  Service: name=SunX509, type=KeyManagerFactory
  Service: name=DTLSv1.2, type=SSLContext
  Service: name=PKIX, type=TrustManagerFactory
  Service: name=SHA512/224withRSA, type=Signature
  Service: name=SHA224withRSA, type=Signature
  Service: name=NewSunX509, type=KeyManagerFactory
  Service: name=SHA384withRSA, type=Signature
  Service: name=DTLSv1.0, type=SSLContext
  Service: name=SHA512/256withRSA, type=Signature
  Service: name=Default, type=SSLContext
  Service: name=TLSv1.1, type=SSLContext
  Service: name=TLSv1.3, type=SSLContext
  Service: name=RSA, type=KeyPairGenerator
  Service: name=TLSv1.2, type=SSLContext
  Service: name=RSASSA-PSS, type=AlgorithmParameters
  Service: name=DTLS, type=SSLContext
  Service: name=MD5andSHA1withRSA, type=Signature
 Provider: name=SunJCE, version=11, services=136, info=SunJCE Provider (implements RSA, DES, Triple DES, AES, Blowfish, ARCFOUR, RC2, PBE, Diffie-Hellman, HMAC, ChaCha20)
  Service: name=AES_192/CBC/NoPadding, type=Cipher
  Service: name=AES_192/OFB/NoPadding, type=Cipher
  Service: name=PBEWithSHA1AndDESede, type=SecretKeyFactory
  Service: name=AES_192/CFB/NoPadding, type=Cipher
  Service: name=PBEWithSHA1AndRC2_40, type=SecretKeyFactory
  Service: name=AESWrap_192, type=Cipher
  Service: name=PBEWithSHA1AndRC2_128, type=SecretKeyFactory
  Service: name=PBEWithHmacSHA224AndAES_256, type=Cipher
  Service: name=DiffieHellman, type=KeyPairGenerator
  Service: name=AES_192/ECB/NoPadding, type=Cipher
  Service: name=PBKDF2WithHmacSHA1, type=SecretKeyFactory
  Service: name=HmacSHA384, type=KeyGenerator
  Service: name=SunTlsKeyMaterial, type=KeyGenerator
  Service: name=AES_192/GCM/NoPadding, type=Cipher
  Service: name=DiffieHellman, type=KeyAgreement
  Service: name=PBEWithMD5AndDES, type=AlgorithmParameters
  Service: name=PBEWithMD5AndDES, type=SecretKeyFactory
  Service: name=PBEWithHmacSHA512, type=Mac
  Service: name=ChaCha20-Poly1305, type=Cipher
  Service: name=PBEWithHmacSHA384AndAES_128, type=Cipher
  Service: name=AES_128/ECB/NoPadding, type=Cipher
  Service: name=AES, type=KeyGenerator
  Service: name=AES_128/OFB/NoPadding, type=Cipher
  Service: name=SunTlsMasterSecret, type=KeyGenerator
  Service: name=AES_128/CBC/NoPadding, type=Cipher
  Service: name=AESWrap_128, type=Cipher
  Service: name=AES_128/CFB/NoPadding, type=Cipher
  Service: name=PBKDF2WithHmacSHA512, type=SecretKeyFactory
  Service: name=AES_128/GCM/NoPadding, type=Cipher
  Service: name=SunTlsRsaPremasterSecret, type=KeyGenerator
  Service: name=PBEWithHmacSHA224AndAES_128, type=SecretKeyFactory
  Service: name=HmacSHA256, type=KeyGenerator
  Service: name=AES_256/GCM/NoPadding, type=Cipher
  Service: name=PBEWithHmacSHA384AndAES_128, type=SecretKeyFactory
  Service: name=DESede, type=AlgorithmParameters
  Service: name=HmacSHA512/224, type=Mac
  Service: name=PBES2, type=AlgorithmParameters
  Service: name=PBEWithSHA1AndRC4_40, type=SecretKeyFactory
  Service: name=PBEWithSHA1AndRC4_128, type=SecretKeyFactory
  Service: name=AES_256/CFB/NoPadding, type=Cipher
  Service: name=AESWrap_256, type=Cipher
  Service: name=DES, type=KeyGenerator
  Service: name=PBEWithMD5AndDES, type=Cipher
  Service: name=AES_256/ECB/NoPadding, type=Cipher
  Service: name=AES_256/CBC/NoPadding, type=Cipher
  Service: name=PBEWithHmacSHA224AndAES_256, type=SecretKeyFactory
  Service: name=AES_256/OFB/NoPadding, type=Cipher
  Service: name=AES, type=AlgorithmParameters
  Service: name=HmacSHA512/256, type=Mac
  Service: name=DESedeWrap, type=Cipher
  Service: name=DiffieHellman, type=AlgorithmParameters
  Service: name=PBEWithHmacSHA224AndAES_128, type=Cipher
  Service: name=PBEWithSHA1AndRC2_128, type=AlgorithmParameters
  Service: name=DESede, type=KeyGenerator
  Service: name=AES, type=Cipher
  Service: name=HmacSHA1, type=KeyGenerator
  Service: name=HmacSHA224, type=KeyGenerator
  Service: name=HmacSHA1, type=Mac
  Service: name=HmacSHA224, type=Mac
  Service: name=HmacSHA256, type=Mac
  Service: name=ChaCha20, type=Cipher
  Service: name=HmacPBESHA1, type=Mac
  Service: name=DiffieHellman, type=KeyFactory
  Service: name=PBEWithSHA1AndRC4_40, type=AlgorithmParameters
  Service: name=ChaCha20-Poly1305, type=AlgorithmParameters
  Service: name=DiffieHellman, type=AlgorithmParameterGenerator
  Service: name=SslMacMD5, type=Mac
  Service: name=DESede, type=Cipher
  Service: name=PBEWithHmacSHA512AndAES_128, type=Cipher
  Service: name=OAEP, type=AlgorithmParameters
  Service: name=DES, type=AlgorithmParameters
  Service: name=PBEWithMD5AndTripleDES, type=SecretKeyFactory
  Service: name=PBEWithSHA1AndRC2_128, type=Cipher
  Service: name=PBEWithSHA1AndRC2_40, type=Cipher
  Service: name=PBEWithSHA1AndDESede, type=Cipher
  Service: name=PBEWithSHA1AndRC4_128, type=Cipher
  Service: name=PBEWithSHA1AndRC4_40, type=Cipher
  Service: name=HmacSHA512, type=KeyGenerator
  Service: name=PBEWithHmacSHA384, type=Mac
  Service: name=PBKDF2WithHmacSHA384, type=SecretKeyFactory
  Service: name=PBEWithHmacSHA1, type=Mac
  Service: name=PBEWithHmacSHA224AndAES_256, type=AlgorithmParameters
  Service: name=PBEWithHmacSHA512AndAES_256, type=Cipher
  Service: name=ARCFOUR, type=Cipher
  Service: name=PBEWithHmacSHA224AndAES_128, type=AlgorithmParameters
  Service: name=PBEWithSHA1AndDESede, type=AlgorithmParameters
  Service: name=HmacSHA384, type=Mac
  Service: name=HmacSHA512, type=Mac
  Service: name=PBEWithHmacSHA256AndAES_256, type=Cipher
  Service: name=RC2, type=AlgorithmParameters
  Service: name=PBEWithSHA1AndRC4_128, type=AlgorithmParameters
  Service: name=AESWrap, type=Cipher
  Service: name=PBKDF2WithHmacSHA256, type=SecretKeyFactory
  Service: name=RSA, type=Cipher
  Service: name=PBEWithHmacSHA384AndAES_256, type=SecretKeyFactory
  Service: name=RC2, type=Cipher
  Service: name=PBEWithSHA1AndRC2_40, type=AlgorithmParameters
  Service: name=PBEWithHmacSHA256AndAES_128, type=Cipher
  Service: name=PBEWithHmacSHA256AndAES_256, type=SecretKeyFactory
  Service: name=PBEWithHmacSHA256AndAES_128, type=AlgorithmParameters
  Service: name=PBEWithHmacSHA1AndAES_128, type=Cipher
  Service: name=DES, type=Cipher
  Service: name=SslMacSHA1, type=Mac
  Service: name=PBEWithHmacSHA256AndAES_128, type=SecretKeyFactory
  Service: name=PBEWithHmacSHA224, type=Mac
  Service: name=PBEWithHmacSHA256AndAES_256, type=AlgorithmParameters
  Service: name=PBEWithMD5AndTripleDES, type=Cipher
  Service: name=PBKDF2WithHmacSHA224, type=SecretKeyFactory
  Service: name=PBEWithHmacSHA1AndAES_128, type=SecretKeyFactory
  Service: name=SunTls12Prf, type=KeyGenerator
  Service: name=Blowfish, type=KeyGenerator
  Service: name=PBEWithHmacSHA256, type=Mac
  Service: name=HmacMD5, type=KeyGenerator
  Service: name=HmacMD5, type=Mac
  Service: name=PBEWithHmacSHA1AndAES_256, type=SecretKeyFactory
  Service: name=PBEWithHmacSHA512AndAES_128, type=AlgorithmParameters
  Service: name=PBEWithHmacSHA1AndAES_128, type=AlgorithmParameters
  Service: name=DES, type=SecretKeyFactory
  Service: name=PBEWithHmacSHA1AndAES_256, type=Cipher
  Service: name=DESede, type=SecretKeyFactory
  Service: name=PBEWithHmacSHA512AndAES_256, type=AlgorithmParameters
  Service: name=PBEWithHmacSHA1AndAES_256, type=AlgorithmParameters
  Service: name=SunTlsPrf, type=KeyGenerator
  Service: name=ARCFOUR, type=KeyGenerator
  Service: name=RC2, type=KeyGenerator
  Service: name=JCEKS, type=KeyStore
  Service: name=GCM, type=AlgorithmParameters
  Service: name=Blowfish, type=AlgorithmParameters
  Service: name=ChaCha20, type=KeyGenerator
  Service: name=PBEWithHmacSHA384AndAES_256, type=AlgorithmParameters
  Service: name=PBEWithHmacSHA512AndAES_128, type=SecretKeyFactory
  Service: name=PBEWithHmacSHA512AndAES_256, type=SecretKeyFactory
  Service: name=PBEWithHmacSHA384AndAES_128, type=AlgorithmParameters
  Service: name=PBEWithMD5AndTripleDES, type=AlgorithmParameters
  Service: name=Blowfish, type=Cipher
  Service: name=PBEWithHmacSHA384AndAES_256, type=Cipher
 Provider: name=SunJGSS, version=11, services=2, info=Sun (Kerberos v5, SPNEGO)
  Service: name=1.2.840.113554.1.2.2, type=GssApiMechanism
  Service: name=1.3.6.1.5.5.2, type=GssApiMechanism
 Provider: name=SunSASL, version=11, services=8, info=Sun SASL provider(implements client mechanisms for: DIGEST-MD5, EXTERNAL, PLAIN, CRAM-MD5, NTLM; server mechanisms for: DIGEST-MD5, CRAM-MD5, NTLM)
  Service: name=DIGEST-MD5, type=SaslClientFactory
  Service: name=DIGEST-MD5, type=SaslServerFactory
  Service: name=EXTERNAL, type=SaslClientFactory
  Service: name=NTLM, type=SaslClientFactory
  Service: name=NTLM, type=SaslServerFactory
  Service: name=PLAIN, type=SaslClientFactory
  Service: name=CRAM-MD5, type=SaslClientFactory
  Service: name=CRAM-MD5, type=SaslServerFactory
 Provider: name=XMLDSig, version=11, services=13, info=XMLDSig (DOM XMLSignatureFactory; DOM KeyInfoFactory; C14N 1.0, C14N 1.1, Exclusive C14N, Base64, Enveloped, XPath, XPath2, XSLT TransformServices)
  Service: name=http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments, type=TransformService
  Service: name=http://www.w3.org/2000/09/xmldsig#enveloped-signature, type=TransformService
  Service: name=http://www.w3.org/2001/10/xml-exc-c14n#WithComments, type=TransformService
  Service: name=http://www.w3.org/2001/10/xml-exc-c14n#, type=TransformService
  Service: name=http://www.w3.org/2002/06/xmldsig-filter2, type=TransformService
  Service: name=http://www.w3.org/TR/1999/REC-xslt-19991116, type=TransformService
  Service: name=http://www.w3.org/2006/12/xml-c14n11, type=TransformService
  Service: name=http://www.w3.org/TR/1999/REC-xpath-19991116, type=TransformService
  Service: name=DOM, type=KeyInfoFactory
  Service: name=http://www.w3.org/2000/09/xmldsig#base64, type=TransformService
  Service: name=http://www.w3.org/2006/12/xml-c14n11#WithComments, type=TransformService
  Service: name=DOM, type=XMLSignatureFactory
  Service: name=http://www.w3.org/TR/2001/REC-xml-c14n-20010315, type=TransformService
 Provider: name=SunPCSC, version=11, services=1, info=Sun PC/SC provider
  Service: name=PC/SC, type=TerminalFactory
 Provider: name=JdkLDAP, version=11, services=1, info=JdkLDAP Provider (implements LDAP CertStore)
  Service: name=LDAP, type=CertStore
 Provider: name=JdkSASL, version=11, services=2, info=JDK SASL provider(implements client and server mechanisms for GSSAPI)
  Service: name=GSSAPI, type=SaslClientFactory
  Service: name=GSSAPI, type=SaslServerFactory
 Provider: name=Apple, version=11, services=1, info=Apple Provider
  Service: name=KeychainStore, type=KeyStore
 Provider: name=SunPKCS11, version=11, services=0, info=Unconfigured and unusable PKCS11 provider
```
