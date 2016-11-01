using Crypto.ASN1;
using Crypto.EllipticCurve.Algorithms;
using Crypto.IO.TLS;
using Crypto.IO.TLS.Extensions;

namespace Crypto.EllipticCurve
{
    public class ECExtensionConfiguration : TlsExtensionConfiguration
    {
        public static readonly ASN1ObjectIdentifier IdEcPublicKey = new ASN1ObjectIdentifier("1.2.840.10045.2.1");


        public override void Configure(TlsExtensionManager manager)
        {
            manager.RegisterPublicKeyReader(IdEcPublicKey, () => new ECKeyReader());

            manager.RegisterHelloExtension(SupportedGroupsExtension.HelloType, (state, data) => new SupportedGroupsExtension(state, data));
            manager.RegisterHelloExtension(SupportedPointFormatsExtension.HelloType, (state, data) => new SupportedPointFormatsExtension(state, data));

            manager.RegisterSignature(ECSignatureAlgorithm.ECDSA, () => new ECDSA());

            manager.RegisterKeyExchange(ECKeyExchange.ECDH_RSA, () => new ECDHKeyExchange());
            manager.RegisterKeyExchange(ECKeyExchange.ECDHE_RSA, () => new ECDHEKeyExchange());
            manager.RegisterKeyExchange(ECKeyExchange.ECDH_ECDSA, () => new ECDHKeyExchange());
            manager.RegisterKeyExchange(ECKeyExchange.ECDHE_ECDSA, () => new ECDHEKeyExchange());

            manager.RegisterSuite(ECCipherSuites.TLS_ECDH_ECDSA_WITH_NULL_SHA, TlsCipherAlgorithm.Null, TlsHashAlgorithm.SHA1, ECSignatureAlgorithm.ECDSA, ECKeyExchange.ECDH_ECDSA);
            manager.RegisterSuite(ECCipherSuites.TLS_ECDH_ECDSA_WITH_RC4_128_SHA, TlsCipherAlgorithm.RC4_128, TlsHashAlgorithm.SHA1, ECSignatureAlgorithm.ECDSA, ECKeyExchange.ECDH_ECDSA);
            manager.RegisterSuite(ECCipherSuites.TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA, TlsCipherAlgorithm.THREEDES_EDE_CBC, TlsHashAlgorithm.SHA1, ECSignatureAlgorithm.ECDSA, ECKeyExchange.ECDH_ECDSA);
            manager.RegisterSuite(ECCipherSuites.TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA, TlsCipherAlgorithm.AES_128_CBC, TlsHashAlgorithm.SHA1, ECSignatureAlgorithm.ECDSA, ECKeyExchange.ECDH_ECDSA);
            manager.RegisterSuite(ECCipherSuites.TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA, TlsCipherAlgorithm.AES_256_CBC, TlsHashAlgorithm.SHA1, ECSignatureAlgorithm.ECDSA, ECKeyExchange.ECDH_ECDSA);

            manager.RegisterSuite(ECCipherSuites.TLS_ECDHE_ECDSA_WITH_NULL_SHA, TlsCipherAlgorithm.Null, TlsHashAlgorithm.SHA1, ECSignatureAlgorithm.ECDSA, ECKeyExchange.ECDHE_ECDSA);
            manager.RegisterSuite(ECCipherSuites.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA, TlsCipherAlgorithm.RC4_128, TlsHashAlgorithm.SHA1, ECSignatureAlgorithm.ECDSA, ECKeyExchange.ECDHE_ECDSA);
            manager.RegisterSuite(ECCipherSuites.TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA, TlsCipherAlgorithm.THREEDES_EDE_CBC, TlsHashAlgorithm.SHA1, ECSignatureAlgorithm.ECDSA, ECKeyExchange.ECDHE_ECDSA);
            manager.RegisterSuite(ECCipherSuites.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, TlsCipherAlgorithm.AES_128_CBC, TlsHashAlgorithm.SHA1, ECSignatureAlgorithm.ECDSA, ECKeyExchange.ECDHE_ECDSA);
            manager.RegisterSuite(ECCipherSuites.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, TlsCipherAlgorithm.AES_256_CBC, TlsHashAlgorithm.SHA1, ECSignatureAlgorithm.ECDSA, ECKeyExchange.ECDHE_ECDSA);

            manager.RegisterSuite(ECCipherSuites.TLS_ECDH_RSA_WITH_NULL_SHA, TlsCipherAlgorithm.Null, TlsHashAlgorithm.SHA1, TlsSignatureAlgorithm.RSA, ECKeyExchange.ECDH_RSA);
            manager.RegisterSuite(ECCipherSuites.TLS_ECDH_RSA_WITH_RC4_128_SHA, TlsCipherAlgorithm.RC4_128, TlsHashAlgorithm.SHA1, TlsSignatureAlgorithm.RSA, ECKeyExchange.ECDH_RSA);
            manager.RegisterSuite(ECCipherSuites.TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA, TlsCipherAlgorithm.THREEDES_EDE_CBC, TlsHashAlgorithm.SHA1, TlsSignatureAlgorithm.RSA, ECKeyExchange.ECDH_RSA);
            manager.RegisterSuite(ECCipherSuites.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA, TlsCipherAlgorithm.AES_128_CBC, TlsHashAlgorithm.SHA1, TlsSignatureAlgorithm.RSA, ECKeyExchange.ECDH_RSA);
            manager.RegisterSuite(ECCipherSuites.TLS_ECDH_RSA_WITH_AES_256_CBC_SHA, TlsCipherAlgorithm.AES_256_CBC, TlsHashAlgorithm.SHA1, TlsSignatureAlgorithm.RSA, ECKeyExchange.ECDH_RSA);

            manager.RegisterSuite(ECCipherSuites.TLS_ECDHE_RSA_WITH_NULL_SHA, TlsCipherAlgorithm.Null, TlsHashAlgorithm.SHA1, TlsSignatureAlgorithm.RSA, ECKeyExchange.ECDHE_RSA);
            manager.RegisterSuite(ECCipherSuites.TLS_ECDHE_RSA_WITH_RC4_128_SHA, TlsCipherAlgorithm.RC4_128, TlsHashAlgorithm.SHA1, TlsSignatureAlgorithm.RSA, ECKeyExchange.ECDHE_RSA);
            manager.RegisterSuite(ECCipherSuites.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA, TlsCipherAlgorithm.THREEDES_EDE_CBC, TlsHashAlgorithm.SHA1, TlsSignatureAlgorithm.RSA, ECKeyExchange.ECDHE_RSA);
            manager.RegisterSuite(ECCipherSuites.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, TlsCipherAlgorithm.AES_128_CBC, TlsHashAlgorithm.SHA1, TlsSignatureAlgorithm.RSA, ECKeyExchange.ECDHE_RSA);
            manager.RegisterSuite(ECCipherSuites.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, TlsCipherAlgorithm.AES_256_CBC, TlsHashAlgorithm.SHA1, TlsSignatureAlgorithm.RSA, ECKeyExchange.ECDHE_RSA);

            manager.RegisterSuite(ECCipherSuites.TLS_ECDH_anon_WITH_NULL_SHA, TlsCipherAlgorithm.Null, TlsHashAlgorithm.SHA1, TlsSignatureAlgorithm.Anonymous, ECKeyExchange.ECDH_anon);
            manager.RegisterSuite(ECCipherSuites.TLS_ECDH_anon_WITH_RC4_128_SHA, TlsCipherAlgorithm.RC4_128, TlsHashAlgorithm.SHA1, TlsSignatureAlgorithm.Anonymous, ECKeyExchange.ECDH_anon);
            manager.RegisterSuite(ECCipherSuites.TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA, TlsCipherAlgorithm.THREEDES_EDE_CBC, TlsHashAlgorithm.SHA1, TlsSignatureAlgorithm.Anonymous, ECKeyExchange.ECDH_anon);
            manager.RegisterSuite(ECCipherSuites.TLS_ECDH_anon_WITH_AES_128_CBC_SHA, TlsCipherAlgorithm.AES_128_CBC, TlsHashAlgorithm.SHA1, TlsSignatureAlgorithm.Anonymous, ECKeyExchange.ECDH_anon);
            manager.RegisterSuite(ECCipherSuites.TLS_ECDH_anon_WITH_AES_256_CBC_SHA, TlsCipherAlgorithm.AES_256_CBC, TlsHashAlgorithm.SHA1, TlsSignatureAlgorithm.Anonymous, ECKeyExchange.ECDH_anon);
        }
    }
}
