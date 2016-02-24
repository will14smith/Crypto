using Crypto.EllipticCurve;
using Crypto.GCM;
using Crypto.IO.TLS;
using Crypto.IO.TLS.Extensions;

namespace Crypto.ECGCM
{
    public class ECGCMExtensionConfiguration : TlsExtensionConfiguration
    {
        public override void Configure(TlsExtensionManager manager)
        {
            manager.RegisterSuite(ECGCMCipherSuites.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, TlsCipherAlgorithm.AES_128_CBC, TlsHashAlgorithm.SHA256, ECSignatureAlgorithm.ECDSA, ECKeyExchange.ECDHE_ECDSA);
            manager.RegisterSuite(ECGCMCipherSuites.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384, TlsCipherAlgorithm.AES_256_CBC, TlsHashAlgorithm.SHA384, ECSignatureAlgorithm.ECDSA, ECKeyExchange.ECDHE_ECDSA);
            manager.RegisterSuite(ECGCMCipherSuites.TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256, TlsCipherAlgorithm.AES_128_CBC, TlsHashAlgorithm.SHA256, ECSignatureAlgorithm.ECDSA, ECKeyExchange.ECDH_ECDSA);
            manager.RegisterSuite(ECGCMCipherSuites.TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384, TlsCipherAlgorithm.AES_256_CBC, TlsHashAlgorithm.SHA384, ECSignatureAlgorithm.ECDSA, ECKeyExchange.ECDH_ECDSA);
            manager.RegisterSuite(ECGCMCipherSuites.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, TlsCipherAlgorithm.AES_128_CBC, TlsHashAlgorithm.SHA256, TlsSignatureAlgorithm.RSA, ECKeyExchange.ECDHE_RSA);
            manager.RegisterSuite(ECGCMCipherSuites.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384, TlsCipherAlgorithm.AES_256_CBC, TlsHashAlgorithm.SHA384, TlsSignatureAlgorithm.RSA, ECKeyExchange.ECDHE_RSA);
            manager.RegisterSuite(ECGCMCipherSuites.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256, TlsCipherAlgorithm.AES_128_CBC, TlsHashAlgorithm.SHA256, TlsSignatureAlgorithm.RSA, ECKeyExchange.ECDH_RSA);
            manager.RegisterSuite(ECGCMCipherSuites.TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384, TlsCipherAlgorithm.AES_256_CBC, TlsHashAlgorithm.SHA384, TlsSignatureAlgorithm.RSA, ECKeyExchange.ECDH_RSA);
            manager.RegisterSuite(ECGCMCipherSuites.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, GCMCipherAlgorithms.AES_128_GCM, TlsHashAlgorithm.SHA256, ECSignatureAlgorithm.ECDSA, ECKeyExchange.ECDHE_ECDSA);
            manager.RegisterSuite(ECGCMCipherSuites.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, GCMCipherAlgorithms.AES_256_GCM, TlsHashAlgorithm.SHA384, ECSignatureAlgorithm.ECDSA, ECKeyExchange.ECDHE_ECDSA);
            manager.RegisterSuite(ECGCMCipherSuites.TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256, GCMCipherAlgorithms.AES_128_GCM, TlsHashAlgorithm.SHA256, ECSignatureAlgorithm.ECDSA, ECKeyExchange.ECDH_ECDSA);
            manager.RegisterSuite(ECGCMCipherSuites.TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384, GCMCipherAlgorithms.AES_256_GCM, TlsHashAlgorithm.SHA384, ECSignatureAlgorithm.ECDSA, ECKeyExchange.ECDH_ECDSA);
            manager.RegisterSuite(ECGCMCipherSuites.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, GCMCipherAlgorithms.AES_128_GCM, TlsHashAlgorithm.SHA256, TlsSignatureAlgorithm.RSA, ECKeyExchange.ECDHE_RSA);
            manager.RegisterSuite(ECGCMCipherSuites.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, GCMCipherAlgorithms.AES_256_GCM, TlsHashAlgorithm.SHA384, TlsSignatureAlgorithm.RSA, ECKeyExchange.ECDHE_RSA);
            manager.RegisterSuite(ECGCMCipherSuites.TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256, GCMCipherAlgorithms.AES_128_GCM, TlsHashAlgorithm.SHA256, TlsSignatureAlgorithm.RSA, ECKeyExchange.ECDH_RSA);
            manager.RegisterSuite(ECGCMCipherSuites.TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384, GCMCipherAlgorithms.AES_256_GCM, TlsHashAlgorithm.SHA384, TlsSignatureAlgorithm.RSA, ECKeyExchange.ECDH_RSA);
        }
    }
}
