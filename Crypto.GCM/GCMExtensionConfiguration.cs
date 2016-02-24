using System;
using Crypto.Encryption;
using Crypto.Encryption.Block;
using Crypto.IO.TLS;
using Crypto.IO.TLS.Extensions;

namespace Crypto.GCM
{
    public class GCMExtensionConfiguration : TlsExtensionConfiguration
    {
        public override void Configure(TlsExtensionManager manager)
        {
            RegisterSuites(manager);
        }

        private void RegisterSuites(TlsExtensionManager manager)
        {
            manager.RegisterCipher(GCMCipherAlgorithms.AES_128_GCM, () => new AEADCipherAdapter(new GCMCipher(new AESCipher(128))));
            manager.RegisterCipher(GCMCipherAlgorithms.AES_256_GCM, () => new AEADCipherAdapter(new GCMCipher(new AESCipher(256))));

            manager.RegisterSuite(GCMCipherSuites.TLS_RSA_WITH_AES_128_GCM_SHA256, GCMCipherAlgorithms.AES_128_GCM, TlsHashAlgorithm.SHA256, TlsSignatureAlgorithm.RSA, TlsKeyExchange.RSA);
            manager.RegisterSuite(GCMCipherSuites.TLS_RSA_WITH_AES_256_GCM_SHA384, GCMCipherAlgorithms.AES_256_GCM, TlsHashAlgorithm.SHA384, TlsSignatureAlgorithm.RSA, TlsKeyExchange.RSA);
            manager.RegisterSuite(GCMCipherSuites.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256, GCMCipherAlgorithms.AES_128_GCM, TlsHashAlgorithm.SHA256, TlsSignatureAlgorithm.RSA, TlsKeyExchange.DHE_RSA);
            manager.RegisterSuite(GCMCipherSuites.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384, GCMCipherAlgorithms.AES_256_GCM, TlsHashAlgorithm.SHA384, TlsSignatureAlgorithm.RSA, TlsKeyExchange.DHE_RSA);
            manager.RegisterSuite(GCMCipherSuites.TLS_DH_RSA_WITH_AES_128_GCM_SHA256, GCMCipherAlgorithms.AES_128_GCM, TlsHashAlgorithm.SHA256, TlsSignatureAlgorithm.RSA, TlsKeyExchange.DH_RSA);
            manager.RegisterSuite(GCMCipherSuites.TLS_DH_RSA_WITH_AES_256_GCM_SHA384, GCMCipherAlgorithms.AES_256_GCM, TlsHashAlgorithm.SHA384, TlsSignatureAlgorithm.RSA, TlsKeyExchange.DH_RSA);
            manager.RegisterSuite(GCMCipherSuites.TLS_DHE_DSS_WITH_AES_128_GCM_SHA256, GCMCipherAlgorithms.AES_128_GCM, TlsHashAlgorithm.SHA256, TlsSignatureAlgorithm.DSA, TlsKeyExchange.DHE_DSS);
            manager.RegisterSuite(GCMCipherSuites.TLS_DHE_DSS_WITH_AES_256_GCM_SHA384, GCMCipherAlgorithms.AES_256_GCM, TlsHashAlgorithm.SHA384, TlsSignatureAlgorithm.DSA, TlsKeyExchange.DHE_DSS);
            manager.RegisterSuite(GCMCipherSuites.TLS_DH_DSS_WITH_AES_128_GCM_SHA256, GCMCipherAlgorithms.AES_128_GCM, TlsHashAlgorithm.SHA256, TlsSignatureAlgorithm.DSA, TlsKeyExchange.DH_DSS);
            manager.RegisterSuite(GCMCipherSuites.TLS_DH_DSS_WITH_AES_256_GCM_SHA384, GCMCipherAlgorithms.AES_256_GCM, TlsHashAlgorithm.SHA384, TlsSignatureAlgorithm.DSA, TlsKeyExchange.DH_DSS);
            manager.RegisterSuite(GCMCipherSuites.TLS_DH_anon_WITH_AES_128_GCM_SHA256, GCMCipherAlgorithms.AES_128_GCM, TlsHashAlgorithm.SHA256, TlsSignatureAlgorithm.Anonymous, TlsKeyExchange.DH_anon);
            manager.RegisterSuite(GCMCipherSuites.TLS_DH_anon_WITH_AES_256_GCM_SHA384, GCMCipherAlgorithms.AES_256_GCM, TlsHashAlgorithm.SHA384, TlsSignatureAlgorithm.Anonymous, TlsKeyExchange.DH_anon);
        }
    }
}
