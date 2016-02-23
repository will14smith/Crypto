using System;
using Crypto.Encryption;
using Crypto.Encryption.Block;
using Crypto.Hashing;
using Crypto.IO.TLS;

namespace Crypto.GCM
{
    public class GCMExtension : TlsExtension
    {
        public override void Init(TlsExtensionManager manager)
        {
            RegisterSuites(manager);
        }

        private void RegisterSuites(TlsExtensionManager manager)
        {
            Func<ICipher> aes128 = () => new AEADCipherAdapter(new GCMCipher(new AESCipher(128)));
            Func<ICipher> aes256 = () => new AEADCipherAdapter(new GCMCipher(new AESCipher(256)));

            Func<IDigest> sha256 = () => new SHA256Digest();
            Func<IDigest> sha384 = () => { throw new NotImplementedException(); };

            Func<ISignatureCipher> rsa = () => new RSA();
            Func<ISignatureCipher> dsa = () => { throw new NotImplementedException(); };
            Func<ISignatureCipher> inv = () => { throw new InvalidOperationException(); };

            Func<IKeyExchange> rsaKE = () => new RSAKeyExchange();
            Func<IKeyExchange> dheRsa = () => new DHEKeyExchange(new RSAKeyExchange());
            Func<IKeyExchange> dhRsa = () => new DHKeyExchange(new RSAKeyExchange());
            Func<IKeyExchange> dheDss = () => { throw new NotImplementedException(); };
            Func<IKeyExchange> dhDss = () => { throw new NotImplementedException(); };
            Func<IKeyExchange> dhAnon = () => { throw new NotImplementedException(); };

            manager.RegisterSuite(GCMCipherSuites.TLS_RSA_WITH_AES_128_GCM_SHA256, aes128, sha256, rsa, rsaKE);
            manager.RegisterSuite(GCMCipherSuites.TLS_RSA_WITH_AES_256_GCM_SHA384, aes256, sha384, rsa, rsaKE);
            manager.RegisterSuite(GCMCipherSuites.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256, aes128, sha256, rsa, dheRsa);
            manager.RegisterSuite(GCMCipherSuites.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384, aes256, sha384, rsa, dheRsa);
            manager.RegisterSuite(GCMCipherSuites.TLS_DH_RSA_WITH_AES_128_GCM_SHA256, aes128, sha256, rsa, dhRsa);
            manager.RegisterSuite(GCMCipherSuites.TLS_DH_RSA_WITH_AES_256_GCM_SHA384, aes256, sha384, rsa, dhRsa);
            manager.RegisterSuite(GCMCipherSuites.TLS_DHE_DSS_WITH_AES_128_GCM_SHA256, aes128, sha256, dsa, dheDss);
            manager.RegisterSuite(GCMCipherSuites.TLS_DHE_DSS_WITH_AES_256_GCM_SHA384, aes256, sha384, dsa, dheDss);
            manager.RegisterSuite(GCMCipherSuites.TLS_DH_DSS_WITH_AES_128_GCM_SHA256, aes128, sha256, dsa, dhDss);
            manager.RegisterSuite(GCMCipherSuites.TLS_DH_DSS_WITH_AES_256_GCM_SHA384, aes256, sha384, dsa, dhDss);
            manager.RegisterSuite(GCMCipherSuites.TLS_DH_anon_WITH_AES_128_GCM_SHA256, aes128, sha256, inv, dhAnon);
            manager.RegisterSuite(GCMCipherSuites.TLS_DH_anon_WITH_AES_256_GCM_SHA384, aes256, sha384, inv, dhAnon);
        }
    }
}
