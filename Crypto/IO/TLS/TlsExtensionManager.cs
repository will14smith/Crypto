using System;
using Crypto.Encryption;
using Crypto.Hashing;
using Crypto.Utils;

namespace Crypto.IO.TLS
{
    public class TlsExtensionManager
    {
        public void RegisterSuite<T>(T cipherSuite, Func<ICipher> cipher, Func<IDigest> digest,
            Func<ISignatureCipher> signature, Func<IKeyExchange> exchange)
            where T : struct
        {
            SecurityAssert.SAssert(typeof(T).IsEnum);

            // yay...
            var x = (CipherSuite) (ushort) (int) (ValueType) cipherSuite;

            RegisterSuite(x, cipher, digest, signature, exchange);
        }

        public void RegisterSuite(CipherSuite cipherSuite, Func<ICipher> cipher, Func<IDigest> digest, Func<ISignatureCipher> signature, Func<IKeyExchange> exchange)
        {
            CipherSuiteExtensions.RegisterSuite(cipherSuite, cipher, digest, signature, exchange);
        }
    }
}