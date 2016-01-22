using System;
using System.Linq;

namespace Crypto.IO.TLS
{
    internal class DefaultTlsNegotiation : ITlsNegotiation
    {
        public TlsVersion DecideVersion(TlsVersion clientVersion)
        {
            return TlsVersion.TLS1_2;
        }

        public CipherSuite DecideCipherSuite(CipherSuite[] clientCipherSuites)
        {
            var supportedCiphers = (CipherSuite[]) Enum.GetValues(typeof (CipherSuite));
            var cipher = clientCipherSuites.FirstOrDefault(x => supportedCiphers.Contains(x));

            // WARNING: default is TLS_NULL_WITH_NULL_NULL....

            return cipher;
        }

        public CompressionMethod DecideCompression(CompressionMethod[] clientCompressionMethods)
        {
            return CompressionMethod.Null;
        }
    }
}