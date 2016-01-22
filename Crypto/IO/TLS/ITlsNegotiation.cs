namespace Crypto.IO.TLS
{
    public interface ITlsNegotiation
    {
        TlsVersion DecideVersion(TlsVersion clientVersion);
        CipherSuite DecideCipherSuite(CipherSuite[] clientCipherSuites);
        CompressionMethod DecideCompression(CompressionMethod[] clientCompressionMethods);
    }
}
