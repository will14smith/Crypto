namespace Crypto.IO.TLS
{
    public enum TlsKeyExchange
    {
        Null = 0,
        RSA = 1,
        DH_DSS = 2,
        DH_RSA = 3,
        DHE_DSS = 4,
        DHE_RSA = 5,
        DH_anon = 6
    }
}
