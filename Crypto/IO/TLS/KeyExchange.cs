namespace Crypto.IO.TLS
{
    public enum KeyExchange
    {
        Null = 0,
        RSA,
        DH_DSS,
        DH_RSA,
        DHE_DSS,
        DHE_RSA,
        DH_anon
    }
}
