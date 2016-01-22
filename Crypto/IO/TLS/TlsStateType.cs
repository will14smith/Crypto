namespace Crypto.IO.TLS
{
    internal enum TlsStateType
    {
        Initial,
        RecievedClientHello,
        SentServerHello,
    }
}