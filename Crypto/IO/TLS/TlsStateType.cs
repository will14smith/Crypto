namespace Crypto.IO.TLS
{
    internal enum TlsStateType
    {
        Initial,

        // server
        WaitingForClientHello,
        RecievedClientHello,
        SendingServerHello,
        SentServerHello,
        RecievedClientKeyExchange,

        // client
        SendingClientHello,
        WaitingForServerHello,
    }
}