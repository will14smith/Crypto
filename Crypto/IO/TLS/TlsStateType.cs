namespace Crypto.IO.TLS
{
    internal enum TlsStateType
    {
        Initial,
        Active,
        
        // server
        WaitingForClientHello,
        RecievedClientHello,
        SendingServerHello,
        SentServerHello,
        RecievedClientKeyExchange,
        WaitingForClientFinished,

        // client
        SendingClientHello,
        WaitingForServerHello
    }
}