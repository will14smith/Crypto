namespace Crypto.IO.TLS
{
    public enum RecordType : byte
    {
        ChangeCipherSpec = 20,
        Alert = 21,
        Handshake = 22,
        Application = 23,
    }
}
