namespace Crypto.IO.TLS.Messages
{
    public enum AlertDescription : byte
    {
        CloseNotify = 0,
        UnexpectedMessage = 10,
        BadRecordMAC = 20,
        DecryptionFailedReserved = 21,
        RecordOverflow = 22,
        DecompressionFailure = 30,
        HandshakeFailure = 40,
        NoCertificateReserved = 41,
        BadCertificate = 42,
        UnsupportedCertificate = 43,
        CertificateRevoked = 44,
        CertificateExpired = 45,
        CertificateUnknown = 46,
        IllegalParameter = 47,
        UnknownCa = 48,
        AccessDenied = 49,
        DecodeError = 50,
        DecryptError = 51,
        ExportRestrictionReserved = 60,
        ProtocolVersion = 70,
        InsufficientSecurity = 71,
        InternalError = 80,
        UserCanceled = 90,
        NoRenegotiation = 100,
        UnsupportedExtension = 110
    }
}