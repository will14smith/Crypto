using Crypto.Utils;

namespace Crypto.IO.TLS.Messages
{
    public class AlertMessage : Message
    {
        private static readonly AlertLevel[] AllowedDescLevels;

        static AlertMessage()
        {
            AllowedDescLevels = new AlertLevel[255];

            AllowedDescLevels[(int)AlertDescription.CloseNotify] = AlertLevel.Warning | AlertLevel.Fatal;
            AllowedDescLevels[(int)AlertDescription.UnexpectedMessage] = AlertLevel.Fatal;
            AllowedDescLevels[(int)AlertDescription.BadRecordMAC] = AlertLevel.Fatal;
            AllowedDescLevels[(int)AlertDescription.DecryptionFailedReserved] = AlertLevel.Fatal;
            AllowedDescLevels[(int)AlertDescription.RecordOverflow] = AlertLevel.Fatal;
            AllowedDescLevels[(int)AlertDescription.DecompressionFailure] = AlertLevel.Fatal;
            AllowedDescLevels[(int)AlertDescription.HandshakeFailure] = AlertLevel.Fatal;
            AllowedDescLevels[(int)AlertDescription.NoCertificateReserved] = AlertLevel.Warning | AlertLevel.Fatal;
            AllowedDescLevels[(int)AlertDescription.BadCertificate] = AlertLevel.Warning | AlertLevel.Fatal;
            AllowedDescLevels[(int)AlertDescription.UnsupportedCertificate] = AlertLevel.Warning | AlertLevel.Fatal;
            AllowedDescLevels[(int)AlertDescription.CertificateRevoked] = AlertLevel.Warning | AlertLevel.Fatal;
            AllowedDescLevels[(int)AlertDescription.CertificateExpired] = AlertLevel.Warning | AlertLevel.Fatal;
            AllowedDescLevels[(int)AlertDescription.CertificateUnknown] = AlertLevel.Warning | AlertLevel.Fatal;
            AllowedDescLevels[(int)AlertDescription.IllegalParameter] = AlertLevel.Fatal;
            AllowedDescLevels[(int)AlertDescription.UnknownCa] = AlertLevel.Fatal;
            AllowedDescLevels[(int)AlertDescription.AccessDenied] = AlertLevel.Fatal;
            AllowedDescLevels[(int)AlertDescription.DecodeError] = AlertLevel.Fatal;
            AllowedDescLevels[(int)AlertDescription.DecryptError] = AlertLevel.Warning | AlertLevel.Fatal;
            AllowedDescLevels[(int)AlertDescription.ExportRestrictionReserved] = AlertLevel.Fatal;
            AllowedDescLevels[(int)AlertDescription.ProtocolVersion] = AlertLevel.Fatal;
            AllowedDescLevels[(int)AlertDescription.InsufficientSecurity] = AlertLevel.Fatal;
            AllowedDescLevels[(int)AlertDescription.InternalError] = AlertLevel.Fatal;
            AllowedDescLevels[(int)AlertDescription.UserCanceled] = AlertLevel.Fatal;
            AllowedDescLevels[(int)AlertDescription.NoRenegotiation] = AlertLevel.Warning;
            AllowedDescLevels[(int)AlertDescription.UnsupportedExtension] = AlertLevel.Warning;
        }

        public AlertMessage(AlertLevel level, AlertDescription description)
        {
            SecurityAssert.SAssert((AllowedDescLevels[(int)description] & level) != 0);

            Level = level;
            Description = description;
        }

        public AlertLevel Level { get; }
        public AlertDescription Description { get; }

        internal static AlertMessage Read(byte[] data)
        {
            return new AlertMessage((AlertLevel)data[0], (AlertDescription)data[1]);
        }

        internal byte[] GetBytes()
        {
            return new byte[] { (byte)Level, (byte)Description };
        }
    }
}
