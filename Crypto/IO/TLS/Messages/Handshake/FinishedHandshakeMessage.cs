using System;
using Crypto.Utils;
using Crypto.Utils.IO;

namespace Crypto.IO.TLS.Messages
{
    public class FinishedHandshakeMessage : HandshakeMessage
    {
        public const int VerifyDataLength = 12; // could in theory not be 12...


        public byte[] VerifyData { get; }

        public FinishedHandshakeMessage(byte[] verifyData) : base(HandshakeType.Finished)
        {
            SecurityAssert.NotNull(verifyData);
            SecurityAssert.SAssert(verifyData.Length == VerifyDataLength);

            VerifyData = verifyData;
        }

        protected override void Write(EndianBinaryWriter writer)
        {
            writer.Write(VerifyData);
        }

        public static HandshakeMessage Read(TlsState state, byte[] body)
        {
            var verifyData = new byte[VerifyDataLength];

            SecurityAssert.SAssert(body.Length == VerifyDataLength);

            Array.Copy(body, verifyData, VerifyDataLength);

            return new FinishedHandshakeMessage(verifyData);
        }
    }
}
