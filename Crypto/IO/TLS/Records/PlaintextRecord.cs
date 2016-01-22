using Crypto.Utils;

namespace Crypto.IO.TLS
{
    public class PlaintextRecord : Record
    {
        public PlaintextRecord(RecordType type, Version version, ushort length)
            : this(type, version, length, new byte[length])
        {
        }

        public PlaintextRecord(RecordType type, Version version, ushort length, byte[] fragment)
            : base(type, version, length)
        {
            // RFC5246 6.2.1: The record layer fragments information blocks into TLSPlaintext records carrying data in chunks of 2^14 bytes or less
            SecurityAssert.SAssert(length <= 0x4000);

            SecurityAssert.NotNull(fragment);
            SecurityAssert.SAssert(fragment.Length == length);
            Fragment = fragment;
        }

        public byte[] Fragment { get; }
    }
}