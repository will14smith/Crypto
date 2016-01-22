using Crypto.Utils;

namespace Crypto.IO.TLS
{
    public abstract class CiphertextRecord : Record
    {
        protected CiphertextRecord(RecordType type, Version version, ushort length) : base(type, version, length)
        {
            // RFC5246 6.2.3
            SecurityAssert.SAssert(length <= 0x4400);
        }
    }
}