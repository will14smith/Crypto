using System.IO;
using Crypto.Utils;

namespace Crypto.IO.TLS
{
    internal class PlaintextStrategy : RecordStrategy
    {
        public PlaintextStrategy(TlsState state, Stream stream) : base(state, stream)
        {
        }

        public override Record Read(RecordType type, TlsVersion version, ushort length)
        {
            SecurityAssert.SAssert(length <= 0x4000);

            var data = Reader.ReadBytes(length);

            return new Record(type, version, data);
        }

        public override void Write(RecordType type, TlsVersion version, byte[] data)
        {
            Writer.Write(type);
            Writer.Write(version);
            Writer.Write((ushort)data.Length);
            Writer.Write(data, 0, data.Length);

        }
    }
}
