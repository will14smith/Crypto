using System.IO;
using Crypto.Utils;
using Crypto.Utils.IO;

namespace Crypto.IO.TLS
{
    public class RecordReader
    {
        private readonly TlsState state;
        private readonly EndianBinaryReader reader;

        public RecordReader(TlsState state, Stream stream)
        {
            this.state = state;
            reader = new EndianBinaryReader(EndianBitConverter.Big, stream);
        }

        public Record ReadRecord()
        {
            var type = reader.ReadRecordType();
            var version = reader.ReadVersion();
            var length = reader.ReadUInt16();

            return state.RecordStrategy.Read(type, version, length);
        }
    }
}