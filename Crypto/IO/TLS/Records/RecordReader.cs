using System;
using System.IO;
using Crypto.Utils;
using StreamReader = Crypto.Utils.IO.StreamReader;

namespace Crypto.IO.TLS
{
    public class RecordReader : StreamReader
    {
        private readonly TlsState state;

        public RecordReader(TlsState state, Stream stream) : base(stream)
        {
            this.state = state;
        }

        public Record ReadRecord()
        {
            return state.Protected ? ReadCipherText() : ReadPlainText();
        }

        private Record ReadCipherText()
        {
            var type = Reader.ReadRecordType();
            var version = Reader.ReadVersion();
            var length = Reader.ReadUInt16();

            throw new NotImplementedException();
        }

        private Record ReadPlainText()
        {
            var type = Reader.ReadRecordType();
            var version = Reader.ReadVersion();
            var length = Reader.ReadUInt16();

            SecurityAssert.SAssert(length <= 0x4000);

            var data = Reader.ReadBytes(length);

            return new Record(type, version, data);
        }
    }
}