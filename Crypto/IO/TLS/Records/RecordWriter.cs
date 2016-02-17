using System;
using System.IO;
using StreamWriter = Crypto.Utils.IO.StreamWriter;

namespace Crypto.IO.TLS
{
    /// <summary>
    /// this handles fragmentation
    /// </summary>
    public class RecordWriter : StreamWriter
    {
        private readonly TlsState state;
        private const int MaxPlainLength = 0x4000;

        public RecordWriter(TlsState state, Stream stream) : base(stream)
        {
            this.state = state;
        }

        public void WriteRecord(Record record)
        {

            var offset = 0;

            // fragment
            while (offset < record.Length)
            {
                var count = Math.Min(MaxPlainLength, record.Length - offset);
                if (state.Protected)
                {
                    WriteCipherText(record, count, offset);
                }
                else
                {
                    WritePlainText(record, count, offset);
                }

                offset += MaxPlainLength;
            }
        }

        private void WriteCipherText(Record record, int count, int offset)
        {
            throw new NotImplementedException();
        }

        private void WritePlainText(Record record, int count, int offset)
        {
            Writer.Write(record.Type);
            Writer.Write(record.Version);
            Writer.Write((ushort)count);
            Writer.Write(record.Data, offset, count);
        }
    }
}