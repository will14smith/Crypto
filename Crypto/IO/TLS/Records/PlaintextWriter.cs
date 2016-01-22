using System;
using System.IO;

namespace Crypto.IO.TLS
{
    public class PlaintextWriter : RecordWriter
    {
        private const int MaxRecordLength = 0x4000;

        public PlaintextWriter(Stream stream) : base(stream)
        {
        }

        public override void WriteRecord(Record record)
        {
            if (record.Length <= MaxRecordLength)
            {
                Write(record, record.Length, 0);
            }
            else
            {
                var offset = 0;

                // fragment
                while (offset < record.Length)
                {
                    var count = Math.Min(MaxRecordLength, record.Length - offset);
                    Write(record, count, offset);

                    offset += MaxRecordLength;
                }
            }
        }

        private void Write(Record record, int count, int offset)
        {
            Writer.Write(record.Type);
            Writer.Write(record.Version);
            Writer.Write((ushort)count);
            Writer.Write(record.Data, offset, count);
        }
    }
}