using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Crypto.IO.TLS
{
    public class PlaintextReader : RecordReader
    {
        public PlaintextReader(Stream stream) : base(stream)
        {
        }

        public override Record ReadRecord()
        {
            var type = Reader.ReadRecordType();
            var version = Reader.ReadVersion();
            var length = Reader.ReadUInt16();

            var data = Reader.ReadBytes(length);

            return new PlaintextRecord(type, version, length, data);
        }
    }
}
