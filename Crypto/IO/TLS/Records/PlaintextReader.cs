using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Crypto.Utils;

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

            SecurityAssert.SAssert(length <= 0x4000);

            var data = Reader.ReadBytes(length);

            return new Record(type, version, data);
        }
    }
}
