using System.IO;

namespace Crypto.IO.TLS
{
    public abstract class RecordReader : StreamReader
    {
        protected RecordReader(Stream stream) : base(stream) { }

        public abstract Record ReadRecord();
    }
}