using System.IO;

namespace Crypto.IO.TLS
{
    /// <summary>
    /// this handles fragmentation
    /// </summary>
    public abstract class RecordWriter : StreamWriter
    {
        protected RecordWriter(Stream stream) : base(stream) { }

        public abstract void WriteRecord(Record record);
    }
}