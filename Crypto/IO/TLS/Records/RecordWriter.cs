using System.IO;

namespace Crypto.IO.TLS
{
    /// <summary>
    /// this handles fragmentation
    /// </summary>
    public class RecordWriter
    {
        private readonly TlsState state;

        public RecordWriter(TlsState state, Stream stream)
        {
            this.state = state;
        }

        public void WriteRecord(Record record)
        {
            state.RecordStrategy.Write(record.Type, record.Version, record.Data);
        }
    }
}