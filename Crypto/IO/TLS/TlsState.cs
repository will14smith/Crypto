using System.IO;

namespace Crypto.IO.TLS
{
    internal class TlsState
    {
        private readonly Stream stream;

        public TlsState(Stream stream)
        {
            this.stream = stream;
        }

        #region records
        public RecordReader GetRecordReader()
        {
            return new PlaintextReader(stream);
        }
        #endregion

        #region stream
        public void Flush()
        {
            stream.Flush();
        }
        #endregion
    }
}
