using System.IO;
using Crypto.Utils;
using Crypto.Utils.IO;

namespace Crypto.IO.TLS
{
    internal interface IRecordStrategy
    {
        Record Read(RecordType type, TlsVersion version, ushort length);
        void Write(RecordType type, TlsVersion version, byte[] data);
    }

    internal abstract class RecordStrategy : IRecordStrategy
    {
        protected readonly TlsState State;
        protected readonly EndianBinaryReader Reader;
        protected readonly EndianBinaryWriter Writer;

        protected RecordStrategy(TlsState state, Stream stream)
        {
            State = state;

            if (stream != null)
            {
                Reader = new EndianBinaryReader(EndianBitConverter.Big, stream);
                Writer = new EndianBinaryWriter(EndianBitConverter.Big, stream);
            }
        }

        public abstract Record Read(RecordType type, TlsVersion version, ushort length);
        public abstract void Write(RecordType type, TlsVersion version, byte[] data);
    }
}
