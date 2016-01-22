using System.IO;

namespace Crypto.Utils.IO
{
    public abstract class StreamWriter
    {
        protected readonly Stream Stream;
        protected readonly EndianBinaryWriter Writer;

        protected StreamWriter(Stream stream)
        {
            Stream = stream;
            Writer = new EndianBinaryWriter(EndianBitConverter.Big, stream);
        }
    }
}