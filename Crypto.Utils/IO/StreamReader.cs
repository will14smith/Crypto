using System.IO;

namespace Crypto.Utils.IO
{
    public abstract class StreamReader
    {
        protected readonly Stream Stream;
        protected readonly EndianBinaryReader Reader;

        protected StreamReader(Stream stream)
        {
            Stream = stream;
            Reader = new EndianBinaryReader(EndianBitConverter.Big, stream);
        }
    }
}
