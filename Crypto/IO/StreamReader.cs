using System.IO;
using Crypto.Utils;

namespace Crypto.IO
{
    public class StreamReader
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
