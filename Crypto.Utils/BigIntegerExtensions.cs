using System.Numerics;

namespace Crypto.Utils
{
    public static class BigIntegerExtensions
    {
        public static int GetByteLength(this BigInteger val)
        {
            return val.ToByteArray().Length;
        }
    }
}
