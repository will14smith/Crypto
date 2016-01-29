using System.Numerics;

namespace Crypto.Utils
{
    public static class HashCodeHelper
    {
        public static int ToInt(BigInteger val)
        {
            var result = 0u;

            while (val != 0)
            {
                result ^= (uint)(val & 0xffffffff);
                val >>= 32;
            }

            return (int) result;
        }
    }
}
