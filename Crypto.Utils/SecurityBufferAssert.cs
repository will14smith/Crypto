using JetBrains.Annotations;

namespace Crypto.Utils
{
    public static class SecurityBufferAssert
    {
        [AssertionMethod]
        public static void AssertBuffer(byte[] buffer, int offset, int length)
        {
            SecurityAssert.NotNull(buffer);
            SecurityAssert.SAssert(offset >= 0);
            SecurityAssert.SAssert(length >= 0);
            SecurityAssert.SAssert(offset + length <= buffer.Length);
        }
    }
}
