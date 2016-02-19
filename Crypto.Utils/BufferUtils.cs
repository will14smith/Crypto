namespace Crypto.Utils
{
    public static class BufferUtils
    {
        public static void Xor(byte[] input, int inputOffset, byte[] target, int targetOffset, int length)
        {
            SecurityBufferAssert.AssertBuffer(input, inputOffset, length);
            SecurityBufferAssert.AssertBuffer(target, targetOffset, length);

            for (var i = 0; i < length; i++)
            {
                target[targetOffset + i] ^= input[inputOffset + i];
            }
        }
    }
}
