namespace Crypto.Encryption.Modes
{
    public interface IBlockMode
    {
        void Init(IBlockCipher cipher);

        byte[] IV { get; set; }

        void BeforeEncryption(byte[] input, int offset);
        void AfterEncryption(byte[] input, int offset);

        void BeforeDecryption(byte[] input, int offset);
        void AfterDecryption(byte[] input, int offset);
    }
}
