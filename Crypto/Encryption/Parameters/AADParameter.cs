namespace Crypto.Encryption.Parameters
{
    public class AADParameter : ICipherParameters
    {
        public AADParameter(ICipherParameters parameters, byte[] aad)
        {
            Parameters = parameters;
            AAD = aad;
        }

        public byte[] AAD { get; }
        public ICipherParameters Parameters { get; }
    }
}
