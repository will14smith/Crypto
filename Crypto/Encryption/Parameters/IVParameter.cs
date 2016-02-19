namespace Crypto.Encryption.Parameters
{
    public class IVParameter : ICipherParameters
    {
        public IVParameter(ICipherParameters parameters, byte[] iv)
        {
            IV = iv;
            Parameters = parameters;
        }

        public byte[] IV { get; }
        public ICipherParameters Parameters { get; }
    }
}