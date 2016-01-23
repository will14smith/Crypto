namespace Crypto.ASN1
{
    public class ASN1TaggedPrimitive : ASN1Object
    {
        public uint Tag { get; }
        public byte[] Value { get; }

        public ASN1TaggedPrimitive(uint tag, byte[] value)
        {
            Tag = tag;
            Value = value;
        }
    }
}
