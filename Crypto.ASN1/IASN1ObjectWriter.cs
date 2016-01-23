namespace Crypto.ASN1
{
    internal interface IASN1ObjectWriter
    {
        void Write(ASN1BitString value);
        void Write(ASN1Boolean value);
        void Write(ASN1Integer value);
        void Write(ASN1Null value);
        void Write(ASN1ObjectIdentifier value);
        void Write(ASN1OctetString value);
        void Write(ASN1Sequence value);
        void Write(ASN1Set value);
        void Write(ASN1Tagged value);
        void Write(ASN1TaggedPrimitive value);
        void Write(ASN1UTCTime value);
        void Write(ASN1UTF8String value);
    }
}
