using System;
using Crypto.ASN1;

namespace Crypto.Certificates
{
    internal static class ASN1ObjectExtensions
    {
        public static string FromDirectoryString(this ASN1Object asn1)
        {
            //TODO UTF8String
            var utf8 = asn1 as ASN1UTF8String;
            if (utf8 != null)
            {
                return utf8.Value;
            }

            //TODO TeletexString
            //TODO PrintableString
            //TODO UniversalString
            //TODO BMPString

            throw new NotImplementedException();
        }

        public static string FromPrintableString(this ASN1Object asn1)
        {
            throw new NotImplementedException();
        }

        public static DateTimeOffset GetTime(this ASN1Object asn1)
        {
            var utc = asn1 as ASN1UTCTime;
            if (utc != null)
            {
                return utc.Value;
            }

            //TODO GeneralizedTime

            throw new NotImplementedException();
        }
    }
}
