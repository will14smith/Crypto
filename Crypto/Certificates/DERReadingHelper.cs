using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace Crypto.Certificates
{
    internal static class DERReadingHelper
    {
        private static readonly Regex HeaderRegex = new Regex("^-----BEGIN ([A-Z ]*)-----", RegexOptions.Compiled | RegexOptions.Multiline);

        public static Tuple<string, byte[]> TryConvertFromBase64(byte[] input)
        {
            var strInput = Encoding.UTF8.GetString(input).Replace("\r", "").Replace("\n", "");
            var header = HeaderRegex.Match(strInput);
            if (!header.Success)
            {
                return Tuple.Create<string, byte[]>(null, input);
            }

            var title = header.Groups[1].Value;
            var footer = $"-----END {title}-----";
            if (!strInput.EndsWith(footer))
            {
                return Tuple.Create<string, byte[]>(null, input);
            }

            input = Convert.FromBase64String(strInput
                .Replace(header.Value, "")
                .Replace(footer, ""));

            return Tuple.Create(title, input);
        }
    }
}
