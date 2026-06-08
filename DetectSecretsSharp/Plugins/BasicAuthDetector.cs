using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace DetectSecretsSharp.Plugins
{
    /// <summary>
    /// Scans for Basic Auth formatted URIs (http://user:pass@host/).
    /// </summary>
    public class BasicAuthDetector : RegexBasedDetector
    {
        // Reserved characters from RFC 3986 Section 2.2 that shouldn't appear in credentials
        private const string ReservedCharacters = @":/?#[]@!$&'()*+,;=";

        public override string SecretType => "Basic Auth Credentials";

        protected override IEnumerable<Regex> DenyList
        {
            get
            {
                // Build regex: ://[^reserved\s]+:([^reserved\s]+)@
                string pattern = $"://[{ReservedCharacters}]{{0}}[^{ReservedCharacters}\\s]+" +
                                 $":([^{ReservedCharacters}\\s]+)@";
                // Actually simpler: just match ://anything:anything@
                // We need to exclude reserved chars from user:pass
                string safePattern = @"://[^\:\/\?\#\[\]\@\!\$\&\'\(\)\*\+\,\;\=\s]+" +
                                     @":([^\:\/\?\#\[\]\@\!\$\&\'\(\)\*\+\,\;\=\s]+)@";
                yield return new Regex(safePattern, RegexOptions.Compiled);
            }
        }
    }
}
