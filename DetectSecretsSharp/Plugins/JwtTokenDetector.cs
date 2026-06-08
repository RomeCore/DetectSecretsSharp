using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace DetectSecretsSharp.Plugins
{
    /// <summary>
    /// Scans for JSON Web Tokens (JWTs) and validates their format.
    /// </summary>
    public class JwtTokenDetector : RegexBasedDetector
    {
        public override string SecretType => "JSON Web Token";

        protected override IEnumerable<Regex> DenyList => new[]
        {
            new Regex(
                @"eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*?",
                RegexOptions.Compiled),
        };

        public override IEnumerable<string> AnalyzeString(string str)
        {
            return base.AnalyzeString(str).Where(IsFormallyValid);
        }

        /// <summary>
        /// Validates that the token parts are valid base64-encoded JSON.
        /// </summary>
        private static bool IsFormallyValid(string token)
        {
            var parts = token.Split('.');

            for (int idx = 0; idx < parts.Length; idx++)
            {
                try
                {
                    string partStr = parts[idx];
                    // Normalize base64 padding
                    int m = partStr.Length % 4;
                    if (m == 1)
                        return false; // invalid padding
                    if (m == 2)
                        partStr += "==";
                    else if (m == 3)
                        partStr += "=";

                    var partBytes = Convert.FromBase64String(partStr);

                    // First two parts must be valid JSON
                    if (idx < 2)
                    {
                        var json = Encoding.UTF8.GetString(partBytes);
                        // Try to parse as JSON
                        var doc = System.Text.Json.JsonDocument.Parse(json);
                        doc.Dispose();
                    }
                }
                catch
                {
                    return false;
                }
            }

            return true;
        }
    }
}
