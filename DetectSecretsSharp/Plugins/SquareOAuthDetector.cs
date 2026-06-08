using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace DetectSecretsSharp.Plugins
{
    /// <summary>
    /// Scans for Square OAuth secrets.
    /// </summary>
    public class SquareOAuthDetector : RegexBasedDetector
    {
        public override string SecretType => "Square OAuth Secret";

        protected override IEnumerable<Regex> DenyList => new[]
        {
            // Square OAuth secrets start with "sq0csp-" or "sq0acp-"
            new Regex(
                @"sq0[csa]sp-[0-9A-Za-z\-_]{22,44}",
                RegexOptions.Compiled),
        };
    }
}
