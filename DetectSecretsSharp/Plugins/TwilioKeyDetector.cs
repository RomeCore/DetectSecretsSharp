using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace DetectSecretsSharp.Plugins
{
    /// <summary>
    /// Scans for Twilio API keys.
    /// </summary>
    public class TwilioKeyDetector : RegexBasedDetector
    {
        public override string SecretType => "Twilio API Key";

        protected override IEnumerable<Regex> DenyList => new[]
        {
            // Twilio API credentials: SK... or AC...
            new Regex(
                @"SK[0-9a-fA-F]{32}",
                RegexOptions.Compiled),
        };
    }
}
