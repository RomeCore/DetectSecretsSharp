using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace DetectSecretsSharp.Plugins
{
    /// <summary>
    /// Scans for SendGrid API tokens.
    /// </summary>
    public class SendGridDetector : RegexBasedDetector
    {
        public override string SecretType => "SendGrid API Token";

        protected override IEnumerable<Regex> DenyList => new[]
        {
            // SendGrid API tokens start with "SG." followed by base64
            new Regex(
                @"SG\.[a-zA-Z0-9_\-+=]{68}",
                RegexOptions.Compiled),
        };
    }
}
