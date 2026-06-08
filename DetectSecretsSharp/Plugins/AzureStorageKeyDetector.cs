using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace DetectSecretsSharp.Plugins
{
    /// <summary>
    /// Scans for Azure Storage Account access keys.
    /// </summary>
    public class AzureStorageKeyDetector : RegexBasedDetector
    {
        public override string SecretType => "Azure Storage Account access key";

        protected override IEnumerable<Regex> DenyList => new[]
        {
            // AccountKey=xxxxxxxxx (88 chars)
            new Regex(
                @"AccountKey=[a-zA-Z0-9+\/=]{88}",
                RegexOptions.Compiled),
        };
    }
}
