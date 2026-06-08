using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace DetectSecretsSharp.Plugins
{
    /// <summary>
    /// Scans for Discord Bot Tokens.
    /// Format: [M|N|O]XXXXXXXXXXXXXXXXXXXXXXX[XX].XXXXXX.XXXXXXXXXXXXXXXXXXXXXXXXXXX
    /// Reference: https://discord.com/developers/docs/reference#authentication
    /// </summary>
    public class DiscordBotTokenDetector : RegexBasedDetector
    {
        public override string SecretType => "Discord Bot Token";

        protected override IEnumerable<Regex> DenyList => new[]
        {
            new Regex(
                @"[MNO][a-zA-Z\d_-]{23,25}\.[a-zA-Z\d_-]{6}\.[a-zA-Z\d_-]{27}",
                RegexOptions.Compiled),
        };
    }
}
