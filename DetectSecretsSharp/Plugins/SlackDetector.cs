using System.Collections.Generic;
using System.Net.Http;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using DetectSecretsSharp.Core;

namespace DetectSecretsSharp.Plugins
{
    /// <summary>
    /// Scans for Slack tokens and webhooks.
    /// </summary>
    public class SlackDetector : RegexBasedDetector
    {
        private static readonly HttpClient _httpClient = new HttpClient();

        public override string SecretType => "Slack Token";

        protected override IEnumerable<Regex> DenyList => new[]
        {
            new Regex(
                @"xox(?:a|b|p|o|s|r)-(?:\d+-)+[a-z0-9]+",
                RegexOptions.Compiled | RegexOptions.IgnoreCase),
            new Regex(
                @"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+",
                RegexOptions.Compiled | RegexOptions.IgnoreCase),
        };

        public override async Task<VerifiedResult> VerifyAsync(string secret)
        {
            try
            {
                if (secret.StartsWith("https://hooks.slack.com/services/T"))
                {
                    var response = await _httpClient.PostAsync(
                        secret,
                        new StringContent("{\"text\":\"\"}", Encoding.UTF8, "application/json"))
                        .ConfigureAwait(false);

                    string responseText = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
                    bool valid = responseText.Contains("missing_text_or_fallback_or_attachments")
                        || responseText.Contains("no_text");

                    return valid ? VerifiedResult.VerifiedTrue : VerifiedResult.VerifiedFalse;
                }
                else
                {
                    var content = new FormUrlEncodedContent(new[]
                    {
                        new KeyValuePair<string, string>("token", secret)
                    });

                    var response = await _httpClient.PostAsync(
                        "https://slack.com/api/auth.test", content)
                        .ConfigureAwait(false);

                    string responseText = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
                    var doc = System.Text.Json.JsonDocument.Parse(responseText);
                    bool valid = doc.RootElement.TryGetProperty("ok", out var okProp) && okProp.GetBoolean();

                    return valid ? VerifiedResult.VerifiedTrue : VerifiedResult.VerifiedFalse;
                }
            }
            catch
            {
                return VerifiedResult.Unverified;
            }
        }
    }
}
