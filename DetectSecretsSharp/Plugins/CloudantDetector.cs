using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using DetectSecretsSharp.Core;
using DetectSecretsSharp.Util;

namespace DetectSecretsSharp.Plugins
{
    /// <summary>
    /// Scans for Cloudant credentials (passwords and API keys).
    /// </summary>
    public class CloudantDetector : RegexBasedDetector
    {
        private static readonly HttpClient _httpClient = new HttpClient();

        public override string SecretType => "Cloudant Credentials";

        private const string Cl = @"(?:cloudant|cl|clou)";
        private const string ClAccount = @"[\w\-]+";
        private const string ClPassword = @"([0-9a-f]{64})";
        private const string ClApiKey = @"([a-z]{24})";

        protected override IEnumerable<Regex> DenyList => new[]
        {
            BuildAssignmentRegex(
                prefixRegex: Cl,
                secretKeywordRegex: @"(?:api|)(?:key|pwd|pw|password|pass|token)",
                secretRegex: ClPassword),
            BuildAssignmentRegex(
                prefixRegex: Cl,
                secretKeywordRegex: @"(?:api|)(?:key|pwd|pw|password|pass|token)",
                secretRegex: ClApiKey),
            new Regex(
                @"(?:https?\:\/\/)" + ClAccount + @"\:" + ClPassword + @"\@" + ClAccount + @"\.cloudant\.com",
                RegexOptions.Compiled | RegexOptions.IgnoreCase),
            new Regex(
                @"(?:https?\:\/\/)" + ClAccount + @"\:" + ClApiKey + @"\@" + ClAccount + @"\.cloudant\.com",
                RegexOptions.Compiled | RegexOptions.IgnoreCase),
        };

        public override async Task<VerifiedResult> VerifyAsync(string secret, CodeSnippet context)
        {
            if (context == null)
                return VerifiedResult.Unverified;

            var hosts = FindAccount(context);
            if (hosts.Count == 0)
                return VerifiedResult.Unverified;

            foreach (var host in hosts)
            {
                return await VerifyCloudantKeyAsync(host, secret).ConfigureAwait(false);
            }

            return VerifiedResult.VerifiedFalse;
        }

        private static List<string> FindAccount(CodeSnippet context)
        {
            const string optHostnameKeyword =
                @"(?:hostname|host|username|id|user|userid|user-id|user-name|" +
                @"name|user_id|user_name|uname|account)";
            const string account = @"(\w[\w\-]*)";
            const string optBasicAuth = @"(?:[\w\-:%]*\@)?";

            var regexes = new[]
            {
                BuildAssignmentRegex(
                    prefixRegex: Cl,
                    secretKeywordRegex: optHostnameKeyword,
                    secretRegex: account),
                new Regex(
                    @"(?:https?\:\/\/)" + optBasicAuth + account + @"\.cloudant\.com",
                    RegexOptions.Compiled | RegexOptions.IgnoreCase),
            };

            var results = new List<string>();
            foreach (var line in context.Lines)
            {
                foreach (var regex in regexes)
                {
                    results.AddRange(
                        regex.Matches(line)
                            .Cast<Match>()
                            .Select(m => m.Value));
                }
            }

            return results;
        }

        private static async Task<VerifiedResult> VerifyCloudantKeyAsync(string hostname, string token)
        {
            try
            {
                var requestUrl = $"https://{hostname}:{token}@{hostname}.cloudant.com";
                var request = new HttpRequestMessage(HttpMethod.Get, requestUrl);
                request.Headers.Add("Content-type", "application/json");

                var response = await _httpClient.SendAsync(request).ConfigureAwait(false);
                return response.StatusCode == System.Net.HttpStatusCode.OK
                    ? VerifiedResult.VerifiedTrue
                    : VerifiedResult.VerifiedFalse;
            }
            catch
            {
                return VerifiedResult.Unverified;
            }
        }
    }
}
