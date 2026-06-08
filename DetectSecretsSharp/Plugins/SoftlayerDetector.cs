using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using DetectSecretsSharp.Core;
using DetectSecretsSharp.Util;

namespace DetectSecretsSharp.Plugins
{
    /// <summary>
    /// Scans for Softlayer credentials.
    /// </summary>
    public class SoftlayerDetector : RegexBasedDetector
    {
        private static readonly HttpClient _httpClient = new HttpClient();

        public override string SecretType => "SoftLayer Credentials";

        private const string Sl = @"(?:softlayer|sl)(?:_|-|)(?:api|)";

        protected override IEnumerable<Regex> DenyList => new[]
        {
            BuildAssignmentRegex(
                prefixRegex: Sl,
                secretKeywordRegex: @"(?:key|pwd|password|pass|token)",
                secretRegex: @"([a-z0-9]{64})"),
            new Regex(
                @"(?:http|https)://api.softlayer.com/soap/(?:v3|v3.1)/([a-z0-9]{64})",
                RegexOptions.Compiled | RegexOptions.IgnoreCase),
        };

        public override async Task<VerifiedResult> VerifyAsync(string secret, CodeSnippet context)
        {
            if (context == null)
                return VerifiedResult.Unverified;

            var usernames = FindUsername(context);
            if (usernames.Count == 0)
                return VerifiedResult.Unverified;

            foreach (var username in usernames)
            {
                return await VerifySoftlayerKeyAsync(username, secret).ConfigureAwait(false);
            }

            return VerifiedResult.VerifiedFalse;
        }

        private static List<string> FindUsername(CodeSnippet context)
        {
            const string usernameKeyword =
                @"(?:username|id|user|userid|user-id|user-name|" +
                @"name|user_id|user_name|uname)";
            const string username = @"(\w(?:\w|_|@|\.|-)+)";

            var regex = BuildAssignmentRegex(
                prefixRegex: Sl,
                secretKeywordRegex: usernameKeyword,
                secretRegex: username);

            var results = new List<string>();
            foreach (var line in context.Lines)
            {
                results.AddRange(
                    regex.Matches(line)
                        .Cast<Match>()
                        .Select(m => m.Value));
            }

            return results;
        }

        private static async Task<VerifiedResult> VerifySoftlayerKeyAsync(string username, string token)
        {
            try
            {
                var request = new HttpRequestMessage(
                    HttpMethod.Get,
                    "https://api.softlayer.com/rest/v3/SoftLayer_Account.json");

                var authBytes = Encoding.UTF8.GetBytes($"{username}:{token}");
                request.Headers.Authorization =
                    new System.Net.Http.Headers.AuthenticationHeaderValue(
                        "Basic", Convert.ToBase64String(authBytes));
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
