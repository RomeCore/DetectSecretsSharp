using System.Collections.Generic;
using System.Net.Http;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using DetectSecretsSharp.Core;

namespace DetectSecretsSharp.Plugins
{
    /// <summary>
    /// Scans for IBM Cloud IAM API keys.
    /// </summary>
    public class IbmCloudIamDetector : RegexBasedDetector
    {
        private static readonly HttpClient _httpClient = new HttpClient();

        public override string SecretType => "IBM Cloud IAM Key";

        private const string OptIbmCloudIam =
            @"(?:ibm(?:_|-|)cloud(?:_|-|)iam|cloud(?:_|-|)iam|" +
            @"ibm(?:_|-|)cloud|ibm(?:_|-|)iam|ibm|iam|cloud|)";

        protected override IEnumerable<Regex> DenyList => new[]
        {
            BuildAssignmentRegex(
                prefixRegex: OptIbmCloudIam + @"(?:_|-|)" + @"(?:api|)",
                secretKeywordRegex: @"(?:key|pwd|password|pass|token)",
                secretRegex: @"([a-zA-Z0-9_\-]{44}(?![a-zA-Z0-9_\-]))"),
        };

        public override async Task<VerifiedResult> VerifyAsync(string secret)
        {
            try
            {
                var content = new FormUrlEncodedContent(new[]
                {
                    new KeyValuePair<string, string>("grant_type", "urn:ibm:params:oauth:grant-type:apikey"),
                    new KeyValuePair<string, string>("apikey", secret),
                });

                var request = new HttpRequestMessage(HttpMethod.Post, "https://iam.cloud.ibm.com/identity/token");
                request.Content = content;
                request.Headers.Add("Accept", "application/json");

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
