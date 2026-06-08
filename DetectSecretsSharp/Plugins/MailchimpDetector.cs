using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using DetectSecretsSharp.Core;

namespace DetectSecretsSharp.Plugins
{
    /// <summary>
    /// Scans for Mailchimp API keys (32 lowercase hex + -usXX).
    /// </summary>
    public class MailchimpDetector : RegexBasedDetector
    {
        private static readonly HttpClient _httpClient = new HttpClient();

        public override string SecretType => "Mailchimp Access Key";

        protected override IEnumerable<Regex> DenyList => new[]
        {
            new Regex(
                @"[0-9a-z]{32}-us[0-9]{1,2}",
                RegexOptions.Compiled),
        };

        public override async Task<VerifiedResult> VerifyAsync(string secret)
        {
            try
            {
                var parts = secret.Split(new[] { "-us" }, StringSplitOptions.None);
                if (parts.Length != 2)
                    return VerifiedResult.Unverified;

                var datacenter = parts[1];
                var request = new HttpRequestMessage(
                    HttpMethod.Get,
                    $"https://us{datacenter}.api.mailchimp.com/3.0/");

                var authBytes = Encoding.UTF8.GetBytes($"any_user:{secret}");
                request.Headers.Authorization =
                    new System.Net.Http.Headers.AuthenticationHeaderValue(
                        "Basic", System.Convert.ToBase64String(authBytes));

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
