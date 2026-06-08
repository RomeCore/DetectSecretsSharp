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
    /// Scans for Stripe API keys (sk_live_ and rk_live_).
    /// </summary>
    public class StripeDetector : RegexBasedDetector
    {
        private static readonly HttpClient _httpClient = new HttpClient();

        public override string SecretType => "Stripe Access Key";

        protected override IEnumerable<Regex> DenyList => new[]
        {
            new Regex(
                @"(?:r|s)k_live_[0-9a-zA-Z]{24}",
                RegexOptions.Compiled),
        };

        public override async Task<VerifiedResult> VerifyAsync(string secret)
        {
            try
            {
                var request = new HttpRequestMessage(
                    HttpMethod.Get,
                    "https://api.stripe.com/v1/charges");

                var authBytes = Encoding.UTF8.GetBytes($"{secret}:");
                request.Headers.Authorization =
                    new System.Net.Http.Headers.AuthenticationHeaderValue(
                        "Basic", System.Convert.ToBase64String(authBytes));

                var response = await _httpClient.SendAsync(request).ConfigureAwait(false);

                if (response.StatusCode == System.Net.HttpStatusCode.OK)
                    return VerifiedResult.VerifiedTrue;

                if (secret.StartsWith("rk_live"))
                    return VerifiedResult.Unverified;

                return VerifiedResult.VerifiedFalse;
            }
            catch
            {
                return VerifiedResult.Unverified;
            }
        }
    }
}
