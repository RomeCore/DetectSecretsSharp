using System.Collections.Generic;
using System.Net.Http;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using DetectSecretsSharp.Core;

namespace DetectSecretsSharp.Plugins
{
    /// <summary>
    /// Scans for Telegram Bot tokens.
    /// </summary>
    public class TelegramBotTokenDetector : RegexBasedDetector
    {
        private static readonly HttpClient _httpClient = new HttpClient();

        public override string SecretType => "Telegram Bot Token";

        protected override IEnumerable<Regex> DenyList => new[]
        {
            new Regex(
                @"\d{8,10}:[0-9A-Za-z_-]{35}",
                RegexOptions.Compiled),
        };

        public override async Task<VerifiedResult> VerifyAsync(string secret)
        {
            try
            {
                var response = await _httpClient.GetAsync(
                    $"https://api.telegram.org/bot{secret}/getMe")
                    .ConfigureAwait(false);

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
