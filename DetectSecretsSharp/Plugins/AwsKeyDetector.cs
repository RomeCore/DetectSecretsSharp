using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using DetectSecretsSharp.Core;
using DetectSecretsSharp.Util;

namespace DetectSecretsSharp.Plugins
{
    /// <summary>
    /// Scans for AWS access keys and secret keys.
    /// </summary>
    public class AwsKeyDetector : RegexBasedDetector
    {
        private const string SecretKeyword = @"(?:key|pwd|pw|password|pass|token)";

        private static readonly HttpClient _httpClient = new HttpClient();

        public override string SecretType => "AWS Access Key";

        protected override IEnumerable<Regex> DenyList => new[]
        {
            new Regex(
                @"(?:A3T[A-Z0-9]|ABIA|ACCA|AKIA|ASIA)[0-9A-Z]{16}",
                RegexOptions.Compiled),
            new Regex(
                @"aws.{0,20}?" + SecretKeyword + @".{0,20}?[\'""]([0-9a-zA-Z/+]{40})[\'""]",
                RegexOptions.Compiled | RegexOptions.IgnoreCase),
        };

        public override async Task<VerifiedResult> VerifyAsync(string secret, CodeSnippet context = null)
        {
            if (!DenyList.First().IsMatch(secret))
                return VerifiedResult.Unverified;

            if (context == null)
                return VerifiedResult.Unverified;

            var candidates = GetSecretAccessKeys(context);
            if (candidates.Count == 0)
                return VerifiedResult.Unverified;

            foreach (var candidate in candidates)
            {
                if (await VerifyAwsSecretAccessKeyAsync(secret, candidate).ConfigureAwait(false))
                    return VerifiedResult.VerifiedTrue;
            }

            return VerifiedResult.VerifiedFalse;
        }

        private static List<string> GetSecretAccessKeys(CodeSnippet context)
        {
            var regex = new Regex(
                @"(=|,|\() *(['""]?)([A-Za-z0-9+/=]{40})(\2)(\))?",
                RegexOptions.Compiled);

            var result = new List<string>();
            foreach (var line in context.Lines)
            {
                foreach (Match match in regex.Matches(line))
                {
                    result.Add(match.Groups[3].Value);
                }
            }
            return result;
        }

        private static async Task<bool> VerifyAwsSecretAccessKeyAsync(string keyId, string secretKey)
        {
            try
            {
                var now = DateTime.UtcNow;
                var amazonDatetime = now.ToString("yyyyMMddTHHmmssZ", CultureInfo.InvariantCulture);
                var requestDate = now.ToString("yyyyMMdd", CultureInfo.InvariantCulture);

                var headers = new Dictionary<string, string>
                {
                    ["Host"] = "sts.amazonaws.com",
                    ["X-Amz-Date"] = amazonDatetime,
                };

                var bodyParams = new Dictionary<string, string>
                {
                    ["Action"] = "GetCallerIdentity",
                    ["Version"] = "2011-06-15",
                };

                var signedHeaders = string.Join(";", headers.Keys.Select(k => k.ToLowerInvariant()));
                var headerLines = string.Join("\n",
                    headers.Select(h => $"{h.Key.ToLowerInvariant()}:{h.Value}"));
                var bodyString = string.Join("&",
                    bodyParams.Select(b => $"{b.Key}={b.Value}"));
                var hashedPayload = Sha256Hex(bodyString);

                var canonicalRequest = string.Format(
                    "POST\n/\n\n{0}\n\n{1}\n{2}",
                    headerLines, signedHeaders, hashedPayload);

                var region = "us-east-1";
                var scope = $"{requestDate}/{region}/sts/aws4_request";

                var stringToSign = string.Format(
                    "AWS4-HMAC-SHA256\n{0}\n{1}\n{2}",
                    amazonDatetime, scope, Sha256Hex(canonicalRequest));

                var signingKey = ComputeSigningKey("AWS4" + secretKey, requestDate, region, "sts");
                var signature = HmacSha256Hex(signingKey, stringToSign);

                var authorization = string.Format(
                    "AWS4-HMAC-SHA256 Credential={0}/{1}, SignedHeaders={2}, Signature={3}",
                    keyId, scope, signedHeaders, signature);

                headers["Authorization"] = authorization;

                var request = new HttpRequestMessage(HttpMethod.Post, "https://sts.amazonaws.com");
                foreach (var header in headers)
                    request.Headers.TryAddWithoutValidation(header.Key, header.Value);

                request.Content = new FormUrlEncodedContent(bodyParams);

                var response = await _httpClient.SendAsync(request).ConfigureAwait(false);
                return response.StatusCode != System.Net.HttpStatusCode.Forbidden;
            }
            catch
            {
                return false;
            }
        }

        private static byte[] ComputeSigningKey(string key, string dateStamp, string regionName, string serviceName)
        {
            byte[] kDate = HmacSha256(Encoding.UTF8.GetBytes(key), dateStamp);
            byte[] kRegion = HmacSha256(kDate, regionName);
            byte[] kService = HmacSha256(kRegion, serviceName);
            byte[] kSigning = HmacSha256(kService, "aws4_request");
            return kSigning;
        }

        private static byte[] HmacSha256(byte[] key, string data)
        {
            using (var hmac = new HMACSHA256(key))
                return hmac.ComputeHash(Encoding.UTF8.GetBytes(data));
        }

        private static string HmacSha256Hex(byte[] key, string data)
        {
            return BytesToHexLower(HmacSha256(key, data));
        }

        private static string Sha256Hex(string data)
        {
            using (var sha256 = SHA256.Create())
                return BytesToHexLower(sha256.ComputeHash(Encoding.UTF8.GetBytes(data)));
        }

        private static string BytesToHexLower(byte[] bytes)
        {
            var hex = new StringBuilder(bytes.Length * 2);
            foreach (byte b in bytes)
                hex.Append(b.ToString("x2"));
            return hex.ToString();
        }
    }
}
