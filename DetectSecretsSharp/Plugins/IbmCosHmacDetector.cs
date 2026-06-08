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
    /// Scans for IBM Cloud Object Storage HMAC credentials.
    /// </summary>
    public class IbmCosHmacDetector : RegexBasedDetector
    {
        private static readonly HttpClient _httpClient = new HttpClient();

        public override string SecretType => "IBM COS HMAC Credentials";

        private const string TokenPrefix = @"(?:(?:ibm)?[-_]?cos[-_]?(?:hmac)?|)";
        private const string PasswordKeyword = @"(?:secret[-_]?(?:access)?[-_]?key)";
        private const string Password = @"([a-f0-9]{48}(?![a-f0-9]))";

        protected override IEnumerable<Regex> DenyList => new[]
        {
            BuildAssignmentRegex(
                prefixRegex: TokenPrefix,
                secretKeywordRegex: PasswordKeyword,
                secretRegex: Password),
        };

        public override async Task<VerifiedResult> VerifyAsync(string secret, CodeSnippet context)
        {
            if (context == null)
                return VerifiedResult.Unverified;

            var keyIdMatches = FindAccessKeyId(context);
            if (keyIdMatches.Count == 0)
                return VerifiedResult.Unverified;

            try
            {
                foreach (var keyId in keyIdMatches)
                {
                    if (await VerifyIbmCosHmacCredentialsAsync(keyId, secret).ConfigureAwait(false))
                        return VerifiedResult.VerifiedTrue;
                }
            }
            catch
            {
                return VerifiedResult.Unverified;
            }

            return VerifiedResult.VerifiedFalse;
        }

        private static List<string> FindAccessKeyId(CodeSnippet context)
        {
            const string keyIdKeyword = @"(?:access[-_]?(?:key)?[-_]?(?:id)?|key[-_]?id)";
            const string keyIdRegex = @"([a-f0-9]{32})";

            var regex = BuildAssignmentRegex(
                prefixRegex: TokenPrefix,
                secretKeywordRegex: keyIdKeyword,
                secretRegex: keyIdRegex);

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

        private static async Task<bool> VerifyIbmCosHmacCredentialsAsync(
            string accessKey, string secretKey,
            string host = "s3.us.cloud-object-storage.appdomain.cloud")
        {
            string httpMethod = "GET";
            string region = "us-standard";
            string endpoint = $"https://{host}";

            var time = DateTime.UtcNow;
            string timestamp = time.ToString("yyyyMMddTHHmmssZ", CultureInfo.InvariantCulture);
            string datestamp = time.ToString("yyyyMMdd", CultureInfo.InvariantCulture);

            string standardizedResource = "/";
            string standardizedQuerystring = "";
            string standardizedHeaders = $"host:{host}\nx-amz-date:{timestamp}\n";
            string signedHeaders = "host;x-amz-date";
            string payloadHash = Sha256Hex("");

            string standardizedRequest = httpMethod + "\n"
                + standardizedResource + "\n"
                + standardizedQuerystring + "\n"
                + standardizedHeaders + "\n"
                + signedHeaders + "\n"
                + payloadHash;

            string hashingAlgorithm = "AWS4-HMAC-SHA256";
            string credentialScope = datestamp + "/" + region + "/s3/aws4_request";
            string sts = hashingAlgorithm + "\n" + timestamp + "\n"
                + credentialScope + "\n" + Sha256Hex(standardizedRequest);

            var signatureKey = CreateSignatureKey(secretKey, datestamp, region, "s3");
            string signature = HmacSha256Hex(signatureKey, sts);

            string v4authHeader = $"{hashingAlgorithm} Credential={accessKey}/{credentialScope}, SignedHeaders={signedHeaders}, Signature={signature}";

            var request = new HttpRequestMessage(HttpMethod.Get, endpoint + standardizedResource + standardizedQuerystring);
            request.Headers.Add("x-amz-date", timestamp);
            request.Headers.TryAddWithoutValidation("Authorization", v4authHeader);

            var response = await _httpClient.SendAsync(request).ConfigureAwait(false);
            return response.StatusCode == System.Net.HttpStatusCode.OK;
        }

        private static byte[] CreateSignatureKey(string key, string dateStamp, string regionName, string serviceName)
        {
            byte[] kDate = HmacSha256(Encoding.UTF8.GetBytes("AWS4" + key), dateStamp);
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
