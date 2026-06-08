using System.Linq;
using DetectSecretsSharp.Plugins;
using Xunit;

namespace DetectSecretsSharp.Tests.Plugins
{
    public class IbmCosHmacDetectorTests
    {
        private readonly IbmCosHmacDetector _detector = new IbmCosHmacDetector();

        [Fact]
        public void SecretType_IsSet()
        {
            Assert.Equal("IBM COS HMAC Credentials", _detector.SecretType);
        }

        [Fact]
        public void AnalyzeString_FindsSecretKey()
        {
            // 48 hex chars
            var key = new string('a', 48);
            var results = _detector.AnalyzeString($"cos_secret_access_key={key}").ToList();
            Assert.Single(results);
        }

        [Fact]
        public void AnalyzeString_FindsIbmCosKey()
        {
            var key = new string('b', 48);
            var results = _detector.AnalyzeString($"ibm_cos_hmac_secret_key={key}").ToList();
            Assert.Single(results);
        }

        [Fact]
        public void AnalyzeString_NoMatch_TooShort()
        {
            var results = _detector.AnalyzeString("cos_key=short").ToList();
            Assert.Empty(results);
        }

        [Fact]
        public void AnalyzeString_NoMatch_NonHex()
        {
            var key = new string('z', 48);
            var results = _detector.AnalyzeString($"cos_secret_key={key}").ToList();
            Assert.Empty(results);
        }

        [Fact]
        public void AnalyzeLine_ReturnsPotentialSecret()
        {
            var key = new string('c', 48);
            var results = _detector.AnalyzeLine(".env", $"COS_HMAC_SECRET_KEY={key}", 6);
            Assert.Single(results);
            var secret = results.First();
            Assert.Equal("IBM COS HMAC Credentials", secret.Type);
        }
    }
}
