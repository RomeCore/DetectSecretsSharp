using System.Linq;
using DetectSecretsSharp.Plugins;
using Xunit;

namespace DetectSecretsSharp.Tests.Plugins
{
    public class CloudantDetectorTests
    {
        private readonly CloudantDetector _detector = new CloudantDetector();

        // Helper: 64 hex chars (mixed, not all same)
        // a1b2c3d4e5f6 = 12 chars, x5 = 60, + a1b2 = 4 => 64
        private const string Hex64 = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";

        [Fact]
        public void SecretType_IsSet()
        {
            Assert.Equal("Cloudant Credentials", _detector.SecretType);
        }

        [Fact]
        public void AnalyzeString_FindsPasswordAssignment()
        {
            var results = _detector.AnalyzeString($"cloudant_password={Hex64}").ToList();
            Assert.Single(results);
        }

        [Fact]
        public void AnalyzeString_FindsUrlWithPassword()
        {
            var results = _detector.AnalyzeString($"https://account:{Hex64}@account.cloudant.com").ToList();
            Assert.Single(results);
        }

        [Fact]
        public void AnalyzeString_NoMatch_RandomText()
        {
            var results = _detector.AnalyzeString("just random text").ToList();
            Assert.Empty(results);
        }

        [Fact]
        public void AnalyzeLine_ReturnsPotentialSecret()
        {
            var results = _detector.AnalyzeLine(".env", $"CLOUDANT_PASSWORD={Hex64}", 7);
            Assert.Single(results);
            var secret = results.First();
            Assert.Equal("Cloudant Credentials", secret.Type);
        }
    }
}
