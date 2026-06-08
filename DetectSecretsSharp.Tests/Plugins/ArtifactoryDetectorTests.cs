using System.Linq;
using DetectSecretsSharp.Plugins;
using Xunit;

namespace DetectSecretsSharp.Tests.Plugins
{
    public class ArtifactoryDetectorTests
    {
        private readonly ArtifactoryDetector _detector = new ArtifactoryDetector();

        [Fact]
        public void SecretType_IsSet()
        {
            Assert.Equal("Artifactory Credentials", _detector.SecretType);
        }

        [Fact]
        public void AnalyzeString_FindsApiToken()
        {
            var results = _detector.AnalyzeString(" AKCabcdefghijk1234567890 ").ToList();
            Assert.Single(results);
        }

        [Fact]
        public void AnalyzeString_FindsEncryptedPassword()
        {
            var results = _detector.AnalyzeString(" AP1abcdefghijklmnop ").ToList();
            Assert.Single(results);
        }

        [Fact]
        public void AnalyzeString_NoMatch_RandomText()
        {
            var results = _detector.AnalyzeString("just some random text").ToList();
            Assert.Empty(results);
        }

        [Fact]
        public void AnalyzeLine_ReturnsPotentialSecret()
        {
            var results = _detector.AnalyzeLine("config.yaml", "artifactory_key: AKCabcdefghijk1234567890", 10);
            Assert.Single(results);
            var secret = results.First();
            Assert.Equal("Artifactory Credentials", secret.Type);
            Assert.Equal("config.yaml", secret.Filename);
            Assert.Equal(10, secret.LineNumber);
        }
    }
}
