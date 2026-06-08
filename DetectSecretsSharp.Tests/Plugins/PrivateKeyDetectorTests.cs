using System.Linq;
using DetectSecretsSharp.Plugins;
using Xunit;

namespace DetectSecretsSharp.Tests.Plugins
{
    public class PrivateKeyDetectorTests
    {
        private readonly PrivateKeyDetector _detector = new PrivateKeyDetector();

        [Fact]
        public void SecretType_IsSet()
        {
            Assert.Equal("Private Key", _detector.SecretType);
        }

        [Theory]
        [InlineData("-----BEGIN RSA PRIVATE KEY-----")]
        [InlineData("-----BEGIN DSA PRIVATE KEY-----")]
        [InlineData("-----BEGIN EC PRIVATE KEY-----")]
        [InlineData("-----BEGIN OPENSSH PRIVATE KEY-----")]
        [InlineData("-----BEGIN PGP PRIVATE KEY BLOCK-----")]
        [InlineData("-----BEGIN PRIVATE KEY-----")]
        [InlineData("-----BEGIN SSH2 ENCRYPTED PRIVATE KEY-----")]
        [InlineData("PuTTY-User-Key-File-2")]
        public void AnalyzeString_FindsPrivateKeyHeader(string header)
        {
            var results = _detector.AnalyzeString(header).ToList();
            Assert.Single(results);
        }

        [Fact]
        public void AnalyzeString_NoMatch_NormalText()
        {
            var results = _detector.AnalyzeString("public key is fine").ToList();
            Assert.Empty(results);
        }

        [Fact]
        public void AnalyzeLine_ReturnsPotentialSecret()
        {
            var results = _detector.AnalyzeLine("id_rsa", "-----BEGIN RSA PRIVATE KEY-----", 1);
            Assert.Single(results);
            var secret = results.First();
            Assert.Equal("Private Key", secret.Type);
            Assert.Equal("id_rsa", secret.Filename);
            Assert.Equal(1, secret.LineNumber);
        }
    }
}
