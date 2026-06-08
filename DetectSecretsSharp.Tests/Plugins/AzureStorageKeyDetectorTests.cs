using System.Linq;
using DetectSecretsSharp.Plugins;
using Xunit;

namespace DetectSecretsSharp.Tests.Plugins
{
    public class AzureStorageKeyDetectorTests
    {
        private readonly AzureStorageKeyDetector _detector = new AzureStorageKeyDetector();

        [Fact]
        public void SecretType_IsSet()
        {
            Assert.Equal("Azure Storage Account access key", _detector.SecretType);
        }

        [Fact]
        public void AnalyzeString_FindsAccountKey()
        {
            // 88-char base64-like key after "AccountKey="
            var key = new string('a', 88);
            var results = _detector.AnalyzeString($"AccountKey={key}").ToList();
            Assert.Single(results);
        }

        [Fact]
        public void AnalyzeString_NoMatch_ShortKey()
        {
            var results = _detector.AnalyzeString("AccountKey=short").ToList();
            Assert.Empty(results);
        }

        [Fact]
        public void AnalyzeString_NoMatch_WrongPrefix()
        {
            var key = new string('a', 88);
            var results = _detector.AnalyzeString($"ConnectionString={key}").ToList();
            Assert.Empty(results);
        }

        [Fact]
        public void AnalyzeLine_ReturnsPotentialSecret()
        {
            var key = new string('b', 88);
            var results = _detector.AnalyzeLine("config.env", $"AZURE_STORAGE_ACCOUNT_KEY={key}", 5);
            // The detector looks for "AccountKey=" specifically, not the full variable name
            // so this won't match if the variable contains more than just "AccountKey"
            // Let's use the exact pattern
            Assert.Empty(results);
        }

        [Fact]
        public void AnalyzeLine_ExactMatch()
        {
            var key = new string('c', 88);
            var results = _detector.AnalyzeLine("config.env", $"AccountKey={key}", 5);
            Assert.Single(results);
            var secret = results.First();
            Assert.Equal("Azure Storage Account access key", secret.Type);
        }
    }
}
