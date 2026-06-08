using System.Linq;
using DetectSecretsSharp.Plugins;
using Xunit;

namespace DetectSecretsSharp.Tests.Plugins
{
    public class IbmCloudIamDetectorTests
    {
        private readonly IbmCloudIamDetector _detector = new IbmCloudIamDetector();

        [Fact]
        public void SecretType_IsSet()
        {
            Assert.Equal("IBM Cloud IAM Key", _detector.SecretType);
        }

        [Fact]
        public void AnalyzeString_FindsAssignment()
        {
            // 44-char key with alphanumeric, underscores, dashes
            var key = new string('a', 44);
            var results = _detector.AnalyzeString($"ibm_cloud_iam_key={key}").ToList();
            Assert.Single(results);
        }

        [Fact]
        public void AnalyzeString_FindsApiKeyAssignment()
        {
            var key = new string('b', 44);
            var results = _detector.AnalyzeString($"ibm_api_key={key}").ToList();
            Assert.Single(results);
        }

        [Fact]
        public void AnalyzeString_NoMatch_TooShort()
        {
            var results = _detector.AnalyzeString("ibm_key=short").ToList();
            Assert.Empty(results);
        }

        [Fact]
        public void AnalyzeLine_ReturnsPotentialSecret()
        {
            var key = new string('c', 44);
            var results = _detector.AnalyzeLine(".env", $"IBM_CLOUD_API_KEY={key}", 3);
            Assert.Single(results);
            var secret = results.First();
            Assert.Equal("IBM Cloud IAM Key", secret.Type);
        }
    }
}
