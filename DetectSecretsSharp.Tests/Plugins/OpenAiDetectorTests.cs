using System.Linq;
using DetectSecretsSharp.Plugins;
using Xunit;

namespace DetectSecretsSharp.Tests.Plugins
{
    public class OpenAiDetectorTests
    {
        private readonly OpenAiDetector _detector = new OpenAiDetector();

        [Fact]
        public void SecretType_IsSet()
        {
            Assert.Equal("OpenAI Token", _detector.SecretType);
        }

        [Fact]
        public void AnalyzeString_FindsLegacyKey()
        {
            // sk- + 20 alnum + T3BlbkFJ + 20 alnum
            var results = _detector.AnalyzeString(
                "sk-abcdefghij1234567890T3BlbkFJabcdefghij1234567890").ToList();
            Assert.Single(results);
        }

        [Fact]
        public void AnalyzeString_FindsProjectKey()
        {
            // sk-proj- + 20 alnum + T3BlbkFJ + 20 alnum
            var results = _detector.AnalyzeString(
                "sk-proj-abcdefghij1234567890T3BlbkFJabcdefghij1234567890").ToList();
            Assert.Single(results);
        }

        [Fact]
        public void AnalyzeString_NoMatch_InvalidPrefix()
        {
            var results = _detector.AnalyzeString(
                "xk-abcdefghij1234567890T3BlbkFJabcdefghij1234567890").ToList();
            Assert.Empty(results);
        }

        [Fact]
        public void AnalyzeString_NoMatch_MissingT3BlbkFJ()
        {
            var results = _detector.AnalyzeString(
                "sk-abcdefghij1234567890XXXXXXXXXXabcdefghij1234567890").ToList();
            Assert.Empty(results);
        }

        [Fact]
        public void AnalyzeLine_ReturnsPotentialSecret()
        {
            var results = _detector.AnalyzeLine(".env",
                "OPENAI_API_KEY=sk-abcdefghij1234567890T3BlbkFJabcdefghij1234567890", 3);
            Assert.Single(results);
            var secret = results.First();
            Assert.Equal("OpenAI Token", secret.Type);
            Assert.Equal(".env", secret.Filename);
            Assert.Equal(3, secret.LineNumber);
        }
    }
}
