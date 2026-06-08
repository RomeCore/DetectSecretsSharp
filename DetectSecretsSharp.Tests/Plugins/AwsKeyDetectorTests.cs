using System.Linq;
using DetectSecretsSharp.Core;
using DetectSecretsSharp.Plugins;
using DetectSecretsSharp.Util;
using Xunit;

namespace DetectSecretsSharp.Tests.Plugins
{
    public class AwsKeyDetectorTests
    {
        private readonly AwsKeyDetector _detector = new AwsKeyDetector();

        [Fact]
        public void SecretType_IsSet()
        {
            Assert.Equal("AWS Access Key", _detector.SecretType);
        }

        [Theory]
        [InlineData("AKIA1234567890ABCDEF")]
        [InlineData("ASIA1234567890ABCDEF")]
        [InlineData("ABIA1234567890ABCDEF")]
        [InlineData("ACCA1234567890ABCDEF")]
        [InlineData("A3TA1234567890ABCDEF")]
        public void AnalyzeString_FindsAwsKeyId(string keyId)
        {
            var results = _detector.AnalyzeString(keyId).ToList();
            Assert.Single(results);
            Assert.Equal(keyId, results[0]);
        }

        [Fact]
        public void AnalyzeString_FindsSecretKeyInAssignment()
        {
            // 40-char base64-like string
            var results = _detector.AnalyzeString(
                "aws_secret_key = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'").ToList();
            Assert.Single(results);
        }

        [Fact]
        public void AnalyzeString_SecretKeyWithPasswordKeyword()
        {
            var results = _detector.AnalyzeString(
                "AWSpassword='wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'").ToList();
            Assert.Single(results);
        }

        [Fact]
        public void AnalyzeString_NoKey_NoMatch()
        {
            var results = _detector.AnalyzeString("just some random text").ToList();
            Assert.Empty(results);
        }

        [Fact]
        public void AnalyzeLine_ReturnsPotentialSecret()
        {
            var results = _detector.AnalyzeLine("credentials.txt",
                "AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF", 5);
            Assert.Single(results);
            var secret = results.First();
            Assert.Equal("AWS Access Key", secret.Type);
            Assert.Equal("credentials.txt", secret.Filename);
            Assert.Equal(5, secret.LineNumber);
        }

        [Fact]
        public void Verify_NoContext_ReturnsUnverified()
        {
            var result = _detector.Verify("AKIA1234567890ABCDEF");
            Assert.Equal(VerifiedResult.Unverified, result);
        }

        [Fact]
        public void Verify_WithContextButNoSecretKey_ReturnsUnverified()
        {
            var context = CodeSnippet.FromSingleLine("just some random context", 1);
            var result = _detector.Verify("AKIA1234567890ABCDEF", context);
            Assert.Equal(VerifiedResult.Unverified, result);
        }

        [Fact]
        public void Verify_NonKeyIdFormat_ReturnsUnverified()
        {
            var context = CodeSnippet.FromSingleLine("password = 'test'", 1);
            var result = _detector.Verify("some random string", context);
            Assert.Equal(VerifiedResult.Unverified, result);
        }
    }
}
