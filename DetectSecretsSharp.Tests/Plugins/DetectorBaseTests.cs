using System.Collections.Generic;
using System.Linq;
using DetectSecretsSharp.Core;
using DetectSecretsSharp.Plugins;
using DetectSecretsSharp.Util;
using Xunit;

namespace DetectSecretsSharp.Tests.Plugins
{
    public class DetectorBaseTests
    {
        private class TestDetector : DetectorBase
        {
            public override string SecretType => "TestSecret";
            public override IEnumerable<string> AnalyzeString(string str)
            {
                if (str.Contains("SECRET"))
                    yield return str;
            }
        }

        [Fact]
        public void AnalyzeLine_FindsSecrets()
        {
            var detector = new TestDetector();
            var results = detector.AnalyzeLine("test.txt", "This is a SECRET value", 10);

            Assert.Single(results);
            var secret = results.First();
            Assert.Equal("TestSecret", secret.Type);
            Assert.Equal("test.txt", secret.Filename);
            Assert.Equal(10, secret.LineNumber);
            Assert.Equal("This is a SECRET value", secret.SecretValue);
        }

        [Fact]
        public void AnalyzeLine_NoMatch_ReturnsEmpty()
        {
            var detector = new TestDetector();
            var results = detector.AnalyzeLine("test.txt", "No secrets here", 5);

            Assert.Empty(results);
        }

        [Fact]
        public void Verify_Default_ReturnsUnverified()
        {
            var detector = new TestDetector();
            var result = detector.Verify("anything");
            Assert.Equal(VerifiedResult.Unverified, result);
        }

        [Fact]
        public void Json_ReturnsDetectorName()
        {
            var detector = new TestDetector();
            var json = detector.Json();

            Assert.Equal("TestDetector", json["name"]);
        }

        [Fact]
        public void FormatScanResult_Default()
        {
            var detector = new TestDetector();
            var secret = new PotentialSecret("TestSecret", "f.txt", "secret-value");

            string result = detector.FormatScanResult(secret);
            Assert.Contains("True", result);
        }

        [Fact]
        public void Equals_SameType_SameConfig_ReturnsTrue()
        {
            var detector1 = new TestDetector();
            var detector2 = new TestDetector();
            Assert.Equal(detector1, detector2);
        }

        [Fact]
        public void GetHashCode_SameType_SameConfig_Matches()
        {
            var detector1 = new TestDetector();
            var detector2 = new TestDetector();
            Assert.Equal(detector1.GetHashCode(), detector2.GetHashCode());
        }

        [Fact]
        public void AnalyzeLine_WithContext_StillWorks()
        {
            var detector = new TestDetector();
            var context = CodeSnippet.FromSingleLine("This is a SECRET value", 10);
            var results = detector.AnalyzeLine("test.txt", "This is a SECRET value", 10, context);

            Assert.Single(results);
        }
    }
}
