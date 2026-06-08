using System.Linq;
using DetectSecretsSharp.Plugins;
using Xunit;

namespace DetectSecretsSharp.Tests.Plugins
{
    public class IpPublicDetectorTests
    {
        private readonly IpPublicDetector _detector = new IpPublicDetector();

        [Fact]
        public void SecretType_IsSet()
        {
            Assert.Equal("Public IP (ipv4)", _detector.SecretType);
        }

        [Theory]
        [InlineData("8.8.8.8")]
        [InlineData("1.1.1.1")]
        [InlineData("208.67.222.222")]
        [InlineData("185.199.108.153")]
        [InlineData("198.51.100.1")]
        public void AnalyzeString_FindsPublicIp(string ip)
        {
            var results = _detector.AnalyzeString(ip).ToList();
            Assert.Single(results);
        }

        [Theory]
        [InlineData("127.0.0.1")]
        [InlineData("10.0.0.1")]
        [InlineData("192.168.1.1")]
        [InlineData("172.16.0.1")]
        [InlineData("172.31.255.255")]
        [InlineData("169.254.1.1")]
        public void AnalyzeString_IgnoresPrivateIp(string ip)
        {
            var results = _detector.AnalyzeString(ip).ToList();
            Assert.Empty(results);
        }

        [Fact]
        public void AnalyzeString_FindsPublicIpWithPort()
        {
            var results = _detector.AnalyzeString("8.8.8.8:53").ToList();
            Assert.Single(results);
        }

        [Fact]
        public void AnalyzeLine_ReturnsPotentialSecret()
        {
            var results = _detector.AnalyzeLine("config.txt", "server=8.8.8.8", 5);
            Assert.Single(results);
            var secret = results.First();
            Assert.Equal("Public IP (ipv4)", secret.Type);
        }
    }
}
