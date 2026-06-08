# DetectSecretsSharp 🔍

A C# port of [Yelp/detect-secrets](https://github.com/Yelp/detect-secrets) — an entropy-based secrets detection library.  
Scans files, diffs, and ad-hoc strings for AWS keys, GitHub tokens, OpenAI keys, private keys, passwords, and 20+ other secret types.

## 🚀 Quick Start

```bash
dotnet add package DetectSecretsSharp
```

```csharp
using DetectSecretsSharp.Core;
using DetectSecretsSharp.Plugins;

// Scan a string with all 27 built-in detectors
var results = SecretsCollection.ScanLineDefault(
    "GITHUB_TOKEN=ghp_abc123ABC456def789GHI012jkl345MNO678");

foreach (var (filename, secret) in results)
{
    Console.WriteLine($"{filename}:{secret.Type} → {secret.SecretValue}");
}
// Output: adhoc-string-scan:GitHub Token → ghp_abc123ABC456def789GHI012jkl345MNO678
```

## 📦 Installation

```
dotnet add package DetectSecretsSharp
```

Or via NuGet Package Manager:
```
Install-Package DetectSecretsSharp
```

**Target:** .NET Standard 2.0+ (compatible with .NET Framework 4.6.1+, .NET Core 2.0+, .NET 5+)

## 🔧 Usage

### Scanning a String

```csharp
// With default detectors (all 27)
var results = SecretsCollection.ScanLineDefault("AKIA1234567890ABCDEF");

// With custom detectors
var results = SecretsCollection.ScanLine(
    "password = \"supersecret\"",
    filename: "config.env",
    new KeywordDetector(), new AwsKeyDetector());

// Async version
var results = await SecretsCollection.ScanLineAsync("sk-live_...", ".env",
    new StripeDetector());
```

### Scanning a File

```csharp
var scanner = new Scanner(new DetectorBase[] {
    new AwsKeyDetector(),
    new GitHubTokenDetector(),
    new OpenAiDetector()
});

var secrets = scanner.ScanFile("config.env");
```

### Scanning Multiple Files

```csharp
var scanner = Scanner.CreateDefault();
var results = scanner.ScanFiles(new[] { "file1.env", "file2.yaml" });

// Async parallel scanning
var results = await scanner.ScanFilesAsync(new[] { "file1.env", "file2.yaml" });
```

### Scanning a Diff

```csharp
var diff = @"--- a/config.env
+++ b/config.env
@@ -0,0 +1 @@
+SLACK_TOKEN=xoxb-123456789012-123456789012-abc123def456ghi789jkl012mno345pqr";

var scanner = new Scanner(new DetectorBase[] { new SlackDetector() });
var results = scanner.ScanDiff(diff);
```

### Working with Baseline (JSON)

```csharp
// Export to baseline
var baseline = secrets.ToBaselineDictionary();
string json = JsonSerializer.Serialize(baseline);

// Load from baseline
var loaded = SecretsCollection.LoadFromBaseline(baseline);
```

### Merge and Trim

```csharp
// Merge old results (preserves verification status)
current.Merge(oldResults);

// Trim: remove false positives that no longer exist
current.Trim(scannedResults);

// Subtraction: behave like set difference
var diff = current - oldResults;
```

## 🗺️ Detectors (27 built-in)

| Detector | Secret Type | Has Verify |
|---|---|---|
| `AwsKeyDetector` | AWS Access Key | ✅ (STS API) |
| `AzureStorageKeyDetector` | Azure Storage Account Key | ❌ |
| `ArtifactoryDetector` | Artifactory Credentials | ❌ |
| `BasicAuthDetector` | Basic Auth Credentials | ❌ |
| `Base64HighEntropyStringDetector` | Base64 High Entropy String | ❌ |
| `CloudantDetector` | Cloudant Credentials | ✅ |
| `DiscordBotTokenDetector` | Discord Bot Token | ❌ |
| `GitHubTokenDetector` | GitHub Token | ❌ |
| `GitLabTokenDetector` | GitLab Token | ❌ |
| `HexHighEntropyStringDetector` | Hex High Entropy String | ❌ |
| `IbmCloudIamDetector` | IBM Cloud IAM Key | ✅ |
| `IbmCosHmacDetector` | IBM COS HMAC Credentials | ✅ |
| `IpPublicDetector` | Public IP (ipv4) | ❌ |
| `JwtTokenDetector` | JSON Web Token | ❌ (format validation) |
| `KeywordDetector` | Secret Keyword | ❌ |
| `MailchimpDetector` | Mailchimp Access Key | ✅ |
| `NpmDetector` | NPM tokens | ❌ |
| `OpenAiDetector` | OpenAI Token | ❌ |
| `PrivateKeyDetector` | Private Key | ❌ |
| `PypiTokenDetector` | PyPI Token | ❌ |
| `SendGridDetector` | SendGrid API Token | ❌ |
| `SlackDetector` | Slack Token | ✅ |
| `SoftlayerDetector` | SoftLayer Credentials | ✅ |
| `SquareOAuthDetector` | Square OAuth Secret | ❌ |
| `StripeDetector` | Stripe Access Key | ✅ |
| `TelegramBotTokenDetector` | Telegram Bot Token | ✅ |
| `TwilioKeyDetector` | Twilio API Key | ❌ |

### Custom Detector

```csharp
public class MyCustomDetector : RegexBasedDetector
{
    public override string SecretType => "My Custom Secret";
    protected override IEnumerable<Regex> DenyList => new[]
    {
        new Regex(@"CUSTOMKEY-[A-Z0-9]{16}", RegexOptions.Compiled)
    };
}

// Usage
var results = SecretsCollection.ScanLine(
    "CUSTOMKEY-ABCD1234EFGH5678",
    detectors: new MyCustomDetector());
```

## ⚙️ Async Verification

Several detectors support **online verification** via external APIs (AWS STS, Slack, Stripe, Telegram, etc.):

```csharp
// Sync (blocks thread)
var result = detector.Verify(secret);

// Async (preferred)
var result = await detector.VerifyAsync(secret);

// With code context
var context = CodeSnippet.FromSingleLine(line, lineNumber);
var result = await detector.VerifyAsync(secret, context);
```

## 🔬 Architecture

```
DetectSecretsSharp
├── Core
│   ├── PotentialSecret       # Secret data model
│   ├── SecretsCollection     # Collection of secrets by file
│   └── Scanner               # File/diff/string scanner
├── Plugins
│   ├── DetectorBase          # Abstract base detector
│   ├── RegexBasedDetector    # Regex-based detector (90% of plugins)
│   └── 27 concrete detectors
└── Util
    ├── CodeSnippet           # Code context for verification
    └── FileType              # File type detection
```

## 📄 License

MIT License — see [LICENSE](LICENSE).

## 🙏 Credits

- Original Python project: [Yelp/detect-secrets](https://github.com/Yelp/detect-secrets)
- Port author: [RomeCore](https://github.com/RomeCore)
