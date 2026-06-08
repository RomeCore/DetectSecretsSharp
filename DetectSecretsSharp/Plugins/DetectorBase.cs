using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using DetectSecretsSharp.Core;
using DetectSecretsSharp.Util;

namespace DetectSecretsSharp.Plugins
{
    /// <summary>
    /// Base class for all secret detectors.
    /// Defines the interface for analyzing strings and lines for potential secrets.
    /// </summary>
    public abstract class DetectorBase
    {
        /// <summary>
        /// Unique, user-facing description to identify this type of secret.
        /// </summary>
        public abstract string SecretType { get; }

        /// <summary>
        /// Analyzes a string and yields all raw secret values found within it.
        /// </summary>
        /// <param name="str">The string to analyze.</param>
        /// <returns>Raw secret values found in the string.</returns>
        public abstract IEnumerable<string> AnalyzeString(string str);

        /// <summary>
        /// Examines a line and finds all possible secret values in it.
        /// </summary>
        public virtual HashSet<PotentialSecret> AnalyzeLine(
            string filename,
            string line,
            int lineNumber = 0,
            CodeSnippet context = null)
        {
            var output = new HashSet<PotentialSecret>();

            foreach (string match in AnalyzeString(line))
            {
                bool isVerified = false;

                if (context != null)
                {
                    try
                    {
                        var verifiedResult = Verify(match, context);
                        isVerified = verifiedResult == VerifiedResult.VerifiedTrue;
                    }
                    catch
                    {
                        isVerified = false;
                    }
                }

                output.Add(
                    new PotentialSecret(
                        type: SecretType,
                        filename: filename,
                        secret: match,
                        lineNumber: lineNumber,
                        isVerified: isVerified));
            }

            return output;
        }

        /// <summary>
        /// Async version of <see cref="AnalyzeLine"/>.
        /// </summary>
        public virtual async Task<HashSet<PotentialSecret>> AnalyzeLineAsync(
            string filename,
            string line,
            int lineNumber = 0,
            CodeSnippet context = null)
        {
            var output = new HashSet<PotentialSecret>();

            foreach (string match in AnalyzeString(line))
            {
                bool isVerified = false;

                if (context != null)
                {
                    try
                    {
                        var verifiedResult = await VerifyAsync(match, context).ConfigureAwait(false);
                        isVerified = verifiedResult == VerifiedResult.VerifiedTrue;
                    }
                    catch
                    {
                        isVerified = false;
                    }
                }

                output.Add(
                    new PotentialSecret(
                        type: SecretType,
                        filename: filename,
                        secret: match,
                        lineNumber: lineNumber,
                        isVerified: isVerified));
            }

            return output;
        }

        // ---- Sync verification wrappers ----

        /// <summary>
        /// Synchronous verification wrapper. Calls <see cref="VerifyAsync(string)"/> internally.
        /// </summary>
        public virtual VerifiedResult Verify(string secret)
        {
            try
            {
                return VerifyAsync(secret).GetAwaiter().GetResult();
            }
            catch
            {
                return VerifiedResult.Unverified;
            }
        }

        /// <summary>
        /// Synchronous verification with context. Calls <see cref="VerifyAsync(string, CodeSnippet)"/> internally.
        /// </summary>
        public virtual VerifiedResult Verify(string secret, CodeSnippet context)
        {
            try
            {
                return VerifyAsync(secret, context).GetAwaiter().GetResult();
            }
            catch
            {
                return VerifiedResult.Unverified;
            }
        }

        // ---- Async verification ----

        /// <summary>
        /// Verifies whether a secret is actually valid by making an external call (e.g. API).
        /// Override this to implement actual async verification logic.
        /// </summary>
        public virtual Task<VerifiedResult> VerifyAsync(string secret)
        {
            return Task.FromResult(VerifiedResult.Unverified);
        }

        /// <summary>
        /// Verifies a secret with additional code context.
        /// Override this if verification requires surrounding code lines.
        /// </summary>
        public virtual Task<VerifiedResult> VerifyAsync(string secret, CodeSnippet context)
        {
            return VerifyAsync(secret);
        }

        /// <summary>
        /// Serializes the detector configuration to a dictionary.
        /// </summary>
        public virtual Dictionary<string, object> Json()
        {
            return new Dictionary<string, object>
            {
                ["name"] = GetType().Name
            };
        }

        /// <summary>
        /// Formats a scan result for display.
        /// </summary>
        public virtual string FormatScanResult(PotentialSecret secret)
        {
            if (secret == null)
                return "True";

            if (secret.SecretValue == null && !secret.IsVerified)
                return "True  (unverified)";

            if (!secret.IsVerified)
            {
                try
                {
                    var verifiedResult = Verify(secret.SecretValue);
                    switch (verifiedResult)
                    {
                        case VerifiedResult.VerifiedFalse:
                            return "False (verified)";
                        case VerifiedResult.VerifiedTrue:
                            return "True  (verified)";
                        case VerifiedResult.Unverified:
                        default:
                            return "True  (unverified)";
                    }
                }
                catch
                {
                    return "True  (unverified)";
                }
            }

            return "True  (verified)";
        }

        public override bool Equals(object obj)
        {
            if (obj == null || GetType() != obj.GetType())
                return false;

            var other = (DetectorBase)obj;
            var thisJson = Json();
            var otherJson = other.Json();

            if (thisJson.Count != otherJson.Count)
                return false;

            foreach (var kvp in thisJson)
            {
                if (!otherJson.TryGetValue(kvp.Key, out var otherValue))
                    return false;

                if (!object.Equals(kvp.Value, otherValue))
                    return false;
            }

            return true;
        }

        public override int GetHashCode()
        {
            int hash = 17;
            foreach (var kvp in Json())
            {
                hash = hash * 31 + (kvp.Key?.GetHashCode() ?? 0);
                hash = hash * 31 + (kvp.Value?.GetHashCode() ?? 0);
            }
            return hash;
        }
    }
}
