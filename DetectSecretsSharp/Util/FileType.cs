using System;
using System.IO;

namespace DetectSecretsSharp.Util
{
    public enum FileType
    {
        Cls = 0,
        Example = 1,
        Go = 2,
        Java = 3,
        JavaScript = 4,
        Php = 5,
        ObjectiveC = 6,
        Python = 7,
        Swift = 8,
        Terraform = 9,
        Yaml = 10,
        CSharp = 11,
        C = 12,
        CPlusPlus = 13,
        Config = 14,
        Ini = 15,
        Properties = 16,
        Toml = 17,
        Other = 18
    }

    public static class FileTypeDetector
    {
        public static FileType DetermineFileType(string filename)
        {
            if (string.IsNullOrEmpty(filename))
                return FileType.Other;

            string ext = Path.GetExtension(filename)?.ToLowerInvariant() ?? "";

            switch (ext)
            {
                case ".cls": return FileType.Cls;
                case ".example": return FileType.Example;
                case ".eyaml":
                case ".yaml":
                case ".yml": return FileType.Yaml;
                case ".go": return FileType.Go;
                case ".java": return FileType.Java;
                case ".js": return FileType.JavaScript;
                case ".m": return FileType.ObjectiveC;
                case ".php": return FileType.Php;
                case ".py":
                case ".pyi": return FileType.Python;
                case ".swift": return FileType.Swift;
                case ".tf": return FileType.Terraform;
                case ".cs": return FileType.CSharp;
                case ".c": return FileType.C;
                case ".cpp": return FileType.CPlusPlus;
                case ".cnf":
                case ".conf":
                case ".cfg":
                case ".cf": return FileType.Config;
                case ".ini": return FileType.Ini;
                case ".properties": return FileType.Properties;
                case ".toml": return FileType.Toml;
                default: return FileType.Other;
            }
        }
    }
}
