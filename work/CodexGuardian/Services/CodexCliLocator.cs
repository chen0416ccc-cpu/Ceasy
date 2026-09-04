using System.Diagnostics;

namespace CodexGuardian.Services;

public sealed class CodexCliLocator
{
    public string? Find()
    {
        var running = FindFromRunningProcesses();
        if (running is not null)
        {
            return running;
        }

        var localRoot = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "OpenAI",
            "Codex",
            "bin");

        if (Directory.Exists(localRoot))
        {
            var candidate = Directory
                .EnumerateFiles(localRoot, "codex.exe", SearchOption.AllDirectories)
                .Select(path => new FileInfo(path))
                .OrderByDescending(file => file.LastWriteTimeUtc)
                .FirstOrDefault();
            if (candidate is not null)
            {
                return candidate.FullName;
            }
        }

        var pathValue = Environment.GetEnvironmentVariable("PATH") ?? string.Empty;
        foreach (var segment in pathValue.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
        {
            var candidate = Path.Combine(segment.Trim(), "codex.exe");
            if (File.Exists(candidate) && !candidate.Contains("WindowsApps", StringComparison.OrdinalIgnoreCase))
            {
                return candidate;
            }
        }

        return null;
    }

    private static string? FindFromRunningProcesses()
    {
        foreach (var process in Process.GetProcessesByName("codex"))
        {
            try
            {
                var path = process.MainModule?.FileName;
                if (path is not null &&
                    File.Exists(path) &&
                    !path.Contains("WindowsApps", StringComparison.OrdinalIgnoreCase))
                {
                    return path;
                }
            }
            catch
            {
                // Process metadata can be unavailable across integrity levels.
            }
            finally
            {
                process.Dispose();
            }
        }

        return null;
    }
}
