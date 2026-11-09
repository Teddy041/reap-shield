// REAP-Shield launcher.
//
// A small native entry point so users can start the desktop app from a source
// checkout by double-clicking "REAP-Shield Launcher.exe" in the project folder.
//
// What it does, in order:
//   1. If the local Electron binary is missing, it asks for consent and runs
//      "npm install" in a visible console window (first run only). When npm
//      skipped Electron's install script, it runs that script directly.
//   2. If the UI bundle (dist/ui) is missing or older than the UI sources, it
//      runs "npm run build:ui" in a visible console window.
//   3. It starts the local Electron binary on the project folder without a
//      console window and exits.
//
// It only runs npm, Node.js and the Electron binary installed into this
// project's node_modules folder.
//
// Pass --yes to skip the first-run confirmation (for scripted setups).
//
// Rebuild with: powershell -ExecutionPolicy Bypass -File launcher\build.ps1

using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Windows.Forms;

[assembly: AssemblyTitle("REAP-Shield Launcher")]
[assembly: AssemblyDescription("Starts the REAP-Shield desktop app from a source checkout")]
[assembly: AssemblyProduct("REAP-Shield")]
[assembly: AssemblyVersion("1.0.0.0")]
[assembly: AssemblyFileVersion("1.0.0.0")]

internal static class Launcher
{
    private const string Title = "REAP-Shield Launcher";
    private const string NodeDownloadUrl = "https://nodejs.org/en/download";

    [STAThread]
    private static int Main(string[] args)
    {
        bool assumeYes = Array.Exists(args, a =>
            string.Equals(a, "--yes", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(a, "/y", StringComparison.OrdinalIgnoreCase));
        try
        {
            return Run(assumeYes);
        }
        catch (Exception ex)
        {
            ShowError("The launcher stopped unexpectedly:\n\n" + ex.Message);
            return 1;
        }
    }

    private static int Run(bool assumeYes)
    {
        string root = AppDomain.CurrentDomain.BaseDirectory.TrimEnd('\\', '/');

        if (!File.Exists(Path.Combine(root, "package.json")) ||
            !File.Exists(Path.Combine(root, "src", "main", "main.mjs")))
        {
            ShowError("This launcher must stay in the REAP-Shield project folder " +
                      "(next to package.json).\n\nCurrent folder:\n" + root);
            return 1;
        }

        string electron = Path.Combine(root, "node_modules", "electron", "dist", "electron.exe");
        string uiIndex = Path.Combine(root, "dist", "ui", "index.html");
        bool needsInstall = !File.Exists(electron);
        bool needsUiBuild = !File.Exists(uiIndex) || IsUiStale(root, uiIndex);

        if (needsInstall || needsUiBuild)
        {
            string npm = FindOnPath("npm.cmd");
            if (npm == null)
            {
                DialogResult open = MessageBox.Show(
                    "REAP-Shield needs Node.js 22 or newer to run from source, " +
                    "but npm was not found on PATH.\n\n" +
                    "Install Node.js (LTS), then start this launcher again.\n\n" +
                    "Open the Node.js download page now?",
                    Title, MessageBoxButtons.YesNo, MessageBoxIcon.Warning);
                if (open == DialogResult.Yes) OpenUrl(NodeDownloadUrl);
                return 1;
            }

            if (needsInstall)
            {
                DialogResult consent = assumeYes ? DialogResult.OK : MessageBox.Show(
                    "First run: REAP-Shield's dependencies are not installed yet.\n\n" +
                    "The launcher will now run \"npm install\" in this folder. " +
                    "It downloads Electron and the other packages listed in " +
                    "package.json (a few hundred MB) and can take several minutes.\n\n" +
                    "Continue?",
                    Title, MessageBoxButtons.OKCancel, MessageBoxIcon.Information);
                if (consent != DialogResult.OK) return 1;

                if (!RunConsole(root, Quote(npm) + " install", "Installing dependencies"))
                {
                    ShowError("\"npm install\" failed. Check the console output, fix the " +
                              "problem (for example the network connection) and start " +
                              "the launcher again.");
                    return 1;
                }
                if (!File.Exists(electron))
                {
                    // Newer npm versions may skip install scripts, which is where
                    // Electron downloads its binary.
                    string node = Path.Combine(Path.GetDirectoryName(npm), "node.exe");
                    if (!File.Exists(node)) node = FindOnPath("node.exe") ?? "node";
                    RunConsole(root,
                               Quote(node) + " " + Quote(Path.Combine(root, "node_modules", "electron", "install.js")),
                               "Downloading the Electron binary");
                }
                if (!File.Exists(electron))
                {
                    ShowError("\"npm install\" finished, but the Electron binary is missing:\n\n" +
                              electron + "\n\nDelete the node_modules folder and try again.");
                    return 1;
                }
            }

            if (needsUiBuild || !File.Exists(uiIndex))
            {
                if (!RunConsole(root, Quote(npm) + " run build:ui", "Building the user interface"))
                {
                    ShowError("\"npm run build:ui\" failed. Check the console output and " +
                              "start the launcher again.");
                    return 1;
                }
            }
        }

        var start = new ProcessStartInfo(electron, ".")
        {
            WorkingDirectory = root,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        // A leftover ELECTRON_RUN_AS_NODE would make Electron behave like plain Node.
        start.EnvironmentVariables.Remove("ELECTRON_RUN_AS_NODE");
        Process.Start(start);
        return 0;
    }

    // Runs a command in a visible console window so the user can follow
    // progress, and keeps the window open on failure so the error stays readable.
    private static bool RunConsole(string root, string command, string label)
    {
        string script =
            "title " + Title + " - " + label + " & " +
            "echo " + label + "... & echo. & " +
            "call " + command +
            " || (echo. & echo The command failed. & pause & exit /b 1)";

        var start = new ProcessStartInfo("cmd.exe", "/d /s /c \"" + script + "\"")
        {
            WorkingDirectory = root,
            UseShellExecute = false,
            CreateNoWindow = false,
        };
        using (Process process = Process.Start(start))
        {
            process.WaitForExit();
            return process.ExitCode == 0;
        }
    }

    // True when any UI source file (or the Vite config) is newer than the built
    // bundle, for example after "git pull".
    private static bool IsUiStale(string root, string uiIndex)
    {
        DateTime built = File.GetLastWriteTimeUtc(uiIndex);
        string uiSources = Path.Combine(root, "src", "ui");
        if (Directory.Exists(uiSources))
        {
            foreach (string file in Directory.EnumerateFiles(uiSources, "*", SearchOption.AllDirectories))
            {
                if (File.GetLastWriteTimeUtc(file) > built) return true;
            }
        }
        string viteConfig = Path.Combine(root, "vite.config.mjs");
        return File.Exists(viteConfig) && File.GetLastWriteTimeUtc(viteConfig) > built;
    }

    private static string Quote(string value)
    {
        return "\"" + value + "\"";
    }

    private static string FindOnPath(string fileName)
    {
        string path = Environment.GetEnvironmentVariable("PATH") ?? string.Empty;
        foreach (string dir in path.Split(Path.PathSeparator))
        {
            string trimmed = dir.Trim().Trim('"');
            if (trimmed.Length == 0) continue;
            try
            {
                string candidate = Path.Combine(trimmed, fileName);
                if (File.Exists(candidate)) return candidate;
            }
            catch (ArgumentException)
            {
                // Ignore malformed PATH entries.
            }
        }
        return null;
    }

    private static void OpenUrl(string url)
    {
        Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
    }

    private static void ShowError(string message)
    {
        MessageBox.Show(message, Title, MessageBoxButtons.OK, MessageBoxIcon.Error);
    }
}
