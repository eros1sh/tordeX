using System.Diagnostics;
using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;

namespace TordeX.Core.Services;

/// <summary>
/// Checks GitHub Releases for newer versions, downloads the update EXE,
/// and replaces the running binary via rename-and-restart.
/// Uses direct HTTPS (not Tor) since GitHub releases are public.
/// </summary>
public sealed class AutoUpdateService : IDisposable
{
    private const string GitHubApiUrl =
        "https://api.github.com/repos/eros1sh/tordeX/releases/latest";

    private const string UserAgent = "tordeX-updater";

    /// <summary>
    /// ECDSA P-256 public key for verifying update signatures (base64-encoded DER SubjectPublicKeyInfo).
    /// Generate a new keypair with GenerateSigningKeyPair() and embed the public key here.
    /// </summary>
    private const string UpdateVerificationPublicKey =
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE" +
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==";

    private readonly HttpClient _http;
    private CancellationTokenSource? _downloadCts;

    public bool UpdateAvailable { get; private set; }
    public string LatestVersion { get; private set; } = string.Empty;
    public string DownloadUrl { get; private set; } = string.Empty;
    public bool IsDownloading { get; private set; }
    public long DownloadedBytes { get; private set; }
    public long DownloadTotalBytes { get; private set; }
    public bool UpdateDismissed { get; set; }
    public string? ErrorMessage { get; private set; }

    /// <summary>
    /// Raised whenever a property changes so Blazor UI can call StateHasChanged.
    /// </summary>
    public event Action? OnStateChanged;

    public AutoUpdateService()
    {
        _http = new HttpClient();
        _http.DefaultRequestHeaders.Add("User-Agent", UserAgent);
        _http.DefaultRequestHeaders.Add("Accept", "application/vnd.github+json");
        _http.Timeout = TimeSpan.FromSeconds(30);
    }

    /// <summary>
    /// Gets the current assembly version (set via csproj Version property).
    /// </summary>
    public static string CurrentVersion
    {
        get
        {
            var asm = Assembly.GetEntryAssembly();
            var ver = asm?.GetName().Version;
            if (ver is null) return "0.0.0";
            return $"{ver.Major}.{ver.Minor}.{ver.Build}";
        }
    }

    /// <summary>
    /// Queries GitHub Releases API and compares tag_name against the current assembly version.
    /// </summary>
    public async Task CheckForUpdateAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            ErrorMessage = null;
            var response = await _http.GetAsync(GitHubApiUrl, cancellationToken)
                .ConfigureAwait(false);

            if (!response.IsSuccessStatusCode)
                return;

            var json = await response.Content.ReadAsStringAsync(cancellationToken)
                .ConfigureAwait(false);

            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;

            var tagName = root.GetProperty("tag_name").GetString() ?? string.Empty;
            var remoteVersion = tagName.TrimStart('v', 'V');

            if (!Version.TryParse(remoteVersion, out var remote))
                return;

            if (!Version.TryParse(CurrentVersion, out var current))
                return;

            if (remote <= current)
                return;

            // Find the tordeX.exe asset download URL
            if (root.TryGetProperty("assets", out var assets))
            {
                foreach (var asset in assets.EnumerateArray())
                {
                    var name = asset.GetProperty("name").GetString() ?? string.Empty;
                    if (name.Equals("tordeX.exe", StringComparison.OrdinalIgnoreCase))
                    {
                        DownloadUrl = asset.GetProperty("browser_download_url").GetString()
                            ?? string.Empty;
                        break;
                    }
                }
            }

            if (string.IsNullOrEmpty(DownloadUrl))
                return;

            LatestVersion = remoteVersion;
            UpdateAvailable = true;
            NotifyStateChanged();
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or JsonException)
        {
            Debug.WriteLine($"[AutoUpdate] Check failed: {ex.Message}");
        }
    }

    /// <summary>
    /// Downloads the new EXE to a temp file, renames old → .old, moves new → original path,
    /// launches the new process, and signals exit.
    /// </summary>
    /// <returns>True if the caller should exit the application.</returns>
    public async Task<bool> DownloadAndApplyUpdateAsync(CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(DownloadUrl) || IsDownloading)
            return false;

        _downloadCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var ct = _downloadCts.Token;

        IsDownloading = true;
        DownloadedBytes = 0;
        DownloadTotalBytes = 0;
        ErrorMessage = null;
        NotifyStateChanged();

        string? tempPath = null;

        try
        {
            using var response = await _http.GetAsync(DownloadUrl,
                HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
            response.EnsureSuccessStatusCode();

            DownloadTotalBytes = response.Content.Headers.ContentLength ?? 0;
            NotifyStateChanged();

            var currentExePath = Environment.ProcessPath
                ?? Process.GetCurrentProcess().MainModule?.FileName
                ?? throw new InvalidOperationException("Cannot determine current EXE path.");

            var dir = Path.GetDirectoryName(currentExePath)!;
            tempPath = Path.Combine(dir, $"tordeX-update-{Guid.NewGuid():N}.tmp");

            await using (var contentStream = await response.Content.ReadAsStreamAsync(ct)
                .ConfigureAwait(false))
            await using (var fileStream = new FileStream(tempPath, FileMode.Create,
                FileAccess.Write, FileShare.None, bufferSize: 81920, useAsync: true))
            {
                var buffer = new byte[81920];
                int bytesRead;
                while ((bytesRead = await contentStream.ReadAsync(buffer, ct)
                    .ConfigureAwait(false)) > 0)
                {
                    await fileStream.WriteAsync(buffer.AsMemory(0, bytesRead), ct)
                        .ConfigureAwait(false);
                    DownloadedBytes += bytesRead;
                    NotifyStateChanged();
                }
            }

            // Validate downloaded file is at least 1 MB (sanity check)
            var fileInfo = new FileInfo(tempPath);
            if (fileInfo.Length < 1_000_000)
            {
                ErrorMessage = "Downloaded file is too small — possible corruption.";
                IsDownloading = false;
                NotifyStateChanged();
                TryDeleteFile(tempPath);
                return false;
            }

            // SECURITY FIX: CWE-494 — Verify cryptographic signature of downloaded update
            var exeData = await File.ReadAllBytesAsync(tempPath, ct).ConfigureAwait(false);
            var sigVerified = await VerifyUpdateSignatureAsync(exeData, ct).ConfigureAwait(false);
            if (!sigVerified)
            {
                ErrorMessage = "Update signature verification failed — update rejected for security.";
                IsDownloading = false;
                NotifyStateChanged();
                TryDeleteFile(tempPath);
                return false;
            }

            // Swap: rename current → .old, move downloaded → current path
            var oldPath = currentExePath + ".old";
            TryDeleteFile(oldPath);
            File.Move(currentExePath, oldPath);
            File.Move(tempPath, currentExePath);
            tempPath = null; // prevent cleanup since we moved it

            // Launch the new EXE
            Process.Start(new ProcessStartInfo
            {
                FileName = currentExePath,
                UseShellExecute = true,
            });

            IsDownloading = false;
            NotifyStateChanged();
            return true; // caller should exit
        }
        catch (OperationCanceledException)
        {
            ErrorMessage = LocalizationService.T("UpdateCancelled");
            IsDownloading = false;
            NotifyStateChanged();
            if (tempPath is not null) TryDeleteFile(tempPath);
            return false;
        }
        catch (Exception ex)
        {
            ErrorMessage = ex.Message;
            IsDownloading = false;
            NotifyStateChanged();
            if (tempPath is not null) TryDeleteFile(tempPath);
            return false;
        }
    }

    /// <summary>
    /// Cancels an in-progress download.
    /// </summary>
    public void CancelDownload()
    {
        _downloadCts?.Cancel();
    }

    /// <summary>
    /// Deletes leftover .old.exe from a previous update. Call once on startup.
    /// </summary>
    public static void CleanupOldExecutable()
    {
        try
        {
            var currentExePath = Environment.ProcessPath
                ?? Process.GetCurrentProcess().MainModule?.FileName;

            if (currentExePath is null) return;

            var oldPath = currentExePath + ".old";
            TryDeleteFile(oldPath);
        }
        catch
        {
            // Best-effort cleanup — ignore failures
        }
    }

    public void Dispose()
    {
        _downloadCts?.Cancel();
        _downloadCts?.Dispose();
        _http.Dispose();
    }

    /// <summary>
    /// Download and verify the .sig file for the update EXE.
    /// The .sig file is a base64-encoded ECDSA P-256 signature over SHA-256(exeData).
    /// </summary>
    private async Task<bool> VerifyUpdateSignatureAsync(byte[] exeData, CancellationToken ct)
    {
        try
        {
            // Download signature file
            var sigUrl = DownloadUrl + ".sig";
            var sigResponse = await _http.GetAsync(sigUrl, ct).ConfigureAwait(false);
            if (!sigResponse.IsSuccessStatusCode)
            {
                Debug.WriteLine($"[AutoUpdate] Signature file not found at {sigUrl}");
                return false;
            }

            var sigBase64 = (await sigResponse.Content.ReadAsStringAsync(ct)
                .ConfigureAwait(false)).Trim();
            var signature = Convert.FromBase64String(sigBase64);

            return VerifyUpdateSignature(exeData, signature);
        }
        catch (Exception ex) when (ex is HttpRequestException or FormatException or CryptographicException)
        {
            Debug.WriteLine($"[AutoUpdate] Signature verification failed: {ex.Message}");
            return false;
        }
    }

    /// <summary>
    /// Verify ECDSA P-256 signature over SHA-256 hash of the EXE data.
    /// </summary>
    private static bool VerifyUpdateSignature(byte[] exeData, byte[] signature)
    {
        using var ecdsa = ECDsa.Create();
        ecdsa.ImportSubjectPublicKeyInfo(Convert.FromBase64String(UpdateVerificationPublicKey), out _);
        return ecdsa.VerifyData(exeData, signature, HashAlgorithmName.SHA256);
    }

    /// <summary>
    /// Utility: Generate a new ECDSA P-256 signing keypair for release signing.
    /// The public key should be embedded in UpdateVerificationPublicKey.
    /// NOT shipped in production — for developer use only.
    /// </summary>
    public static (string publicKeyBase64, string privateKeyBase64) GenerateSigningKeyPair()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var publicKey = Convert.ToBase64String(ecdsa.ExportSubjectPublicKeyInfo());
        var privateKey = Convert.ToBase64String(ecdsa.ExportPkcs8PrivateKey());
        return (publicKey, privateKey);
    }

    private void NotifyStateChanged() => OnStateChanged?.Invoke();

    private static void TryDeleteFile(string path)
    {
        try
        {
            if (File.Exists(path))
                File.Delete(path);
        }
        catch
        {
            // Best-effort — old file may still be locked
        }
    }
}
