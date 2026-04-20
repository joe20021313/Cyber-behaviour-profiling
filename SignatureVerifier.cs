using System;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Cyber_behaviour_profiling
{
    public enum SignatureTrustState
    {
        NoSignature = 0,
        InvalidSignature = 1,
        Revoked = 2,
        RevocationCheckFailed = 3,
        ValidSignatureUntrustedPublisher = 4,
        TrustedPublisherVerified = 5
    }

    public sealed class SignatureVerificationResult
    {
        public bool HasSignature { get; init; }
        public bool IsCryptographicallyValid { get; init; }
        public bool IsTrustedPublisher { get; init; }
        public SignatureTrustState TrustState { get; init; } = SignatureTrustState.NoSignature;
        public string PublisherName { get; init; } = "";
        public string IssuerName { get; init; } = "";
        public string Thumbprint { get; init; } = "";
        public string Summary { get; init; } = "No digital signature present.";
        public uint HResult { get; init; }

        public bool AllowsTrustDampening => TrustState == SignatureTrustState.TrustedPublisherVerified;

        public string ShortLabel => TrustState switch
        {
            SignatureTrustState.TrustedPublisherVerified => string.IsNullOrWhiteSpace(PublisherName)
                ? "safe (trusted maker)"
                : $"safe (made by {PublisherName})",
            SignatureTrustState.ValidSignatureUntrustedPublisher => string.IsNullOrWhiteSpace(PublisherName)
                ? "signed (but maker is unknown)"
                : $"signed (by {PublisherName}; maker is unknown)",
            SignatureTrustState.Revoked => "signature is broken/cancelled",
            SignatureTrustState.RevocationCheckFailed => "signed, but we couldn't check if it was cancelled",
            SignatureTrustState.InvalidSignature => "signed, but the signature looks fake",
            _ => "no signature found"
        };
    }

    [SupportedOSPlatform("windows")]
    public static class SignatureVerifier
    {
        private static readonly HashSet<string> EmbeddedSignatureExtensions = new(StringComparer.OrdinalIgnoreCase)
        {
            ".exe", ".dll", ".sys", ".ocx", ".scr", ".cpl", ".drv", ".efi"
        };

        private const uint ErrorSuccess = 0;
        private const uint WtdRevokeWholeChain = 0x00000001;
        private const uint TrustENoSignature = 0x800B0100;
        private const uint TrustESubjectNotTrusted = 0x800B0004; // Zone.Identifier ADS (downloaded from internet, not unblocked)
        private const uint CertERevoked = 0x800B010C;
        private const uint CryptENoRevocationCheck = 0x80092012;
        private const uint CryptERevocationOffline = 0x80092013;

        private static readonly Guid WintrustActionGenericVerify =
            new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

        internal static Func<string, SignatureVerificationResult>? TestOverride { get; set; }

        [DllImport("wintrust.dll", SetLastError = false, CharSet = CharSet.Unicode)]
        private static extern uint WinVerifyTrust(IntPtr hwnd, ref Guid pgActionID, ref WINTRUST_DATA pWVTData);

        [StructLayout(LayoutKind.Sequential)]
        private struct WINTRUST_FILE_INFO
        {
            public uint cbStruct;
            public IntPtr pcwszFilePath;
            public IntPtr hFile;
            public IntPtr pgKnownSubject;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct WINTRUST_DATA
        {
            public uint cbStruct;
            public IntPtr pPolicyCallbackData;
            public IntPtr pSIPClientData;
            public uint dwUIChoice;
            public uint fdwRevocationChecks;
            public uint dwUnionChoice;
            public IntPtr pFile;
            public uint dwStateAction;
            public IntPtr hWVTStateData;
            public IntPtr pwszURLReference;
            public uint dwProvFlags;
            public uint dwUIContext;
            public IntPtr pSignatureSettings;
        }

        internal static IDisposable PushTestOverride(Func<string, SignatureVerificationResult> overrideFunc)
        {
            ArgumentNullException.ThrowIfNull(overrideFunc);

            var previous = TestOverride;
            TestOverride = overrideFunc;
            return new TestOverrideScope(() => TestOverride = previous);
        }

        internal static bool SupportsEmbeddedSignature(string? filePath)
        {
            if (string.IsNullOrWhiteSpace(filePath))
                return false;

            return EmbeddedSignatureExtensions.Contains(Path.GetExtension(filePath));
        }

        public static SignatureVerificationResult VerifyFile(string? filePath)
        {
            if (TestOverride != null && !string.IsNullOrWhiteSpace(filePath))
                return TestOverride(filePath);

            if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath))
            {
                return new SignatureVerificationResult
                {
                    TrustState = SignatureTrustState.NoSignature,
                    Summary = "No digital signature present."
                };
            }

            uint authResult = VerifyAuthenticode(filePath);
            bool hasSignature = authResult != TrustENoSignature;
            X509Certificate2? certificate = TryLoadCertificate(filePath);

            string publisherName = certificate == null ? "" : GetPublisherName(certificate);
            string issuerName = certificate == null ? "" : GetIssuerName(certificate);
            string thumbprint = certificate?.Thumbprint ?? "";

            if (!hasSignature)
            {
                return new SignatureVerificationResult
                {
                    HasSignature = false,
                    TrustState = SignatureTrustState.NoSignature,
                    PublisherName = publisherName,
                    IssuerName = issuerName,
                    Thumbprint = thumbprint,
                    Summary = "No digital signature present."
                };
            }

            if (authResult == CertERevoked)
            {
                return CreateResult(
                    SignatureTrustState.Revoked,
                    hasSignature: true,
                    isCryptographicallyValid: false,
                    isTrustedPublisher: false,
                    publisherName,
                    issuerName,
                    thumbprint,
                    BuildRevokedSummary(publisherName),
                    hresult: authResult);
            }

            bool chainRevoked = false;
            bool revocationUnknown = authResult == CryptENoRevocationCheck || authResult == CryptERevocationOffline;
            bool chainValid = false;

            if (certificate != null)
            {
                chainValid = BuildChain(certificate, out chainRevoked, out bool chainRevocationUnknown);
                revocationUnknown |= chainRevocationUnknown;
            }

            if (chainRevoked)
            {
                return CreateResult(
                    SignatureTrustState.Revoked,
                    hasSignature: true,
                    isCryptographicallyValid: false,
                    isTrustedPublisher: false,
                    publisherName,
                    issuerName,
                    thumbprint,
                    BuildRevokedSummary(publisherName),
                    hresult: authResult);
            }

            if (revocationUnknown)
            {
                return CreateResult(
                    SignatureTrustState.RevocationCheckFailed,
                    hasSignature: true,
                    isCryptographicallyValid: false,
                    isTrustedPublisher: false,
                    publisherName,
                    issuerName,
                    thumbprint,
                    BuildRevocationUnknownSummary(publisherName));
            }

            // TRUST_E_SUBJECT_NOT_TRUSTED means the Authenticode hash check passed but Windows
            // zone policy blocked trust (Zone.Identifier ADS — file downloaded from internet).
            // If the chain independently validates, the signature is genuinely valid.
            if (authResult == TrustESubjectNotTrusted && chainValid)
            {
                bool isTrusted = MatchesTrustedPublisher(publisherName);
                return CreateResult(
                    isTrusted
                        ? SignatureTrustState.TrustedPublisherVerified
                        : SignatureTrustState.ValidSignatureUntrustedPublisher,
                    hasSignature: true,
                    isCryptographicallyValid: true,
                    isTrustedPublisher: isTrusted,
                    publisherName,
                    issuerName,
                    thumbprint,
                    isTrusted
                        ? BuildTrustedPublisherSummary(publisherName)
                        : BuildUntrustedPublisherSummary(publisherName),
                    hresult: authResult);
            }

            bool cryptographicallyValid = authResult == ErrorSuccess && (certificate == null || chainValid);
            if (!cryptographicallyValid)
            {
                return CreateResult(
                    SignatureTrustState.InvalidSignature,
                    hasSignature: true,
                    isCryptographicallyValid: false,
                    isTrustedPublisher: false,
                    publisherName,
                    issuerName,
                    thumbprint,
                    BuildInvalidSignatureSummary(publisherName),
                    hresult: authResult);
            }

            bool trustedPublisher = MatchesTrustedPublisher(publisherName);
            return CreateResult(
                trustedPublisher
                    ? SignatureTrustState.TrustedPublisherVerified
                    : SignatureTrustState.ValidSignatureUntrustedPublisher,
                hasSignature: true,
                isCryptographicallyValid: true,
                isTrustedPublisher: trustedPublisher,
                publisherName,
                issuerName,
                thumbprint,
                trustedPublisher
                    ? BuildTrustedPublisherSummary(publisherName)
                    : BuildUntrustedPublisherSummary(publisherName));
        }

        private static SignatureVerificationResult CreateResult(
            SignatureTrustState trustState,
            bool hasSignature,
            bool isCryptographicallyValid,
            bool isTrustedPublisher,
            string publisherName,
            string issuerName,
            string thumbprint,
            string summary,
            uint hresult = 0) =>
            new()
            {
                TrustState = trustState,
                HasSignature = hasSignature,
                IsCryptographicallyValid = isCryptographicallyValid,
                IsTrustedPublisher = isTrustedPublisher,
                PublisherName = publisherName,
                IssuerName = issuerName,
                Thumbprint = thumbprint,
                Summary = summary,
                HResult = hresult
            };

        private static string BuildTrustedPublisherSummary(string publisherName) =>
            string.IsNullOrWhiteSpace(publisherName)
                ? "Trusted digital signature verified through Authenticode, certificate-chain, and revocation checks."
                : $"Trusted digital signature verified for publisher '{publisherName}'.";

        private static string BuildUntrustedPublisherSummary(string publisherName) =>
            string.IsNullOrWhiteSpace(publisherName)
                ? "A valid digital signature is present, but the signer identity could not be matched to a trusted public vendor."
                : $"A valid digital signature is present for '{publisherName}', but the signer is not on the trusted public-vendor list.";

        private static string BuildInvalidSignatureSummary(string publisherName) =>
            string.IsNullOrWhiteSpace(publisherName)
                ? "A digital signature is present, but trust validation failed."
                : $"A digital signature is present for '{publisherName}', but trust validation failed.";

        private static string BuildRevokedSummary(string publisherName) =>
            string.IsNullOrWhiteSpace(publisherName)
                ? "A digital signature is present, but the signing certificate is revoked."
                : $"A digital signature is present for '{publisherName}', but the signing certificate is revoked.";

        private static string BuildRevocationUnknownSummary(string publisherName) =>
            string.IsNullOrWhiteSpace(publisherName)
                ? "A digital signature is present, but revocation status could not be verified. No trust dampeners were applied."
                : $"A digital signature is present for '{publisherName}', but revocation status could not be verified. No trust dampeners were applied.";

        private static bool MatchesTrustedPublisher(string publisherName)
        {
            if (string.IsNullOrWhiteSpace(publisherName))
                return false;

            string normalizedPublisher = NormalizePublisherName(publisherName);
            return MapToData._trustedPublishers.Any(allowed =>
                NormalizePublisherName(allowed).Equals(normalizedPublisher, StringComparison.OrdinalIgnoreCase));
        }

        private static bool BuildChain(
            X509Certificate2 certificate,
            out bool chainRevoked,
            out bool revocationUnknown)
        {
            chainRevoked = false;
            revocationUnknown = false;

            using var chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = X509RevocationMode.Online;
            chain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
            chain.ChainPolicy.VerificationTime = DateTime.UtcNow;
            chain.ChainPolicy.UrlRetrievalTimeout = TimeSpan.FromSeconds(15);
            chain.ChainPolicy.ApplicationPolicy.Add(new Oid("1.3.6.1.5.5.7.3.3"));

            bool valid = chain.Build(certificate);
            chainRevoked = chain.ChainStatus.Any(status =>
                status.Status.HasFlag(X509ChainStatusFlags.Revoked));
            revocationUnknown = chain.ChainStatus.Any(status =>
                status.Status.HasFlag(X509ChainStatusFlags.RevocationStatusUnknown) ||
                status.Status.HasFlag(X509ChainStatusFlags.OfflineRevocation));

            return valid && !chainRevoked && !revocationUnknown;
        }

        private static X509Certificate2? TryLoadCertificate(string filePath)
        {
            try
            {
#pragma warning disable SYSLIB0057
                var certificate = X509Certificate.CreateFromSignedFile(filePath);
#pragma warning restore SYSLIB0057
                return certificate == null ? null : new X509Certificate2(certificate);
            }
            catch
            {
                return null;
            }
        }

        private static string GetPublisherName(X509Certificate2 certificate)
        {
            string organizationName = ExtractDistinguishedNameValue(certificate.Subject, "O");
            if (!string.IsNullOrWhiteSpace(organizationName))
                return organizationName;

            string simpleName = certificate.GetNameInfo(X509NameType.SimpleName, false) ?? "";
            return NormalizePublisherName(simpleName);
        }

        private static string GetIssuerName(X509Certificate2 certificate)
        {
            string organizationName = ExtractDistinguishedNameValue(certificate.Issuer, "O");
            if (!string.IsNullOrWhiteSpace(organizationName))
                return organizationName;

            string simpleName = certificate.GetNameInfo(X509NameType.SimpleName, true) ?? "";
            return NormalizePublisherName(simpleName);
        }

        private static string ExtractDistinguishedNameValue(string distinguishedName, string key)
        {
            if (string.IsNullOrWhiteSpace(distinguishedName))
                return "";

            foreach (string part in distinguishedName.Split(','))
            {
                string trimmed = part.Trim();
                if (trimmed.StartsWith(key + "=", StringComparison.OrdinalIgnoreCase))
                    return NormalizePublisherName(trimmed[(key.Length + 1)..].Trim().Trim('"'));
            }

            return "";
        }

        private static string NormalizePublisherName(string value)
        {
            if (string.IsNullOrWhiteSpace(value))
                return "";

            return string.Join(" ", value.Trim().Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries));
        }

        private static uint VerifyAuthenticode(string filePath)
        {
            IntPtr filePathPtr = IntPtr.Zero;
            IntPtr fileInfoPtr = IntPtr.Zero;

            try
            {
                filePathPtr = Marshal.StringToHGlobalUni(filePath);
                var fileInfo = new WINTRUST_FILE_INFO
                {
                    cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>(),
                    pcwszFilePath = filePathPtr,
                    hFile = IntPtr.Zero,
                    pgKnownSubject = IntPtr.Zero
                };

                fileInfoPtr = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_FILE_INFO>());
                Marshal.StructureToPtr(fileInfo, fileInfoPtr, false);

                Guid actionId = WintrustActionGenericVerify;
                var trustData = new WINTRUST_DATA
                {
                    cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
                    pPolicyCallbackData = IntPtr.Zero,
                    pSIPClientData = IntPtr.Zero,
                    dwUIChoice = 2,
                    fdwRevocationChecks = WtdRevokeWholeChain,
                    dwUnionChoice = 1,
                    pFile = fileInfoPtr,
                    dwStateAction = 0,
                    hWVTStateData = IntPtr.Zero,
                    pwszURLReference = IntPtr.Zero,
                    dwProvFlags = 0,
                    dwUIContext = 0,
                    pSignatureSettings = IntPtr.Zero
                };

                return WinVerifyTrust(IntPtr.Zero, ref actionId, ref trustData);
            }
            catch
            {
                return TrustENoSignature;
            }
            finally
            {
                if (filePathPtr != IntPtr.Zero)
                    Marshal.FreeHGlobal(filePathPtr);
                if (fileInfoPtr != IntPtr.Zero)
                    Marshal.FreeHGlobal(fileInfoPtr);
            }
        }

        private sealed class TestOverrideScope : IDisposable
        {
            private readonly Action _onDispose;
            private bool _disposed;

            public TestOverrideScope(Action onDispose)
            {
                _onDispose = onDispose;
            }

            public void Dispose()
            {
                if (_disposed)
                    return;

                _disposed = true;
                _onDispose();
            }
        }
    }
}