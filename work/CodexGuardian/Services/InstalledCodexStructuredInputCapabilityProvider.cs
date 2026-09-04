using CodexGuardian.Control;
using CodexGuardian.Models;

namespace CodexGuardian.Services;

internal sealed class InstalledCodexStructuredInputCapabilityProvider
    : IDesktopStructuredInputCapabilityProvider
{
    private readonly CodexStructuredInputPackageEvidenceReader _reader;
    private readonly AttachmentLimitSettings _limits;

    internal InstalledCodexStructuredInputCapabilityProvider(
        AttachmentLimitSettings limits,
        CodexStructuredInputPackageEvidenceReader? reader = null)
    {
        ArgumentNullException.ThrowIfNull(limits);
        AttachmentImportLimitGuard.EnsureValidLimits(limits);
        _limits = new AttachmentLimitSettings
        {
            MaximumAttachmentsPerMessage = limits.MaximumAttachmentsPerMessage,
            MaximumBytesPerFile = limits.MaximumBytesPerFile,
            MaximumBytesPerMessage = limits.MaximumBytesPerMessage,
            MaximumLibraryBytes = limits.MaximumLibraryBytes
        };
        _reader = reader ?? new CodexStructuredInputPackageEvidenceReader();
    }

    public Task<DesktopStructuredInputCapabilities> ReadAsync(
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        try
        {
            var evidence = _reader.Read();
            cancellationToken.ThrowIfCancellationRequested();
            var asar = evidence.AppAsar.Snapshot;
            var semantic = new CodexStructuredInputSemanticSnapshot
            {
                Acquisition = StructuredInputEvidenceAcquisition.ReadOnlyAsar,
                PackageName = asar.PackageName,
                ProductName = asar.ProductName,
                PackageVersion = asar.PackageVersion,
                Epoch = evidence.Epoch,
                FollowerMethods = new HashSet<string>(
                    asar.FollowerMethods,
                    StringComparer.Ordinal),
                StartTurnHostHandler = asar.StartTurnHostHandler,
                StartTurnAssertsOwner = asar.StartTurnAssertsOwner,
                NativeMethod = asar.NativeMethod,
                NativeMethodVersion = asar.NativeMethodVersion,
                PreservesInput = asar.PreservesInput,
                PreservesStableClientUserMessageId = asar.PreservesStableClientUserMessageId,
                NativeInputKinds = new HashSet<string>(
                    asar.NativeInputKinds,
                    StringComparer.Ordinal),
                HandlerShapeSha256 = asar.HandlerShapeSha256,
                InputShapeSha256 = asar.InputShapeSha256,
                SupportsAttachmentOnly = asar.SupportsAttachmentOnly,
                MaximumAttachmentCount = _limits.MaximumAttachmentsPerMessage,
                MaximumBytesPerFile = _limits.MaximumBytesPerFile,
                MaximumBytesPerPayload = _limits.MaximumBytesPerMessage
            };
            return Task.FromResult(CodexStructuredInputCapabilityInspector.Inspect(semantic));
        }
        catch (CodexStructuredInputPackageException exception)
            when (exception.IsCompatibilityFailure)
        {
            return Task.FromResult(Unavailable(
                StructuredInputCapabilityState.Unsupported,
                "installed-package-structured-semantics-unsupported"));
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch
        {
            return Task.FromResult(Unavailable(
                StructuredInputCapabilityState.Unknown,
                "installed-package-structured-evidence-unavailable"));
        }
    }

    private static DesktopStructuredInputCapabilities Unavailable(
        StructuredInputCapabilityState state,
        string detail) =>
        new(
            state,
            new HashSet<string>(StringComparer.Ordinal),
            SupportsAttachmentOnly: false,
            MaximumAttachmentCount: 0,
            MaximumBytesPerFile: 0,
            MaximumBytesPerPayload: 0,
            Epoch: 0,
            SemanticFingerprint: string.Empty,
            detail);
}
