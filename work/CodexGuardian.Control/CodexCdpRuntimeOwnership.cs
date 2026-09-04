using System;
using System.Threading;
using System.Threading.Tasks;

namespace CodexGuardian.Control;

internal sealed record CodexCdpRuntimeIdentity
{
    internal CodexCdpRuntimeIdentity(
        string runtimeId,
        string launchOperationId,
        int processId,
        DateTimeOffset creationTimeUtc)
    {
        if (!CodexCdpBrokerProtocol.IsControlIdentifier(runtimeId))
        {
            throw new ArgumentException("A valid runtime identifier is required.", nameof(runtimeId));
        }

        if (!CodexCdpBrokerProtocol.IsControlIdentifier(launchOperationId))
        {
            throw new ArgumentException(
                "A valid launch operation identifier is required.",
                nameof(launchOperationId));
        }

        if (processId <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(processId));
        }

        ValidateUtcTimestamp(creationTimeUtc, nameof(creationTimeUtc));
        RuntimeId = runtimeId;
        LaunchOperationId = launchOperationId;
        ProcessId = processId;
        CreationTimeUtc = creationTimeUtc;
    }

    internal string RuntimeId { get; }

    internal string LaunchOperationId { get; }

    internal int ProcessId { get; }

    internal DateTimeOffset CreationTimeUtc { get; }

    private static void ValidateUtcTimestamp(DateTimeOffset value, string parameterName)
    {
        if (value == default || value.Offset != TimeSpan.Zero)
        {
            throw new ArgumentException("A non-default UTC timestamp is required.", parameterName);
        }
    }
}

internal enum CodexCdpRuntimeExitKind
{
    Natural,
    Faulted
}

internal sealed record CodexCdpRuntimeExitResult
{
    private CodexCdpRuntimeExitResult(
        CodexCdpRuntimeExitKind kind,
        int? exitCode,
        string? failureCode,
        DateTimeOffset observedAtUtc)
    {
        if (observedAtUtc == default || observedAtUtc.Offset != TimeSpan.Zero)
        {
            throw new ArgumentException(
                "A non-default UTC observation timestamp is required.",
                nameof(observedAtUtc));
        }

        Kind = kind;
        ExitCode = exitCode;
        FailureCode = failureCode;
        ObservedAtUtc = observedAtUtc;
    }

    internal CodexCdpRuntimeExitKind Kind { get; }

    internal int? ExitCode { get; }

    internal string? FailureCode { get; }

    internal DateTimeOffset ObservedAtUtc { get; }

    internal static CodexCdpRuntimeExitResult Natural(
        int exitCode,
        DateTimeOffset observedAtUtc) =>
        new(CodexCdpRuntimeExitKind.Natural, exitCode, null, observedAtUtc);

    internal static CodexCdpRuntimeExitResult Faulted(
        string failureCode,
        DateTimeOffset observedAtUtc)
    {
        if (!IsBoundedFailureCode(failureCode))
        {
            throw new ArgumentException(
                "A bounded machine-readable runtime failure code is required.",
                nameof(failureCode));
        }

        return new CodexCdpRuntimeExitResult(
            CodexCdpRuntimeExitKind.Faulted,
            null,
            failureCode,
            observedAtUtc);
    }

    private static bool IsBoundedFailureCode(string? value)
    {
        if (value is null || value.Length is < 3 or > 64)
        {
            return false;
        }

        foreach (var character in value)
        {
            if (!char.IsAsciiLetterOrDigit(character) && character is not '-' and not '_')
            {
                return false;
            }
        }

        return true;
    }
}

internal interface ICodexCdpHandleLease : IAsyncDisposable
{
    CodexCdpRuntimeIdentity Identity { get; }

    bool IsAlive { get; }

    Task<CodexCdpRuntimeExitResult> Exit { get; }
}

internal enum CodexCdpRuntimeReconciliationKind
{
    NoCodex,
    ExternalCodexPresent
}

internal enum CodexCdpRuntimeStartKind
{
    Owned,
    RaceLost
}

internal sealed class CodexCdpRuntimeStartResultV1 : IAsyncDisposable
{
    private readonly object _gate = new();
    private ICodexCdpHandleLease? _ownedLease;
    private Task? _disposeTask;
    private bool _leaseTaken;

    private CodexCdpRuntimeStartResultV1(
        CodexCdpRuntimeStartKind kind,
        ICodexCdpHandleLease? ownedLease)
    {
        Kind = kind;
        _ownedLease = ownedLease;
    }

    internal CodexCdpRuntimeStartKind Kind { get; }

    internal static CodexCdpRuntimeStartResultV1 Owned(ICodexCdpHandleLease lease)
    {
        ArgumentNullException.ThrowIfNull(lease);
        if (!lease.IsAlive || lease.Exit.IsCompleted)
        {
            throw new ArgumentException(
                "An owned runtime result requires one live retained lease.",
                nameof(lease));
        }

        return new CodexCdpRuntimeStartResultV1(CodexCdpRuntimeStartKind.Owned, lease);
    }

    internal static CodexCdpRuntimeStartResultV1 RaceLost() =>
        new(CodexCdpRuntimeStartKind.RaceLost, ownedLease: null);

    internal ICodexCdpHandleLease TakeOwnedLease()
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposeTask is not null, this);
            if (Kind != CodexCdpRuntimeStartKind.Owned || _leaseTaken || _ownedLease is null)
            {
                throw new InvalidOperationException("runtime-start-result-has-no-owned-lease");
            }

            var lease = _ownedLease;
            _ownedLease = null;
            _leaseTaken = true;
            return lease;
        }
    }

    public ValueTask DisposeAsync()
    {
        lock (_gate)
        {
            if (_disposeTask is not null)
            {
                return new ValueTask(_disposeTask);
            }

            var lease = _ownedLease;
            _ownedLease = null;
            _disposeTask = lease is null
                ? Task.CompletedTask
                : DisposeLeaseAsync(lease);
            return new ValueTask(_disposeTask);
        }
    }

    private static async Task DisposeLeaseAsync(ICodexCdpHandleLease lease)
    {
        // Publish the result's one-shot dispose task before lease callbacks can reenter it.
        await Task.Yield();
        await lease.DisposeAsync().ConfigureAwait(false);
    }
}

internal interface ICodexCdpRuntimeControlHost : IAsyncDisposable
{
    ValueTask<CodexCdpRuntimeReconciliationKind> ReconcileAsync(
        CancellationToken cancellationToken = default);

    ValueTask<CodexCdpRuntimeStartResultV1> StartManagedAsync(
        string operationId,
        CancellationToken cancellationToken = default);
}
