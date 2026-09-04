using CodexGuardian.Control;
using System;
using System.Runtime.ExceptionServices;
using System.Threading;
using System.Threading.Tasks;

namespace CodexGuardian.Broker;

internal interface IBrokerSingleInstanceLeaseV1 : IAsyncDisposable
{
}

internal sealed class BrokerSingleInstanceLeaseException : InvalidOperationException
{
    internal BrokerSingleInstanceLeaseException(
        string code,
        string message,
        Exception? innerException = null)
        : base(message, innerException)
    {
        if (!CodexCdpBrokerProtocol.IsControlIdentifier(code))
        {
            throw new ArgumentException(
                "A bounded Broker singleton failure code is required.",
                nameof(code));
        }

        Code = code;
    }

    internal string Code { get; }
}

internal sealed class BrokerSingleInstanceLeaseV1 : IBrokerSingleInstanceLeaseV1
{
    private const string MutexSuffix = ".lifetime-singleton";

    private readonly object _lifecycleGate = new();
    private readonly ManualResetEventSlim _releaseRequested = new(false);
    private readonly TaskCompletionSource<Exception?> _acquisition = new(
        TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource<Exception?> _release = new(
        TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly Thread _ownerThread;
    private readonly string _mutexName;
    private Task? _disposeTask;

    private BrokerSingleInstanceLeaseV1(string mutexName)
    {
        _mutexName = mutexName;
        _ownerThread = new Thread(OwnMutex)
        {
            IsBackground = true,
            Name = "CodexGuardian Broker singleton owner"
        };
    }

    internal static BrokerSingleInstanceLeaseV1 Acquire(
        string currentUserSid,
        uint sessionId)
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException(
                "The Broker production singleton requires Windows.");
        }

        var endpoint = CodexCdpBrokerProtocol.CreateEndpointName(
            currentUserSid,
            sessionId);
        var lease = new BrokerSingleInstanceLeaseV1(
            "Local\\" + endpoint + MutexSuffix);
        try
        {
            lease._ownerThread.Start();
            var acquisitionFailure = lease._acquisition.Task.GetAwaiter().GetResult();
            if (acquisitionFailure is null)
            {
                return lease;
            }

            var releaseFailure = lease._release.Task.GetAwaiter().GetResult();
            lease.DisposeSynchronizationResources();
            var failure = BrokerControlFailureArbitration.PreserveCleanupFailure(
                acquisitionFailure,
                releaseFailure)!;
            ExceptionDispatchInfo.Capture(failure).Throw();
            throw new InvalidOperationException("Unreachable singleton acquisition failure.");
        }
        catch
        {
            if (!lease._ownerThread.IsAlive)
            {
                lease.DisposeSynchronizationResources();
            }

            throw;
        }
    }

    public ValueTask DisposeAsync()
    {
        lock (_lifecycleGate)
        {
            _disposeTask ??= DisposeCoreAsync();
            return new ValueTask(_disposeTask);
        }
    }

    private void OwnMutex()
    {
        Mutex? mutex = null;
        var acquisitionPublished = false;
        Exception? releaseFailure = null;
        try
        {
            mutex = new Mutex(initiallyOwned: false, _mutexName);
            var ownsMutex = false;
            try
            {
                ownsMutex = mutex.WaitOne(0);
            }
            catch (AbandonedMutexException)
            {
                // An abandoned instance is a cold acquisition. No prior in-memory
                // Broker authority is inherited from the terminated owner.
                ownsMutex = true;
            }

            if (!ownsMutex)
            {
                throw new BrokerSingleInstanceLeaseException(
                    "broker-single-instance-active",
                    "Another Broker already owns this user-session lifetime.");
            }

            acquisitionPublished = true;
            _acquisition.TrySetResult(null);
            _releaseRequested.Wait();
            mutex.ReleaseMutex();
        }
        catch (Exception exception)
        {
            if (!acquisitionPublished)
            {
                _acquisition.TrySetResult(exception);
            }
            else
            {
                releaseFailure = exception;
            }
        }
        finally
        {
            try
            {
                mutex?.Dispose();
            }
            catch (Exception exception)
            {
                releaseFailure = BrokerControlFailureArbitration.PreserveCleanupFailure(
                    releaseFailure,
                    exception);
            }

            if (!acquisitionPublished && !_acquisition.Task.IsCompleted)
            {
                _acquisition.TrySetResult(new BrokerSingleInstanceLeaseException(
                    "broker-single-instance-failed",
                    "The Broker singleton owner thread terminated before acquisition."));
            }

            _release.TrySetResult(releaseFailure);
        }
    }

    private async Task DisposeCoreAsync()
    {
        // Publish the one-shot task before releasing the dedicated mutex owner thread.
        await Task.Yield();
        _releaseRequested.Set();
        var failure = await _release.Task.ConfigureAwait(false);
        DisposeSynchronizationResources();
        if (failure is not null)
        {
            ExceptionDispatchInfo.Capture(failure).Throw();
        }
    }

    private void DisposeSynchronizationResources()
    {
        try
        {
            _releaseRequested.Dispose();
        }
        catch (ObjectDisposedException)
        {
        }
    }
}
