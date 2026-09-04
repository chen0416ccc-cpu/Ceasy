using CodexGuardian.Infrastructure;
using CodexGuardian.Models;
using System.Collections.Specialized;
using System.ComponentModel;

internal static class WorkflowLineageViewModelOfflineTests
{
    internal static async Task RunAsync(Action<bool, string> assert)
    {
        ArgumentNullException.ThrowIfNull(assert);
        await RunCaseAsync(
            "lineage batch initialization emits one reset",
            TestBatchInitializationAsync,
            assert);
        await RunCaseAsync(
            "lineage display updates preserve stable object identity",
            TestStableDisplayUpdateAsync,
            assert);
    }

    private static Task TestBatchInitializationAsync()
    {
        var collection = new ResettableObservableCollection<int>();
        var notifications = new List<NotifyCollectionChangedAction>();
        collection.CollectionChanged += (_, eventArgs) => notifications.Add(eventArgs.Action);

        collection.Initialize(Enumerable.Range(0, 256).ToArray());
        Ensure(
            collection.Count == 256 &&
            notifications.SequenceEqual([NotifyCollectionChangedAction.Reset]),
            "initial lineage materialization did not use one bounded reset");
        Ensure(
            Throws<InvalidOperationException>(() => collection.Initialize([257])),
            "a non-empty collection accepted destructive batch replacement");
        return Task.CompletedTask;
    }

    private static Task TestStableDisplayUpdateAsync()
    {
        var original = Projection("Prepared", WorkflowLineageTone.Neutral);
        var changed = Projection("Confirmed", WorkflowLineageTone.Success);
        var item = new WorkflowLineageDisplayItem(original);
        var propertyNotifications = 0;
        item.PropertyChanged += OnPropertyChanged;

        Ensure(!item.UpdateFrom(original), "an identical lineage row reported a change");
        Ensure(
            item.UpdateFrom(changed) &&
            item.StableRef == original.StableRef &&
            item.StateText == "Confirmed" &&
            item.Tone == WorkflowLineageTone.Success &&
            propertyNotifications == 1,
            "an in-place lineage state update replaced identity or fanned out notifications");
        Ensure(
            Throws<InvalidOperationException>(() => item.UpdateFrom(
                changed with { StableRef = "action-DIFFERENT" })),
            "a lineage display object accepted a changed stable identity");
        return Task.CompletedTask;

        void OnPropertyChanged(object? sender, PropertyChangedEventArgs eventArgs)
        {
            Ensure(
                ReferenceEquals(sender, item) && eventArgs.PropertyName == string.Empty,
                "lineage display update did not use one aggregate property notification");
            propertyNotifications++;
        }
    }

    private static WorkflowLineageDisplayProjection Projection(
        string state,
        WorkflowLineageTone tone) =>
        new(
            "action-ABCDEF123456",
            "WorkflowLineageItem-ABCDEF",
            "Send preset, " + state,
            "Send preset",
            "Source to target",
            "Preset 2",
            state,
            string.Empty,
            "Next",
            "08-18 12:00",
            "Flow ABCDEF",
            IndentWidth: 0,
            IsCorrelationStart: true,
            tone);

    private static async Task RunCaseAsync(
        string name,
        Func<Task> test,
        Action<bool, string> assert)
    {
        try
        {
            await test();
            assert(true, name);
        }
        catch (Exception exception)
        {
            assert(false, name + ": " + exception.Message);
        }
    }

    private static bool Throws<TException>(Action action)
        where TException : Exception
    {
        try
        {
            action();
            return false;
        }
        catch (TException)
        {
            return true;
        }
    }

    private static void Ensure(bool condition, string message)
    {
        if (!condition)
        {
            throw new InvalidOperationException(message);
        }
    }
}
