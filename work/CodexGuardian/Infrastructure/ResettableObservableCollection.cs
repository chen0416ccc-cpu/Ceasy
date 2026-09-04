using System.Collections.ObjectModel;
using System.Collections.Specialized;
using System.ComponentModel;

namespace CodexGuardian.Infrastructure;

internal sealed class ResettableObservableCollection<T> : ObservableCollection<T>
{
    internal void ReplaceAll(IReadOnlyList<T> items)
    {
        ArgumentNullException.ThrowIfNull(items);
        CheckReentrancy();
        Items.Clear();
        foreach (var item in items)
        {
            Items.Add(item);
        }

        OnPropertyChanged(new PropertyChangedEventArgs(nameof(Count)));
        OnPropertyChanged(new PropertyChangedEventArgs("Item[]"));
        OnCollectionChanged(new NotifyCollectionChangedEventArgs(
            NotifyCollectionChangedAction.Reset));
    }

    internal void Initialize(IReadOnlyList<T> items)
    {
        ArgumentNullException.ThrowIfNull(items);
        if (Count != 0)
        {
            throw new InvalidOperationException("Batch initialization requires an empty collection.");
        }

        if (items.Count == 0)
        {
            return;
        }

        CheckReentrancy();
        foreach (var item in items)
        {
            Items.Add(item);
        }

        OnPropertyChanged(new PropertyChangedEventArgs(nameof(Count)));
        OnPropertyChanged(new PropertyChangedEventArgs("Item[]"));
        OnCollectionChanged(new NotifyCollectionChangedEventArgs(
            NotifyCollectionChangedAction.Reset));
    }
}
