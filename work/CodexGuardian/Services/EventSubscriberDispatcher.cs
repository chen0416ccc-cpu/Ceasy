namespace CodexGuardian.Services;

internal static class EventSubscriberDispatcher
{
    internal static void Invoke<TEventArgs>(
        EventHandler<TEventArgs>? subscribers,
        object sender,
        TEventArgs eventArgs,
        Action<Exception>? onSubscriberFailure = null)
    {
        if (subscribers is null)
        {
            return;
        }

        foreach (var subscriber in subscribers.GetInvocationList().Cast<EventHandler<TEventArgs>>())
        {
            try
            {
                subscriber(sender, eventArgs);
            }
            catch (Exception exception)
            {
                try
                {
                    onSubscriberFailure?.Invoke(exception);
                }
                catch
                {
                }
            }
        }
    }
}
