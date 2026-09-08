using System;
using System.Windows;
using System.Windows.Media.Animation;

namespace CodexGuardian.Controls;

public sealed class SpringEase : EasingFunctionBase
{
    public SpringEase()
    {
        EasingMode = EasingMode.EaseIn;
    }

    protected override double EaseInCore(double normalizedTime)
    {
        if (!SystemParameters.ClientAreaAnimation)
        {
            return 1;
        }

        if (normalizedTime <= 0 || normalizedTime >= 1)
        {
            return normalizedTime;
        }

        // An underdamped step response, normalized to settle exactly at the final frame.
        static double Response(double time) =>
            1 - Math.Exp(-7.5 * time) * (Math.Cos(11.5 * time) + 7.5 / 11.5 * Math.Sin(11.5 * time));

        return Response(normalizedTime) / Response(1);
    }

    protected override Freezable CreateInstanceCore() => new SpringEase();
}
