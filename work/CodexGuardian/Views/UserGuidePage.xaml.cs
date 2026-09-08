using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;

namespace CodexGuardian.Views;

public partial class UserGuidePage : Page
{
    public UserGuidePage()
    {
        InitializeComponent();
    }

    private void UserGuidePage_Loaded(object sender, RoutedEventArgs e)
    {
        // Frame navigation does not inherit the shell's data context.
        var owner = Window.GetWindow(this) ?? Application.Current?.MainWindow;
        if (owner is not null)
        {
            SetBinding(DataContextProperty, new Binding(nameof(DataContext)) { Source = owner });
        }
    }
}
