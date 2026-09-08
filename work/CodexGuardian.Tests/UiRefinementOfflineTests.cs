using CodexGuardian.Models;
using System.IO;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Markup;
using System.Windows.Media;
using System.Windows.Threading;
using System.Xml.Linq;
using ComboBox = System.Windows.Controls.ComboBox;
using Size = System.Windows.Size;

internal static class UiRefinementOfflineTests
{
    private static readonly XNamespace Presentation = "http://schemas.microsoft.com/winfx/2006/xaml/presentation";
    private static readonly XNamespace Xaml = "http://schemas.microsoft.com/winfx/2006/xaml";

    internal static async Task RunAsync(Action<bool, string> assert)
    {
        ArgumentNullException.ThrowIfNull(assert);
        await RunCaseAsync("conversation headings inherit the themed foreground", TestHeadingThemeAsync, assert);
        await RunCaseAsync("closed combo boxes forward the display-member selector", TestComboBoxContractAsync, assert);
        await RunCaseAsync("closed combo boxes render display names without an application window", TestComboBoxRenderingAsync, assert);
        await RunCaseAsync("the user guide has complete bilingual resources and accurate defaults", TestGuideAsync, assert);
        await RunCaseAsync("technical disclosure preserves visible identity and protection authority", TestTaskDetailsAsync, assert);
    }

    private static Task TestHeadingThemeAsync()
    {
        var main = ReadProductXaml("MainWindow.xaml");
        var app = ReadProductXaml("App.xaml");
        var header = FindNamed(main, "TasksIndexHeaderStage");
        var implicitStyle = app.Descendants(Presentation + "Style").Single(element =>
            Attribute(element, "TargetType") == "TextBlock" && element.Attribute(Xaml + "Key") is null);
        Ensure(HasInkSetter(implicitStyle), "the implicit TextBlock style lost its themed primary foreground");
        foreach (var binding in new[]
                 {
                     "{Binding [Shell.Conversations], Source={StaticResource Loc}}",
                     "{Binding ConversationGroupTitle}"
                 })
        {
            var heading = header.Descendants(Presentation + "TextBlock").Single(element =>
                Attribute(element, "Text") == binding);
            var style = heading.Element(Presentation + "TextBlock.Style")?.Element(Presentation + "Style");
            Ensure(
                Attribute(heading, "Foreground") == "{DynamicResource InkBrush}" ||
                style is not null && (HasInkSetter(style) ||
                    Attribute(style, "BasedOn") == "{StaticResource {x:Type TextBlock}}"),
                "a conversation heading overrides the implicit style without retaining InkBrush: " + binding);
        }

        return Task.CompletedTask;
    }

    private static Task TestComboBoxContractAsync()
    {
        var style = FindKey(ReadProductXaml("App.xaml"), "FieldComboBoxStyle");
        var selectedContent = style.Descendants(Presentation + "ContentPresenter").Single(element =>
            Attribute(element, "Content") ==
                "{Binding SelectionBoxItem, RelativeSource={RelativeSource AncestorType=ComboBox}}");
        Ensure(
            Attribute(selectedContent, "ContentTemplate") ==
                "{Binding SelectionBoxItemTemplate, RelativeSource={RelativeSource AncestorType=ComboBox}}" &&
            Attribute(selectedContent, "ContentTemplateSelector") ==
                "{Binding ItemTemplateSelector, RelativeSource={RelativeSource AncestorType=ComboBox}}" &&
            Attribute(selectedContent, "ContentStringFormat") ==
                "{Binding SelectionBoxItemStringFormat, RelativeSource={RelativeSource AncestorType=ComboBox}}",
            "the closed selection presenter must forward the template, selector, and string format");
        return Task.CompletedTask;
    }

    private static Task TestComboBoxRenderingAsync() => RunStaAsync(() =>
    {
        // Load only the control's resource closure, never the production Application or a Window.
        var app = ReadProductXaml("App.xaml");
        var resourceMarkup = new XElement(
            Presentation + "ResourceDictionary",
            new XAttribute(XNamespace.Xmlns + "x", Xaml.NamespaceName),
            new[] { "BodyFont", "IconFont", "CodexFocusVisual", "FieldComboBoxStyle" }
                .Select(key => new XElement(FindKey(app, key))));
        var resources = (ResourceDictionary)XamlReader.Parse(resourceMarkup.ToString());
        var options = new[]
        {
            new RecoveryCountingModeOption(RecoveryCountingMode.PerFailedTurn, "Per failed turn"),
            new RecoveryCountingModeOption(RecoveryCountingMode.SharedIncidentBudget, "\u5171\u4eab\u5c1d\u8bd5\u9884\u7b97")
        };
        var comboBox = new ComboBox
        {
            Resources = resources,
            Style = (Style)resources["FieldComboBoxStyle"],
            DisplayMemberPath = nameof(RecoveryCountingModeOption.DisplayName),
            ItemsSource = options,
            Width = 280,
            Height = 40
        };

        foreach (var index in Enumerable.Range(0, options.Length))
        {
            comboBox.SelectedIndex = index;
            comboBox.ApplyTemplate();
            comboBox.Measure(new Size(280, 40));
            comboBox.Arrange(new Rect(0, 0, 280, 40));
            comboBox.UpdateLayout();
            Dispatcher.CurrentDispatcher.Invoke(static () => { }, DispatcherPriority.ContextIdle);
            comboBox.UpdateLayout();
            var labels = VisualChildren(comboBox).OfType<TextBlock>().Select(text => text.Text).ToArray();
            Ensure(labels.Contains(options[index].DisplayName, StringComparer.Ordinal),
                "the closed combo box did not render its selected DisplayName");
            Ensure(!labels.Any(text => text.Contains("RecoveryCountingModeOption", StringComparison.Ordinal)),
                "the closed combo box leaked the option record's ToString output");
        }
    });

    private static Task TestGuideAsync()
    {
        var guide = ReadProductXaml(Path.Combine("Views", "UserGuidePage.xaml"));
        var app = ReadProductXaml("App.xaml");
        var zh = ReadResources("AppStrings.resx");
        var en = ReadResources("AppStrings.en.resx");
        var references = new HashSet<string>(StringComparer.Ordinal);
        string[] textAttributes = ["Text", "Content", "Header", "ToolTip", "AutomationProperties.Name", "AutomationProperties.HelpText"];
        foreach (var element in guide.Root!.DescendantsAndSelf())
        {
            foreach (var attribute in element.Attributes().Where(attribute => textAttributes.Contains(attribute.Name.LocalName)))
            {
                if (attribute.Name.LocalName == "Text" && Attribute(element, "FontFamily") == "{StaticResource IconFont}")
                {
                    Ensure(attribute.Value.All(character => character is >= '\uE000' and <= '\uF8FF'),
                        "an icon text field contains hard-coded prose");
                    continue;
                }

                var match = Regex.Match(attribute.Value, @"^\{Binding \[(Guide\.[A-Za-z0-9]+)\], Source=\{StaticResource Loc\}\}$");
                Ensure(match.Success, "guide prose bypasses the localization service: " + attribute.Name);
                references.Add(match.Groups[1].Value);
            }

            if (element.Name.LocalName is "TextBlock" or "Run" or "Span" or "Paragraph")
            {
                Ensure(!element.Nodes().OfType<XText>().Any(text => !string.IsNullOrWhiteSpace(text.Value)),
                    "the guide contains an unlocalized inline text node");
            }
        }

        var zhGuide = zh.Where(pair => pair.Key.StartsWith("Guide.", StringComparison.Ordinal))
            .ToDictionary(pair => pair.Key, pair => pair.Value, StringComparer.Ordinal);
        var enGuide = en.Where(pair => pair.Key.StartsWith("Guide.", StringComparison.Ordinal))
            .ToDictionary(pair => pair.Key, pair => pair.Value, StringComparer.Ordinal);
        Ensure(references.Count >= 20 && references.SetEquals(zhGuide.Keys) && references.SetEquals(enGuide.Keys),
            "the guide has missing, obsolete, or unreferenced bilingual keys");
        Ensure(zhGuide.Values.All(value => !string.IsNullOrWhiteSpace(value)) &&
            enGuide.Values.All(value => !string.IsNullOrWhiteSpace(value) && !Regex.IsMatch(value, @"[\u3400-\u9fff]")),
            "the English guide contains untranslated text or a guide value is empty");
        string[] retiredClaims = ["CodexGuardian", "Claude", "Safety Drill", "SafeDrill", "\u4ec0\u4e48\u90fd\u4e0d\u7528\u505a", "\u5176\u4ed6\u4e34\u65f6\u6027\u9519\u8bef"];
        Ensure(!zhGuide.Values.Concat(enGuide.Values).Any(value => retiredClaims.Any(claim =>
                value.Contains(claim, StringComparison.OrdinalIgnoreCase))),
            "the guide restored a retired product identity or unsupported recovery promise");
        Ensure(zhGuide["Guide.IntroBody"].Contains("Ceasy", StringComparison.Ordinal) &&
            zhGuide["Guide.IntroBody"].Contains("Codex Desktop", StringComparison.Ordinal) &&
            enGuide["Guide.IntroBody"].Contains("Ceasy", StringComparison.Ordinal) &&
            enGuide["Guide.IntroBody"].Contains("Codex Desktop", StringComparison.Ordinal) &&
            zhGuide["Guide.DefaultBody"].Contains("\u9ed8\u8ba4\u4ec5\u76d1\u6d4b", StringComparison.Ordinal) &&
            zhGuide["Guide.DefaultBody"].Contains("\u81ea\u52a8\u6062\u590d\u5173\u95ed", StringComparison.Ordinal) &&
            enGuide["Guide.DefaultBody"].Contains("monitor-only", StringComparison.OrdinalIgnoreCase) &&
            enGuide["Guide.DefaultBody"].Contains("automatic recovery off", StringComparison.OrdinalIgnoreCase),
            "the guide no longer identifies the observed product and monitor-only recovery default");

        var keys = app.Descendants().Concat(guide.Descendants())
            .Select(element => (string?)element.Attribute(Xaml + "Key"))
            .Where(key => key is not null).ToHashSet(StringComparer.Ordinal);
        var missingResources = guide.Descendants().Attributes().SelectMany(attribute =>
                Regex.Matches(attribute.Value, @"\{(?:StaticResource|DynamicResource) ([A-Za-z0-9]+)\}")
                    .Select(match => match.Groups[1].Value))
            .Where(key => !keys.Contains(key)).Distinct(StringComparer.Ordinal).ToArray();
        Ensure(missingResources.Length == 0, "guide references undefined theme resources: " + string.Join(", ", missingResources));
        var back = FindAutomationId(guide, "UserGuideBackButton");
        var guideCode = File.ReadAllText(Path.Combine(FindProductRoot(), "Views", "UserGuidePage.xaml.cs"));
        Ensure(Attribute(back, "Command") == "{Binding NavigateCommand}" &&
            Attribute(guide.Root!, "Loaded") == "UserGuidePage_Loaded" &&
            guideCode.Contains("Window.GetWindow(this) ?? Application.Current?.MainWindow", StringComparison.Ordinal) &&
            guideCode.Contains("SetBinding(DataContextProperty, new Binding(nameof(DataContext)) { Source = owner })", StringComparison.Ordinal) &&
            Attribute(back, "CommandParameter") == "Settings" &&
            !back.Ancestors().Any(element => element.Name.LocalName == "ScrollViewer"),
            "the guide back action no longer returns to preferences outside the scrolling body");
        var scroll = FindAutomationId(guide, "UserGuideScrollViewer");
        Ensure(Attribute(scroll, "VerticalScrollBarVisibility") == "Auto" &&
            Attribute(scroll, "HorizontalScrollBarVisibility") == "Disabled",
            "the guide lost its bounded vertical reading surface");
        return Task.CompletedTask;
    }

    private static Task TestTaskDetailsAsync()
    {
        var main = ReadProductXaml("MainWindow.xaml");
        var content = FindNamed(main, "TaskWorkbenchContentStage");
        var details = FindAutomationId(main, "TaskTechnicalDetailsExpander");
        Ensure(details.Name == Presentation + "Expander" && Attribute(details, "IsExpanded") == "False" &&
            details.Ancestors().Contains(content), "technical details must remain a collapsed disclosure in the task workbench");
        Ensure(Attribute(details, "Expanded") is null && Attribute(details, "Collapsed") is null &&
            !details.DescendantsAndSelf().Attributes().Any(attribute => attribute.Name.LocalName is
                "Command" or "IsChecked" or "SelectedValue"),
            "technical disclosure must not contain a write-capable control or permission-changing event");
        foreach (var path in new[] { "Source", "Cwd", "LatestTurnText" })
        {
            var value = content.Descendants().Single(element => Attribute(element, "Text") == "{Binding SelectedTask." + path + "}");
            Ensure(value.Ancestors().Contains(details), "technical field escaped its disclosure: " + path);
        }

        foreach (var id in new[] { "TaskDiagnosticReference", "TaskAttemptsValue", "ConversationProtectionToggle" })
        {
            var element = FindAutomationId(main, id);
            Ensure(element.Ancestors().Contains(content) &&
                !element.AncestorsAndSelf().TakeWhile(ancestor => ancestor != content)
                    .Any(ancestor => ancestor.Name.LocalName == "Expander" ||
                        Attribute(ancestor, "Visibility") is "Collapsed" or "Hidden"),
                "the always-available diagnostic or protection control became hidden: " + id);
        }

        var identity = FindAutomationId(main, "TaskDiagnosticReference");
        var attempts = FindAutomationId(main, "TaskAttemptsValue");
        var protection = FindAutomationId(main, "ConversationProtectionToggle");
        Ensure(Attribute(identity, "Text") == "{Binding SelectedTask.DiagnosticReference}" && Attribute(identity, "Height") == "0" &&
            Attribute(attempts, "Text") == "{Binding SelectedTask.Attempts}" &&
            Attribute(protection, "IsChecked") == "{Binding SelectedTask.IsEnabled, Mode=TwoWay}" &&
            Attribute(protection, "IsEnabled") == "{Binding SelectedTask.CanToggleProtection}",
            "task identity, attempt projection, or protection binding authority changed");
        Ensure(!content.Descendants(Presentation + "Grid.ColumnDefinitions").Any(definitions =>
                definitions.Elements().Any(column => Attribute(column, "Width") == "7*") &&
                definitions.Elements().Any(column => Attribute(column, "Width") == "4*")),
            "the task workbench restored its permanent competing detail columns");
        var settings = new AppSettings();
        Ensure(settings.MonitorOnly && !settings.AutomaticRecoveryEnabled,
            "a UI refinement changed automatic-recovery defaults");
        return Task.CompletedTask;
    }

    private static bool HasInkSetter(XElement style) => style.Elements(Presentation + "Setter").Any(setter =>
        Attribute(setter, "Property") == "Foreground" && Attribute(setter, "Value") == "{DynamicResource InkBrush}");

    private static string? Attribute(XElement element, string name) => (string?)element.Attribute(name);

    private static XElement FindNamed(XDocument document, string name) => document.Descendants().Single(element =>
        (string?)element.Attribute(Xaml + "Name") == name);

    private static XElement FindKey(XDocument document, string key) => document.Descendants().Single(element =>
        (string?)element.Attribute(Xaml + "Key") == key);

    private static XElement FindAutomationId(XDocument document, string id) => document.Descendants().Single(element =>
        Attribute(element, "AutomationProperties.AutomationId") == id);

    private static XDocument ReadProductXaml(string relativePath) => XDocument.Load(Path.Combine(FindProductRoot(), relativePath));

    private static Dictionary<string, string> ReadResources(string fileName) =>
        XDocument.Load(Path.Combine(FindProductRoot(), "Localization", fileName)).Root!.Elements("data")
            .ToDictionary(element => (string)element.Attribute("name")!, element => (string?)element.Element("value") ?? string.Empty,
                StringComparer.Ordinal);

    private static string FindProductRoot()
    {
        for (var directory = new DirectoryInfo(Environment.CurrentDirectory); directory is not null; directory = directory.Parent)
        {
            foreach (var candidate in new[] { Path.Combine(directory.FullName, "work", "CodexGuardian"), Path.Combine(directory.FullName, "CodexGuardian") })
            {
                if (File.Exists(Path.Combine(candidate, "MainWindow.xaml")))
                {
                    return candidate;
                }
            }
        }

        throw new InvalidOperationException("Run UI contracts from the authoritative project checkout.");
    }

    private static IEnumerable<DependencyObject> VisualChildren(DependencyObject root)
    {
        for (var index = 0; index < VisualTreeHelper.GetChildrenCount(root); index++)
        {
            var child = VisualTreeHelper.GetChild(root, index);
            yield return child;
            foreach (var descendant in VisualChildren(child))
            {
                yield return descendant;
            }
        }
    }

    private static Task RunStaAsync(Action test)
    {
        var completion = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var thread = new Thread(() =>
        {
            try
            {
                test();
                completion.SetResult();
            }
            catch (Exception exception)
            {
                completion.SetException(exception);
            }
            finally
            {
                Dispatcher.CurrentDispatcher.InvokeShutdown();
            }
        }) { IsBackground = true };
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        return completion.Task.WaitAsync(TimeSpan.FromSeconds(15));
    }

    private static async Task RunCaseAsync(string name, Func<Task> test, Action<bool, string> assert)
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

    private static void Ensure(bool condition, string message)
    {
        if (!condition)
        {
            throw new InvalidOperationException(message);
        }
    }
}
