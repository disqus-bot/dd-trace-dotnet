// <copyright file="RunCiCommand.cs" company="Datadog">
// Unless explicitly stated otherwise all files in this repository are licensed under the Apache 2 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/). Copyright 2017 Datadog, Inc.
// </copyright>

using System;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Datadog.Trace.Agent.DiscoveryService;
using Datadog.Trace.Ci;
using Datadog.Trace.Ci.Tags;
using Datadog.Trace.Logging;
using Datadog.Trace.Util;
using Spectre.Console;
using Spectre.Console.Cli;

namespace Datadog.Trace.Tools.Runner
{
    internal class RunCiCommand : AsyncCommand<RunCiSettings>
    {
        private static readonly IDatadogLogger Log = DatadogLogging.GetLoggerFor(typeof(RunCiCommand));
        private readonly ApplicationContext _applicationContext;

        public RunCiCommand(ApplicationContext applicationContext)
        {
            _applicationContext = applicationContext;
        }

        public override async Task<int> ExecuteAsync(CommandContext context, RunCiSettings settings)
        {
            // CI Visibility mode is enabled.
            var args = RunHelper.GetArguments(context, settings);
            var program = args[0];
            var arguments = args.Count > 1 ? Utils.GetArgumentsAsString(args.Skip(1)) : string.Empty;

            // Get profiler environment variables
            if (!RunHelper.TryGetEnvironmentVariables(_applicationContext, settings, out var profilerEnvironmentVariables))
            {
                return 1;
            }

            // We force CIVisibility mode on child process
            profilerEnvironmentVariables[Configuration.ConfigurationKeys.CIVisibility.Enabled] = "1";

            // We check the settings and merge with the command settings options
            var ciVisibilitySettings = CIVisibility.Settings;
            var agentless = ciVisibilitySettings.Agentless;
            var apiKey = ciVisibilitySettings.ApiKey;
            var applicationKey = ciVisibilitySettings.ApplicationKey;
            if (!string.IsNullOrEmpty(settings?.ApiKey))
            {
                agentless = true;
                apiKey = settings.ApiKey;
                profilerEnvironmentVariables[Configuration.ConfigurationKeys.CIVisibility.AgentlessEnabled] = "1";
                profilerEnvironmentVariables[Configuration.ConfigurationKeys.ApiKey] = settings.ApiKey;
            }

            // If the agentless feature flag is enabled, we check for ApiKey
            // If the agentless feature flag is disabled, we check if we have connection to the agent before running the process.
            AgentConfiguration agentConfiguration = null;
            IDiscoveryService discoveryService = NullDiscoveryService.Instance;
            if (agentless)
            {
                Log.Debug("RunCiCommand: Agentless has been enabled. Checking API key");
                if (string.IsNullOrWhiteSpace(apiKey))
                {
                    Utils.WriteError("An API key is required in Agentless mode.");
                    Log.Error("RunHelper: An API key is required in Agentless mode.");
                    return 1;
                }
            }
            else
            {
                Log.Debug("RunCiCommand: Agent-based mode has been enabled. Checking agent connection.");
                (agentConfiguration, discoveryService) = await Utils.CheckAgentConnectionAsync(settings.AgentUrl).ConfigureAwait(false);
                if (agentConfiguration is null)
                {
                    Log.Error("RunCiCommand: Agent configuration cannot be retrieved.");
                    return 1;
                }
            }

            // Set Agentless configuration from the command line options
            ciVisibilitySettings.SetAgentlessConfiguration(agentless, apiKey, applicationKey, ciVisibilitySettings.AgentlessUrl);

            // Initialize flags to enable code coverage and test skipping
            var codeCoverageEnabled = ciVisibilitySettings.CodeCoverageEnabled == true || ciVisibilitySettings.TestsSkippingEnabled == true;
            var testSkippingEnabled = ciVisibilitySettings.TestsSkippingEnabled == true;

            var createTestSession = false;
            string codeCoveragePath = null;
            var hasEvpProxy = !string.IsNullOrEmpty(agentConfiguration?.EventPlatformProxyEndpoint);
            if (agentless || hasEvpProxy)
            {
                // Initialize CI Visibility with the current settings
                Log.Debug("RunCiCommand: Initialize CI Visibility for the runner.");
                CIVisibility.InitializeFromRunner(ciVisibilitySettings, discoveryService, hasEvpProxy);

                // Upload git metadata by default (unless is disabled explicitly) or if ITR is enabled (required).
                Log.Debug("RunCiCommand: Uploading repository changes.");
                var lazyItrClient = new Lazy<IntelligentTestRunnerClient>(() => new(CIEnvironmentValues.Instance.WorkspacePath, ciVisibilitySettings));
                if (ciVisibilitySettings.GitUploadEnabled != false || ciVisibilitySettings.IntelligentTestRunnerEnabled)
                {
                    await lazyItrClient.Value.UploadRepositoryChangesAsync().ConfigureAwait(false);

                    // Once the repository has been uploaded we switch off the git upload in children processes
                    profilerEnvironmentVariables[Configuration.ConfigurationKeys.CIVisibility.GitUploadEnabled] = "0";
                    EnvironmentHelpers.SetEnvironmentVariable(Configuration.ConfigurationKeys.CIVisibility.GitUploadEnabled, "0");
                }

                // We can activate all features here (Agentless or EVP proxy mode)
                createTestSession = true;
                if (!agentless)
                {
                    // EVP proxy is enabled.
                    // By setting the environment variables we avoid the usage of the DiscoveryService in each child process
                    // to ask for EVP proxy support.
                    profilerEnvironmentVariables[Configuration.ConfigurationKeys.CIVisibility.ForceAgentsEvpProxy] = "1";
                    EnvironmentHelpers.SetEnvironmentVariable(Configuration.ConfigurationKeys.CIVisibility.ForceAgentsEvpProxy, "1");
                    Log.Debug("RunCiCommand: EVP proxy was detected.");
                }

                // If we have api and application key, and the code coverage or the tests skippable environment variables
                // are not set when the intelligent test runner is enabled, we query the settings api to check if it should enable coverage or not.
                var useConfigurationApi = !agentless || !string.IsNullOrEmpty(applicationKey);
                if (!useConfigurationApi)
                {
                    Log.Debug("RunCiCommand: Application key is empty, call to configuration api skipped.");
                }
                else if (!ciVisibilitySettings.IntelligentTestRunnerEnabled)
                {
                    Log.Debug("RunCiCommand: Intelligent test runner is disabled, call to configuration api skipped.");
                }

                // If we still don't know if we have to enable code coverage or test skipping, then let's request the configuration API
                if (useConfigurationApi
                 && ciVisibilitySettings.IntelligentTestRunnerEnabled
                 && (ciVisibilitySettings.CodeCoverageEnabled == null || ciVisibilitySettings.TestsSkippingEnabled == null))
                {
                    try
                    {
                        CIVisibility.Log.Debug("RunCiCommand: Calling configuration api...");

                        // we skip the framework info because we are interested in the target projects info not the runner one.
                        var itrSettings = await lazyItrClient.Value.GetSettingsAsync(skipFrameworkInfo: true).ConfigureAwait(false);
                        codeCoverageEnabled = itrSettings.CodeCoverage == true || itrSettings.TestsSkipping == true;
                        testSkippingEnabled = itrSettings.TestsSkipping == true;
                    }
                    catch (Exception ex)
                    {
                        CIVisibility.Log.Warning(ex,  "Error getting ITR settings from configuration api");
                    }
                }
            }

            Log.Debug("RunCiCommand: CodeCoverageEnabled = {Value}", codeCoverageEnabled);
            Log.Debug("RunCiCommand: TestSkippingEnabled = {Value}", testSkippingEnabled);
            ciVisibilitySettings.SetCodeCoverageEnabled(codeCoverageEnabled);
            profilerEnvironmentVariables[Configuration.ConfigurationKeys.CIVisibility.CodeCoverage] = codeCoverageEnabled ? "1" : "0";

            // Let's set the code coverage datacollector if the code coverage is enabled
            if (codeCoverageEnabled)
            {
                // Check if we are running dotnet process
                if (string.Equals(program, "dotnet", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(program, "VSTest.Console", StringComparison.OrdinalIgnoreCase))
                {
                    var isTestCommand = false;
                    var isVsTestCommand = string.Equals(program, "VSTest.Console", StringComparison.OrdinalIgnoreCase);
                    foreach (var arg in args.Skip(1))
                    {
                        isTestCommand |= string.Equals(arg, "test", StringComparison.OrdinalIgnoreCase);
                        isVsTestCommand |= string.Equals(arg, "vstest", StringComparison.OrdinalIgnoreCase);

                        if (isTestCommand || isVsTestCommand)
                        {
                            break;
                        }
                    }

                    // Add the Datadog coverage collector
                    var baseDirectory = Path.GetDirectoryName(typeof(Coverage.Collector.CoverageCollector).Assembly.Location);
                    if (isTestCommand)
                    {
                        arguments += " --collect DatadogCoverage --test-adapter-path \"" + baseDirectory + "\"";
                    }
                    else if (isVsTestCommand)
                    {
                        arguments += " /Collect:DatadogCoverage /TestAdapterPath:\"" + baseDirectory + "\"";
                    }

                    // Sets the code coverage path to store the json files for each module.
                    var outputFolders = new[] { Environment.CurrentDirectory, Path.GetTempPath(), };
                    foreach (var folder in outputFolders)
                    {
                        var outputPath = Path.Combine(folder, $"datadog-coverage-{DateTime.Now:yyyy-MM-dd_HH_mm_ss}");
                        if (!Directory.Exists(outputPath))
                        {
                            try
                            {
                                Directory.CreateDirectory(outputPath);
                                profilerEnvironmentVariables[Configuration.ConfigurationKeys.CIVisibility.CodeCoveragePath] = outputPath;
                                EnvironmentHelpers.SetEnvironmentVariable(Configuration.ConfigurationKeys.CIVisibility.CodeCoveragePath, outputPath);
                                codeCoveragePath = outputPath;
                                break;
                            }
                            catch (Exception ex)
                            {
                                Utils.WriteError("Error creating folder for the global code coverage files:");
                                AnsiConsole.WriteException(ex);
                            }
                        }
                    }
                }
            }

            // Final command to execute
            var command = $"{program} {arguments}".Trim();

            // We create a test session if the flag is turned on (agentless or evp proxy)
            TestSession session = null;
            if (createTestSession && Program.CallbackForTests is null)
            {
                session = TestSession.GetOrCreate(command, null, null, null, true);
                session.SetTag(CommonTags.TestSessionTestsSkippingEnabled, testSkippingEnabled ? "true" : "false");
                session.SetTag(CommonTags.TestSessionCodeCoverageEnabled, codeCoverageEnabled ? "true" : "false");

                // At session level we know if the ITR is disabled (meaning that no tests will be skipped)
                // In that case we tell the backend no tests are going to be skipped.
                if (!testSkippingEnabled)
                {
                    session.SetTag(CommonTags.TestsSkipped, "false");
                }
            }

            // Run child process
            var exitCode = 0;
            try
            {
                AnsiConsole.WriteLine("Running: " + command);

                if (Program.CallbackForTests != null)
                {
                    Program.CallbackForTests(program, arguments, profilerEnvironmentVariables);
                    return 0;
                }

                Log.Debug("RunCiCommand: Launching: {Value}", command);
                var processInfo = Utils.GetProcessStartInfo(program, Environment.CurrentDirectory, profilerEnvironmentVariables);
                if (!string.IsNullOrEmpty(arguments))
                {
                    processInfo.Arguments = arguments;
                }

                exitCode = Utils.RunProcess(processInfo, _applicationContext.TokenSource.Token);
                session?.SetTag(TestTags.CommandExitCode, exitCode);
                Log.Debug<int>("RunCiCommand: Finished with exit code: {Value}", exitCode);
                return exitCode;
            }
            catch (Exception ex)
            {
                session?.SetErrorInfo(ex);
                throw;
            }
            finally
            {
                if (session is not null)
                {
                    // If the code coverage path is set we try to read all json files created, merge them into a single one and extract the
                    // global code coverage percentage.
                    // Note: we also write the total global code coverage to the `session-coverage-{date}.json` file
                    if (!string.IsNullOrEmpty(codeCoveragePath))
                    {
                        var outputPath = Path.Combine(codeCoveragePath, $"session-coverage-{DateTime.Now:yyyy-MM-dd_HH_mm_ss}.json");
                        if (CoverageUtils.TryCombineAndGetTotalCoverage(codeCoveragePath, outputPath, out var globalCoverage, useStdOut: false) &&
                            globalCoverage is not null)
                        {
                            // Adds the global code coverage percentage to the session
                            session.SetTag(CommonTags.CodeCoverageTotalLines, globalCoverage.Data[0].ToString(CultureInfo.InvariantCulture));
                        }
                    }

                    await session.CloseAsync(exitCode == 0 ? TestStatus.Pass : TestStatus.Fail).ConfigureAwait(false);
                }
            }
        }

        public override ValidationResult Validate(CommandContext context, RunCiSettings settings)
        {
            var runValidation = RunHelper.Validate(context, settings);
            return !runValidation.Successful ? runValidation : base.Validate(context, settings);
        }
    }
}
