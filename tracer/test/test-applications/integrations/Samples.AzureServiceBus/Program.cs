using System;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using OpenTelemetry;
using OpenTelemetry.Resources;
using OpenTelemetry.Trace;

namespace Samples.AzureServiceBus
{
    public class Program
    {
        private static readonly bool _fullCapabilities = Environment.GetEnvironmentVariable("FULL_ASB_ENABLED") == "true";
        private static readonly RequestHelper _requestHelper = new(_fullCapabilities);
        private static readonly string _queueNamePrefix = "test-queue-name";

        private static async Task Main(string[] args)
        {
            var serviceName = Environment.GetEnvironmentVariable("DD_SERVICE") ?? "Samples.AzureServiceBus";
            var serviceVersion = Environment.GetEnvironmentVariable("DD_VERSION") ?? "1.0.0";
            AppContext.SetSwitch("Azure.Experimental.EnableActivitySource", true);

            using var tracerProvider = Sdk.CreateTracerProviderBuilder()
                .SetResourceBuilder(
                    ResourceBuilder.CreateDefault()
                        .AddService(serviceName: serviceName, serviceVersion: serviceVersion))
                .AddSource(serviceName)
                .AddAzureServiceBusIfEnvironmentVariablePresent()
                .AddOtlpExporterIfEnvironmentVariablePresent()
                .AddConsoleExporter()
                .Build();

            var tracer = tracerProvider.GetTracer(serviceName);
            var processor = await _requestHelper.InitializeServiceBusProcessor($"{_queueNamePrefix}-eventbased");

            /*
            if (Environment.GetEnvironmentVariable("FULL_ASB_ENABLED") == "true")
            {
                await _requestHelper.ManageSessionAsync($"{_queueNamePrefix}-session");
                await _requestHelper.ScheduleMessagesAndCancelAsync($"{_queueNamePrefix}-scheduling");
            }
            */

            await _requestHelper.SendIndividualMessageAsync(tracer, $"{_queueNamePrefix}-individual");
            await _requestHelper.ReceiveIndividualMessageAsync($"{_queueNamePrefix}-individual");

            await _requestHelper.SendBatchMessagesAsync(tracer, $"{_queueNamePrefix}-batch");
            await _requestHelper.ReceiveBatchMessageAsync($"{_queueNamePrefix}-batch");

            await _requestHelper.SendMessagesToProcessorAsync(tracer, $"{_queueNamePrefix}-eventbased");

            await processor.StopProcessingAsync();

            // API's:
            /*
             * DONE:
                ServiceBusSender.Send	ServiceBusSender.SendMessageAsync|ServiceBusSender.SendMessagesAsync
                ServiceBusSender.Schedule	ServiceBusSender.ScheduleMessageAsync|ServiceBusSender.ScheduleMessagesAsync
                ServiceBusSender.Cancel	ServiceBusSender.CancelScheduledMessageAsync|ServiceBusSender.CancelScheduledMessagesAsync
                ServiceBusReceiver.Receive	ServiceBusReceiver.ReceiveMessageAsync|ServiceBusReceiver.ReceiveMessagesAsync
                ServiceBusReceiver.ReceiveDeferred	ServiceBusReceiver.ReceiveDeferredMessagesAsync
                ServiceBusReceiver.Peek	ServiceBusReceiver.PeekMessageAsync|ServiceBusReceiver.PeekMessagesAsync
                ServiceBusReceiver.Abandon	ServiceBusReceiver.AbandonMessagesAsync
                ServiceBusReceiver.Complete	ServiceBusReceiver.CompleteMessagesAsync
                ServiceBusReceiver.DeadLetter	ServiceBusReceiver.DeadLetterMessagesAsync
                ServiceBusReceiver.Defer	ServiceBusReceiver.DeferMessagesAsync
                ServiceBusReceiver.RenewMessageLock	ServiceBusReceiver.RenewMessageLockAsync
                ServiceBusSessionReceiver.RenewSessionLock	ServiceBusSessionReceiver.RenewSessionLockAsync
                ServiceBusSessionReceiver.GetSessionState	ServiceBusSessionReceiver.GetSessionStateAsync
                ServiceBusSessionReceiver.SetSessionState	ServiceBusSessionReceiver.SetSessionStateAsync
             * TODO:
                ServiceBusProcessor.ProcessMessage	Processor callback set on ServiceBusProcessor. ProcessMessageAsync property
                ServiceBusSessionProcessor.ProcessSessionMessage	Processor callback set on ServiceBusSessionProcessor. ProcessMessageAsync property
            */
        }
    }
}
