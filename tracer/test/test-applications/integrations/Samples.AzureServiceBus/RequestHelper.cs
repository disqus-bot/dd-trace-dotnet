using System;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.Diagnostics;
using System.Threading.Tasks;
using Azure.Messaging.ServiceBus;
using OpenTelemetry.Trace;

namespace Samples.AzureServiceBus
{
    class RequestHelper
    {
        private const string ConnectionString = "Endpoint=sb://localhost/;SharedAccessKeyName=all;SharedAccessKey=CLwo3FQ3S39Z4pFOQDefaiUd1dSsli4XOAj3Y9Uh1E=;EnableAmqpLinkRedirect=false";

        public RequestHelper(bool useFullCapabilities)
        {
            var clientOptions = new ServiceBusClientOptions
            {
                TransportType = ServiceBusTransportType.AmqpTcp
            };

            Client = new ServiceBusClient(ConnectionString, clientOptions);
            UseFullCapabilities = useFullCapabilities;
        }

        private ServiceBusClient Client { get; }

        private bool UseFullCapabilities { get; }

        public async Task ManageSessionAsync(string queueName)
        {
            ServiceBusSender sender = Client.CreateSender(queueName);

            // Create and send a session message
            ServiceBusMessage message = CreateMessage("ManageSessionAsync");
            message.SessionId = "mySessionId";
            await sender.SendMessageAsync(message);

            // Create a session receiver
            ServiceBusSessionReceiver receiver = await Client.AcceptNextSessionAsync(queueName, "mySessionId");
            ServiceBusReceivedMessage receivedMessage = await receiver.ReceiveMessageAsync();
            Console.WriteLine($"ManageSessionAsync: Received message with SessionId={receivedMessage.SessionId}");

            await receiver.RenewSessionLockAsync();
            await receiver.SetSessionStateAsync(new BinaryData("state"));
            var state = await receiver.GetSessionStateAsync();
            Console.WriteLine($"ManageSessionAsync: Received SessionState={state}");
        }

        public async Task ScheduleMessagesAndCancelAsync(string queueName)
        {
            var sender = Client.CreateSender(queueName);

            var sequenceNumber = await sender.ScheduleMessageAsync(CreateMessage("ScheduleMessagesAndCancelAsync"), DateTimeOffset.Now.AddMinutes(10));
            await sender.CancelScheduledMessageAsync(sequenceNumber);

            List<ServiceBusMessage> messagesList = new()
            {
                CreateMessage("ScheduleMessagesAndCancelAsync-List-1"),
                CreateMessage("ScheduleMessagesAndCancelAsync-List-2"),
                CreateMessage("ScheduleMessagesAndCancelAsync-List-3"),
            };
            var sequenceNumbers = await sender.ScheduleMessagesAsync(messagesList, DateTimeOffset.Now.AddMinutes(10));
            await sender.CancelScheduledMessagesAsync(sequenceNumbers);
        }

        public async Task SendIndividualMessageAsync(Tracer tracer, string queueName)
        {
            using var span = tracer.StartActiveSpan("SendIndividualMessageAsync");

            var sender = Client.CreateSender(queueName);
            await sender.SendMessageAsync(CreateMessage("HandleIndividualMessageAsync"));
        }

        public async Task ReceiveIndividualMessageAsync(string queueName)
        {
            var receiver = Client.CreateReceiver(queueName, new ServiceBusReceiverOptions()
            {
                ReceiveMode = ServiceBusReceiveMode.PeekLock
            });

            // With the live message, perform the following steps:
            // - Send message
            // - Peek
            // - Receive
            // - Renew
            // - Abandon
            await receiver.PeekMessageAsync();
            var message = await receiver.ReceiveMessageAsync();
            // await receiver.RenewMessageLockAsync(message);
            await receiver.AbandonMessageAsync(message);

            // With the live message, perform the following steps:
            // - Receive
            // - Defer
            // - ReceiveDeferred
            // - DeadLetter
            message = await receiver.ReceiveMessageAsync();

            if (UseFullCapabilities)
            {
                await receiver.DeferMessageAsync(message);
                message = await receiver.ReceiveDeferredMessageAsync(message.SequenceNumber);
            }

            await receiver.DeadLetterMessageAsync(message);

            // With the now-deadlettered message:
            // - Receive
            // - Complete
            var deadLetterReceiver = Client.CreateReceiver(GetDeadLetterQueueName(queueName), new ServiceBusReceiverOptions()
            {
                ReceiveMode = ServiceBusReceiveMode.PeekLock
            });
            message = await deadLetterReceiver.ReceiveMessageAsync();
            await deadLetterReceiver.CompleteMessageAsync(message);
        }

        public async Task SendBatchMessagesAsync(Tracer tracer, string queueName)
        {
            using var span = tracer.StartActiveSpan("SendBatchMessagesAsync");

            var sender = Client.CreateSender(queueName);
            List<ServiceBusMessage> messagesList = new()
            {
                CreateMessage("HandleBatchMessageAsync-List-1"),
                CreateMessage("HandleBatchMessageAsync-List-2"),
                CreateMessage("HandleBatchMessageAsync-List-3"),
            };
            await sender.SendMessagesAsync(messagesList);
        }

        public async Task ReceiveBatchMessageAsync(string queueName)
        {
            
            var receiver = Client.CreateReceiver(queueName, new ServiceBusReceiverOptions()
            {
                ReceiveMode = ServiceBusReceiveMode.PeekLock
            });

            // With the message batch, perform the following steps:
            // - Receive
            // - Defer (individually)
            // - ReceiveDeferred
            // - Complete  (individually)
            List<ServiceBusReceivedMessage> messagesToBeCompleted = new();
            List<long> deferredSequenceNumbers = new();
            var receivedMessages = await receiver.ReceiveMessagesAsync(maxMessages: 3);
            if (!UseFullCapabilities)
            {
                foreach (var message in receivedMessages)
                {
                    await receiver.CompleteMessageAsync(message);
                }

                return;
            }

            foreach (var message in receivedMessages)
            {
                deferredSequenceNumbers.Add(message.SequenceNumber);
                await receiver.DeferMessageAsync(message);
            }

            foreach (var receivedMessage in await receiver.ReceiveDeferredMessagesAsync(deferredSequenceNumbers))
            {
                await receiver.CompleteMessageAsync(receivedMessage);
            }
        }

        public async Task<ServiceBusProcessor> InitializeServiceBusProcessor(string queueName)
        {
            var processor = Client.CreateProcessor(queueName);
            processor.ProcessMessageAsync += ProcessMessageHandler;
            processor.ProcessErrorAsync += ProcessErrorHandler;
            await processor.StartProcessingAsync();

            return processor;
        }

        public async Task SendMessagesToProcessorAsync(Tracer tracer, string queueName)
        {
            using var span = tracer.StartActiveSpan("SendMessagesToProcessorAsync");

            var sender = Client.CreateSender(queueName);
            await sender.SendMessageAsync(CreateMessage("SendMessagesToProcessorAsync"));
        }

        private async Task ProcessMessageHandler(ProcessMessageEventArgs args)
        {
            // complete the message. message is deleted from the queue. 
            await args.CompleteMessageAsync(args.Message);
        }

        private Task ProcessErrorHandler(ProcessErrorEventArgs args)
        {
            return Task.CompletedTask;
        }

        private string GetDeadLetterQueueName(string queueName) => $"{queueName}-dlq";

        private ServiceBusMessage CreateMessage(string body) => new ServiceBusMessage(body)
        {
            ContentType = "text/plain",
            ReplyTo = "replyto",
            Subject = "subject",
        };
    }
}
