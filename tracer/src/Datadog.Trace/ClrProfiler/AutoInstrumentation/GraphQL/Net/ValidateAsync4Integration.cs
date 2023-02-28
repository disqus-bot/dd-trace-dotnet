// <copyright file="ValidateAsync4Integration.cs" company="Datadog">
// Unless explicitly stated otherwise all files in this repository are licensed under the Apache 2 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/). Copyright 2017 Datadog, Inc.
// </copyright>

using System;
using System.ComponentModel;
using Datadog.Trace.ClrProfiler.CallTarget;

namespace Datadog.Trace.ClrProfiler.AutoInstrumentation.GraphQL.Net
{
    /// <summary>
    /// GraphQL.Validation.DocumentValidator calltarget instrumentation for GraphQL 4
    /// </summary>
    [InstrumentMethod(
        AssemblyName = GraphQLCommon.GraphQLAssembly,
        TypeName = "GraphQL.Validation.DocumentValidator",
        MethodName = "ValidateAsync",
        ReturnTypeName = ClrNames.GenericParameterTask,
        ParameterTypeNames = new[] { "GraphQL.Types.ISchema", "GraphQL.Language.AST.Document", "GraphQL.Language.AST.VariableDefinitions", "System.Collections.Generic.IEnumerable`1[GraphQL.Validation.IValidationRule]", ClrNames.Ignore, "GraphQL.Inputs" },
        MinimumVersion = GraphQLCommon.Major4,
        MaximumVersion = GraphQLCommon.Major4,
        IntegrationName = GraphQLCommon.IntegrationName)]
    [Browsable(false)]
    [EditorBrowsable(EditorBrowsableState.Never)]
    public class ValidateAsync4Integration
    {
        /// <summary>
        /// OnMethodBegin callback
        /// </summary>
        /// <typeparam name="TTarget">Type of the target</typeparam>
        /// <typeparam name="TSchema">Type of the schema</typeparam>
        /// <typeparam name="TDocument">Type of the document</typeparam>
        /// <typeparam name="TVariables">Type of the variables</typeparam>
        /// <typeparam name="TRules">Type of the rules</typeparam>
        /// <typeparam name="TUserContext">Type of the user context</typeparam>
        /// <typeparam name="TInputs">Type of the inputs</typeparam>
        /// <param name="instance">Instance value, aka `this` of the instrumented method.</param>
        /// <param name="schema">The GraphQL schema value</param>
        /// <param name="document">The GraphQL document value</param>
        /// <param name="variables">The GraphQL variables</param>
        /// <param name="rules">The list of validation rules</param>
        /// <param name="userContext">The user context</param>
        /// <param name="inputs">The input variables</param>
        /// <returns>Calltarget state value</returns>
        internal static CallTargetState OnMethodBegin<TTarget, TSchema, TDocument, TVariables, TRules, TUserContext, TInputs>(TTarget instance, TSchema schema, TDocument document, TVariables variables, TRules rules, TUserContext userContext, TInputs inputs)
            where TDocument : IDocument
        {
            return new CallTargetState(GraphQLCommon.CreateScopeFromValidate(Tracer.InternalInstance, document.OriginalQuery));
        }

        /// <summary>
        /// OnAsyncMethodEnd callback
        /// </summary>
        /// <typeparam name="TTarget">Type of the target</typeparam>
        /// <typeparam name="TValidationResult">Type of the validation result value</typeparam>
        /// <param name="instance">Instance value, aka `this` of the instrumented method.</param>
        /// <param name="validationResult">ExecutionResult instance</param>
        /// <param name="exception">Exception instance in case the original code threw an exception.</param>
        /// <param name="state">Calltarget state value</param>
        /// <returns>A response value, in an async scenario will be T of Task of T</returns>
        internal static TValidationResult OnAsyncMethodEnd<TTarget, TValidationResult>(TTarget instance, TValidationResult validationResult, Exception exception, in CallTargetState state)
            where TValidationResult : IValidationResultTuple
        {
            var scope = state.Scope;

            if (state.Scope is null)
            {
                return validationResult;
            }

            try
            {
                if (exception != null)
                {
                    scope.Span?.SetException(exception);
                }
                else
                {
                    GraphQLCommon.RecordExecutionErrorsIfPresent(scope.Span, GraphQLCommon.ValidationErrorType, validationResult.Item1.Errors);
                }
            }
            finally
            {
                scope.Dispose();
            }

            return validationResult;
        }
    }
}
