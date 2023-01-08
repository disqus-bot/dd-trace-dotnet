// <copyright file="ProbeExpressionParser.cs" company="Datadog">
// Unless explicitly stated otherwise all files in this repository are licensed under the Apache 2 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/). Copyright 2017 Datadog, Inc.
// </copyright>

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq.Expressions;
using Datadog.Trace.Debugger.Models;
using Datadog.Trace.Debugger.Snapshots;
using Datadog.Trace.Vendors.Newtonsoft.Json;
using Datadog.Trace.Vendors.Newtonsoft.Json.Linq;
using static Datadog.Trace.Debugger.Expressions.ProbeExpressionParserHelper;

namespace Datadog.Trace.Debugger.Expressions;

internal partial class ProbeExpressionParser<T>
{
    private static readonly LabelTarget ReturnTarget = Expression.Label(typeof(T));
    private static readonly Func<ScopeMember, ScopeMember[], T> DefaultDelegate;

    private List<EvaluationError> _errors;
    private int _arrayStack;

    static ProbeExpressionParser()
    {
        DefaultDelegate = (_, _) =>
        {
            if (typeof(T) == typeof(bool))
            {
                return (T)(object)true;
            }

            return default;
        };
    }

    private delegate Expression Combiner(Expression left, Expression right);

    private Expression ParseRoot(
        JsonTextReader reader,
        List<ParameterExpression> parameters)
    {
        var readerValue = reader.Value?.ToString();
        switch (reader.TokenType)
        {
            case JsonToken.PropertyName:
                switch (readerValue)
                {
                    case "and":
                        {
                            return ConditionalOperator(reader, Expression.AndAlso, parameters);
                        }

                    case "or":
                        {
                            return ConditionalOperator(reader, Expression.OrElse, parameters);
                        }

                    default:
                        return ParseTree(reader, parameters, null, false);
                }
        }

        return null;
    }

    private Expression ConditionalOperator(JsonTextReader reader, Combiner combiner, List<ParameterExpression> parameters)
    {
        Expression Combine(Expression leftOperand, Expression rightOperand) =>
            leftOperand == null ? rightOperand : combiner(leftOperand, rightOperand.Type != ProbeExpressionParserHelper.UndefinedValueType ? rightOperand : Expression.Constant(true));

        _arrayStack++;
        reader.Read();
        var right = ParseTree(reader, parameters, null);
        var left = Combine(null, right);

        while (reader.Read())
        {
            if (reader.TokenType == JsonToken.StartArray)
            {
                _arrayStack++;
                continue;
            }
            else if (reader.TokenType == JsonToken.EndArray)
            {
                _arrayStack--;
                continue;
            }

            if (reader.TokenType is JsonToken.StartObject or JsonToken.EndObject)
            {
                continue;
            }

            if (_arrayStack == 0)
            {
                break;
            }

            right = ParseTree(reader, parameters, null, false);
            left = Combine(left, right);
        }

        return left;
    }

    private Expression ParseTree(
        JsonTextReader reader,
        List<ParameterExpression> parameters,
        ParameterExpression itParameter,
        bool shouldAdvanceReader = true)
    {
        while (ConditionalRead(reader, shouldAdvanceReader))
        {
            var readerValue = reader.Value?.ToString();
            try
            {
                switch (reader.TokenType)
                {
                    case JsonToken.PropertyName:
                        {
                            switch (readerValue)
                            {
                                // operators
                                case "and":
                                case "&&":
                                    {
                                        var right = ParseRoot(reader, parameters);
                                        return right;
                                    }

                                case "or":
                                case "||":
                                    {
                                        var right = ParseRoot(reader, parameters);
                                        return right;
                                    }

                                case "eq":
                                case "==":
                                    {
                                        return Equal(reader, parameters, itParameter);
                                    }

                                case "!=":
                                case "neq":
                                    {
                                        return NotEqual(reader, parameters, itParameter);
                                    }

                                case ">":
                                case "gt":
                                    {
                                        return GreaterThan(reader, parameters, itParameter);
                                    }

                                case ">=":
                                case "ge":
                                    {
                                        return GreaterThanOrEqual(reader, parameters, itParameter);
                                    }

                                case "<":
                                case "lt":
                                    {
                                        return LessThan(reader, parameters, itParameter);
                                    }

                                case "<=":
                                case "le":
                                    {
                                        return LessThanOrEqual(reader, parameters, itParameter);
                                    }

                                case "not":
                                case "!":
                                    {
                                        return Not(reader, parameters, itParameter);
                                    }

                                // string operations
                                case "isEmpty":
                                    {
                                        return IsEmpty(reader, parameters, itParameter);
                                    }

                                case "len":
                                    {
                                        return Length(reader, parameters, itParameter);
                                    }

                                case "substring":
                                    {
                                        return Substring(reader, parameters, itParameter);
                                    }

                                case "startWith":
                                    {
                                        return StartWith(reader, parameters, itParameter);
                                    }

                                case "endWith":
                                    {
                                        return EndWith(reader, parameters, itParameter);
                                    }

                                case "contains":
                                    {
                                        return Contains(reader, parameters, itParameter);
                                    }

                                case "matches":
                                    {
                                        return RegexMatches(reader, parameters, itParameter);
                                    }

                                // collection operations
                                case "hasAny":
                                    {
                                        return HasAny(reader, parameters);
                                    }

                                case "hasAll":
                                    {
                                        return HasAll(reader, parameters);
                                    }

                                case "filter":
                                    {
                                        return Filter(reader, parameters);
                                    }

                                case "count":
                                    {
                                        return Count(reader, parameters, itParameter);
                                    }

                                case "index":
                                    {
                                        return GetItemAtIndex(reader, parameters, itParameter);
                                    }

                                // generic operations
                                case "getmember":
                                    {
                                        return GetMember(reader, parameters, itParameter);
                                    }

                                case "ref":
                                    {
                                        return GetReference(reader, parameters, itParameter);
                                    }

                                case "isUndefined":
                                    {
                                        return IsUndefined(reader, parameters, itParameter);
                                    }

                                case "Ignore":
                                case "ignore":
                                    {
                                        reader.Read();
                                        break;
                                    }

                                default:
                                    {
                                        AddError(readerValue, "Operator has not defined");
                                        return ReturnDefaultValueExpression();
                                    }
                            }

                            break;
                        }

                    case JsonToken.String:
                        {
                            if (readerValue?.StartsWith("#") == true)
                            {
                                // skip comment
                                return ParseTree(reader, parameters, itParameter);
                            }

                            if (readerValue == "@return")
                            {
                                return itParameter;
                            }

                            if (readerValue == "@duration")
                            {
                                return itParameter;
                            }

                            if (readerValue == "@it")
                            {
                                // current item in iterator
                                if (itParameter == null)
                                {
                                    AddError(readerValue, "current item in iterator is null");
                                    return Expression.Parameter(UndefinedValueType, Expressions.UndefinedValue.Instance.ToString());
                                }

                                return itParameter;
                            }

                            if (readerValue == "@exceptions")
                            {
                                return itParameter;
                            }

                            return Expression.Constant(readerValue);
                        }

                    case JsonToken.Integer:
                        {
                            return Expression.Constant(Convert.ChangeType(readerValue, TypeCode.Int32));
                        }

                    case JsonToken.StartArray:
                        {
                            _arrayStack++;
                            break;
                        }

                    case JsonToken.EndArray:
                        {
                            _arrayStack--;
                            break;
                        }

                    case JsonToken.Null:
                        {
                            return Expression.Constant(null);
                        }
                }
            }
            catch (Exception e)
            {
                AddError(reader.Value?.ToString() ?? "N/A", e.Message);
                return ReturnDefaultValueExpression();
            }
        }

        return null;
    }

    private void AddError(string expression, string error)
    {
        (_errors ??= new List<EvaluationError>()).Add(new EvaluationError { Expression = expression, Message = error });
    }

    private bool ConditionalRead(JsonTextReader reader, bool shouldAdvanceReader)
    {
        return !shouldAdvanceReader || reader.Read();
    }

    private void SetReaderAtExpressionStart(JsonTextReader reader)
    {
        while (reader.Read())
        {
            if (reader.TokenType != JsonToken.PropertyName)
            {
                continue;
            }

            if (reader.Value?.ToString() == "json")
            {
                // TODO: This is only used in test code, remove
                reader.Read();
                reader.Read();
            }

            return;
        }
    }

    private Expression HandleReturnType(Expression finalExpr)
    {
        if (typeof(T).IsAssignableFrom(finalExpr.Type))
        {
            return finalExpr;
        }

        if (typeof(T) != typeof(string))
        {
            // let the caller throw the correct assign exception
            return finalExpr;
        }

        // for string, call ToString or return the type name
        if (SupportedTypesService.IsSafeToCallToString(finalExpr.Type))
        {
            finalExpr = Expression.Call(finalExpr, GetMethodByReflection(typeof(object), nameof(object.ToString), Type.EmptyTypes));
        }
        else
        {
            finalExpr = Expression.Constant(finalExpr.Type.FullName, typeof(string));
        }

        return finalExpr;
    }

    private ExpressionBodyAndParameters ParseProbeExpression(string expressionJson, ScopeMember @this, ScopeMember[] argsOrLocals)
    {
        @this.Type ??= @this.Value?.GetType();
        if (string.IsNullOrEmpty(expressionJson) || argsOrLocals == null || @this.Type == null)
        {
            throw new ArgumentException($"{nameof(ParseProbeExpression)} has been called with an invalid argument");
        }

        var scopeMembers = new List<ParameterExpression>();
        var expressions = new List<Expression>();
        var thisParameterExpression = Expression.Parameter(@this.GetType());
        var thisVariable = Expression.Variable(@this.Type, "this");
        expressions.Add(Expression.Assign(thisVariable, Expression.Convert(Expression.Field(thisParameterExpression, "Value"), @this.Type)));
        scopeMembers.Add(thisVariable);

        var argsOrLocalsParameterExpression = Expression.Parameter(argsOrLocals.GetType());

        for (var index = 0; index < argsOrLocals.Length; index++)
        {
            if (argsOrLocals[index].Type == null)
            {
                break;
            }

            var argOrLocal = argsOrLocals[index];
            var variable = Expression.Variable(argOrLocal.Type, argOrLocal.Name);
            scopeMembers.Add(variable);

            expressions.Add(
                Expression.Assign(
                    variable,
                    Expression.Convert(
                    Expression.Field(
                    Expression.ArrayIndex(
                        argsOrLocalsParameterExpression,
                        Expression.Constant(index)),
                    "Value"),
                    argOrLocal.Type)));
        }

        var reader = new JsonTextReader(new StringReader(expressionJson));
        SetReaderAtExpressionStart(reader);

        var result = Expression.Variable(typeof(T), "$dd_el_result");
        scopeMembers.Add(result);
        var finalExpr = ParseRoot(reader, scopeMembers);
        finalExpr = HandleReturnType(finalExpr);
        expressions.Add(finalExpr is not GotoExpression ? Expression.Assign(result, finalExpr) : finalExpr);
        expressions.Add(Expression.Label(ReturnTarget, result));
        var body = (Expression)Expression.Block(scopeMembers, expressions);
        if (body.CanReduce)
        {
            body = body.ReduceAndCheck();
        }

        return new ExpressionBodyAndParameters(body, thisParameterExpression, argsOrLocalsParameterExpression);
    }

    internal static CompiledExpression<T> ParseExpression(JObject expressionJson, ScopeMember @this, ScopeMember[] argsOrLocals)
    {
        return ParseExpression(expressionJson.ToString(), @this, argsOrLocals);
    }

    internal static CompiledExpression<T> ParseExpression(string expressionJson, ScopeMember @this, ScopeMember[] argsOrLocals)
    {
        var parser = new ProbeExpressionParser<T>();
        ExpressionBodyAndParameters parsedExpression = default;
        try
        {
            parsedExpression = parser.ParseProbeExpression(expressionJson, @this, argsOrLocals);
            var expression = Expression.Lambda<Func<ScopeMember, ScopeMember[], T>>(parsedExpression.ExpressionBody, parsedExpression.ThisParameterExpression, parsedExpression.ArgsAndLocalsParameterExpression);
            var compiled = expression.Compile();
            return new CompiledExpression<T>(compiled, expression, expressionJson, parser._errors?.ToArray());
        }
        catch (Exception e)
        {
            parser.AddError(parsedExpression.ExpressionBody?.ToString() ?? expressionJson, e.Message);
            return new CompiledExpression<T>(
                DefaultDelegate,
                parsedExpression.ExpressionBody ?? Expression.Constant("N/A"),
                expressionJson,
                parser._errors.ToArray());
        }
    }
}