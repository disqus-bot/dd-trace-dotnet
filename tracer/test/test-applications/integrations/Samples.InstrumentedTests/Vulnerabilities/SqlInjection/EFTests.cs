#if !NETCOREAPP2_1
using System;
using System.Data;
using System.Data.Entity;
using System.Data.Entity.Core.EntityClient;
using System.Data.Entity.Infrastructure;
using System.Data.SqlClient;
using System.Linq;
using System.Linq.Expressions;
using System.Reflection;
using Datadog.Trace.Iast.Aspects.System;
using FluentAssertions;
using Xunit;
using Xunit.Abstractions;

namespace Samples.InstrumentedTests.Iast.Vulnerabilities.SqlInjection;

// We cannot use localDB on linux and these calls cannot be mocked
[Trait("Category", "LinuxUnsupported")]
public class EFTests : EFBaseTests
{
    private readonly ITestOutputHelper _testOutputHelper;

    public EFTests(ITestOutputHelper testOutputHelper)
    {
        _testOutputHelper = testOutputHelper;
        var connection = SqlDDBBCreator.Create();
        db = new ApplicationDbContext(connection.ConnectionString);
        titleParam = new SqlParameter("@title", taintedTitle);
        if (db.Database.Connection.State != ConnectionState.Open)
        {
            db.Database.Connection.Open();
        }
    }

    private static string MyContact(string a, string b)
    {
        return string.Concat(a, b);
    }

    [Fact]
    public void TestConcatEF()
    {
        // doesn't do what we want, count be along the right lines if we get the method body
        // var directCallResult = MyContact("a", "b");
        // _testOutputHelper.WriteLine("directCallResult: " + directCallResult);
        // var realFunc = ((Func<string, string, string>)MyContact);

        // below would work with this value of realFunc
        // var realFunc = ((Func<string, string, string>)string.Concat);

        // of course the below value of realFunc fails, but with exactly the right error message ...
        // var realFunc = ((Func<string, string, string>)string.Concat);
        Func<string, string, string> realFunc = ((a, b) => string.Concat(a, b));
        var contactResult = realFunc.Invoke(taintedTitle, "b");
        _testOutputHelper.WriteLine("contactResult: " + contactResult);
        var contact = realFunc.Method;
        _testOutputHelper.WriteLine(contact.ToString());

        // Expression<Func<Book, bool>> func = Getter(contact);
        Expression<Func<Book, bool>> exp = ((c) => realFunc(taintedTitle, "e") == "dsfs");

        // compiling the function and calling it doesn't change anything, you won't really expect it to
        // as the expression tree has already been generated
        // var compiledFunc = func.Compile();
        // compiledFunc(null);

        var data = (db as ApplicationDbContext).Books.Where(exp).ToList();
        _testOutputHelper.WriteLine("here!!!!");

        Assert.True(false); // see debug output, in cases where call to Where works
    }


    // The below method generates more or less the same tree as the below snippet, but
    // waiting for the MethodInfo of the method to be called to be passed in:
    //  Expression<Func<Book, bool>> getter = (Book x) => string.Concat("a", "b") !=  "ba";
    private Expression<Func<Book, bool>> Getter(MethodInfo methodToCall)
    {
        ParameterExpression parameterExpression = Expression.Parameter(typeof(Book), "x");
        Expression[] array = new Expression[2];
        array[0] = Expression.Constant("a", typeof(string));
        array[1] = Expression.Constant("b", typeof(string));
        BinaryExpression body = Expression.NotEqual(Expression.Call(null, methodToCall, array), Expression.Constant("ba", typeof(string)));
        ParameterExpression[] array2 = new ParameterExpression[1];
        array2[0] = parameterExpression;
        return Expression.Lambda<Func<Book, bool>>(body, array2);
    }

    public static MethodInfo GetMethodInfo<T>(Expression<Action<T>> expression)
    {
        var member = expression.Body as MethodCallExpression;

        if (member != null)
            return member.Method;

        throw new ArgumentException("Expression is not a method", "expression");
    }
    private bool Filter(Book x)
    {
        _testOutputHelper.WriteLine("filtering book " + x.Title);
        return string.Concat(x.Title, "a", "b", "c") != "xyz";
    }

    private string ConcatForTests2()
    {
        return string.Concat(taintedTitle, "eee");
    }


    [Fact]
    public void GivenEntityFramework_WhenCallingExecutSqlQueryWithTainted_VulnerabilityIsReported()
    {
        var data = (db as ApplicationDbContext).Books.SqlQuery(queryUnsafe).ToList();
        data.Count.Should().Be(1);
        AssertVulnerable();
    }

    [Fact]
    public void GivenEntityFramework_WhenCallingExecutSqlQueryParamWithTainted_VulnerabilityIsNotReported()
    {
        var data = (db as ApplicationDbContext).Books.SqlQuery(@"Select * from dbo.Books where title =@title", titleParam).ToList();
        data.Count.Should().Be(1);
        AssertNotVulnerable();
    }

    [Fact]
    public void efwfedrfref2226798879()
    {
        string.Concat(taintedTitle, "eee");

        AssertUntaintedWithOriginalCallCheck(
            () => (db as ApplicationDbContext).Books.Where(x => ConcatForTests() != "eeef").ToList(),
            () => (db as ApplicationDbContext).Books.Where(x => ConcatForTests() != "eeef").ToList());

        var data = (db as ApplicationDbContext).Books.Where(x => ConcatForTests() != "eeef").ToList();
        AssertNotVulnerable();
    }

    [Fact]
    public void efwfedrfref2223434()
    {
        var t = (string t1, string t2) => string.Concat(t1, t2);

        AssertUntaintedWithOriginalCallCheck(
            () => (db as ApplicationDbContext).Books.Where(x => t(taintedTitle, "ee") != "eeef").ToList(),
            () => (db as ApplicationDbContext).Books.Where(x => t(taintedTitle, "ee") != "eeef").ToList());

        var data = (db as ApplicationDbContext).Books.Where(x => t(taintedTitle, "ee") != "eeef").ToList();
        AssertNotVulnerable();
    }

    [Fact]
    public void efwfedrfref222343444()
    {
        var t = (string t1, string t2) => string.Concat(t1, t2);

        AssertUntaintedWithOriginalCallCheck(
            () => (db as ApplicationDbContext).Books.Where(x => string.Format(taintedTitle, "ee") != "eeef").ToList(),
            () => (db as ApplicationDbContext).Books.Where(x => string.Format(taintedTitle, "ee") != "eeef").ToList());

        var data = (db as ApplicationDbContext).Books.Where(x => string.Format(taintedTitle, "ee") != "eeef").ToList();
        AssertNotVulnerable();
    }

    [Fact]
    public async void efwfedrfref22234344tytrytry4()
    {
        using (var context = db)
        {
            var books = await (context as ApplicationDbContext).Books.ToListAsync();
            var t6employeesToUpdate = books.SingleOrDefault(e => ConcatForTests() == "John Doe");

            // Attempt to concatenate strings within the LINQ query
            var employeesToUpdate = await (context as ApplicationDbContext).Books
                .Where(e => ConcatForTests() != "John Doe")
                .SingleOrDefaultAsync();

            // This line will trigger the error when trying to save changes
            await context.SaveChangesAsync();
        }   
    }

    [Fact]
    public void TestConcatEFsadsadasd()
    {
        var data = (db as ApplicationDbContext).Books.Where(x => ConcatForTests() != "eeef").ToList();
    }

    private string ConcatForTests()
    {
        return string.Concat(taintedTitle, "eee");
    }

    [Fact]
    public void efwfedrfref222()
    {
        string.Concat(taintedTitle, "eee");

        AssertUntaintedWithOriginalCallCheck(
            () => (db as ApplicationDbContext).Books.Where(x => taintedTitle + "eee" != "eeef").ToList(),
            () => (db as ApplicationDbContext).Books.Where(x => string.Concat(taintedTitle, "eee") != "eeef").ToList());

        (db as ApplicationDbContext).Books.Where(x => string.Concat(taintedTitle, "eee") != "eeef").ToList();
    }

    protected override EntityCommand GetEntityCommand(string title)
    {
        var queryString = "SELECT b.Title FROM ApplicationDbContext.Books AS b where b.Title ='" + title + "'";
        var adapter = (IObjectContextAdapter)db;
        var objectContext = adapter.ObjectContext;
        var conn = (EntityConnection)objectContext.Connection;
        conn.Open();
        var query = new EntityCommand(queryString, conn);
        return query;
    }
}
#endif
