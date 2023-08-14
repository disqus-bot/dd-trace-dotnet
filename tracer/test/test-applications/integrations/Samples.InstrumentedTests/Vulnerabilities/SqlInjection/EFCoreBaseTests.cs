#if NETCOREAPP3_0_OR_GREATER
using System;
using System.Collections.Generic;
using System.Data.Common;
using System.Data.Entity;
using System.Linq;
using System.Security.Policy;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Xunit;
using static Dapper.SqlMapper;

namespace Samples.InstrumentedTests.Iast.Vulnerabilities.SqlInjection;

public abstract class EFCoreBaseTests: InstrumentationTestsBase, IDisposable
{
    protected string taintedTitle = "Think_Python";
    protected string notTaintedValue = "nottainted";
    protected string commandUnsafe;
    protected string commandUnsafeparameter;
    protected readonly string commandSafe = "Update Books set title= title where title = @title";
    protected readonly string commandSafeNoParameters = "Update Books set title= 'Think_Python' where title = 'Think_Python'";
    protected readonly string querySafe = "Select * from Books where title = @title";
    protected DbParameter titleParam;
    protected string queryUnsafe;
    protected FormattableString formatStr;
    protected ApplicationDbContextCore dbContext;

    public EFCoreBaseTests()
    {
        AddTainted(taintedTitle);
        formatStr = $"Update Books set title= title where title = {taintedTitle}";
        commandUnsafeparameter = "Update Books set title=title where title ='" + taintedTitle + "' or title=@title";
        commandUnsafe = "Update Books set title= title where title ='" + taintedTitle + "'";
        queryUnsafe = "Select * from Books where title ='" + taintedTitle + "'";
    }

    public void Dispose()
    {
        dbContext.Database.CloseConnection();
    }

#if NET5_0_OR_GREATER

    [Fact]
    public void GivenACoreDatabase_WhenCallingExecuteSqlRawWithTainted_VulnerabilityIsReported()
    {
        dbContext.Database.ExecuteSqlRaw(commandUnsafe);
        AssertVulnerable();
    }

    [Fact]
    public void GivenACoreDatabase_WhenCallingExecuteSqlRawWithTainted_VulnerabilityIsReported2()
    {
        dbContext.Database.ExecuteSqlRaw(commandUnsafe, titleParam);
        AssertVulnerable();
    }

    [Fact]
    public void GivenACoreDatabase_WhenCallingExecuteSqlRawWithTainted_VulnerabilityIsReported3()
    {
        dbContext.Database.ExecuteSqlRaw(commandUnsafe, new List<DbParameter>() { titleParam });
        AssertVulnerable();
    }

    [Fact]
    public void GivenACoreDatabase_WhenCallingExecuteSqlRawAsyncWithTainted_VulnerabilityIsReported()
    {
        dbContext.Database.ExecuteSqlRawAsync(commandUnsafe);
        AssertVulnerable();
    }

    [Fact]
    public void GivenACoreDatabase_WhenCallingExecuteSqlRawAsyncWithTainted_VulnerabilityIsReported2()
    {
        dbContext.Database.ExecuteSqlRawAsync(commandUnsafeparameter, titleParam);
        AssertVulnerable();
    }

    [Fact]
    public void GivenACoreDatabase_WhenCallingExecuteSqlRawAsyncWithTainted_VulnerabilityIsReported3()
    {
        dbContext.Database.ExecuteSqlRawAsync(commandUnsafeparameter, new List<DbParameter>() { titleParam });
        AssertVulnerable();
    }

    [Fact]
    public void GivenACoreDatabase_WhenCallingExecuteSqlRawAsyncWithTainted_VulnerabilityIsReported4()
    {
        dbContext.Database.ExecuteSqlRawAsync(commandUnsafe, CancellationToken.None);
        AssertVulnerable();
    }

    [Fact]
    public void GivenACoreDatabase_WhenCallingExecuteSqlRawAsyncyWithTainted_VulnerabilityIsReported5()
    {
        dbContext.Database.ExecuteSqlRawAsync(commandUnsafe, new List<DbParameter>() { titleParam }, CancellationToken.None);
        AssertVulnerable();
    }

    [Fact]
    public void GivenACoreDatabase_WhenCallingFromSqlRawWithTainted_VulnerabilityIsReported()
    {
        dbContext.Books.FromSqlRaw(queryUnsafe).ToList();
        AssertVulnerable();
    }

    [Fact]
    public void GivenACoreDatabase_WhenCallingFromSqlRawWithTainted_VulnerabilityIsReported2()
    {
        dbContext.Books.FromSqlRaw(queryUnsafe, titleParam).ToList();
        AssertVulnerable();
    }

    [Fact]
    public void GivenACoreDatabase_WhenCallingFromSqlRawWithTainted_VulnerabilityIsReported3()
    {
        dbContext.Books.FromSqlRaw("Select * from dbo.Books where title ='" + taintedTitle + "'");
        AssertVulnerable();
    }

    [Fact]
    public void GivenACoreDatabase_WhenCallingFromSqlRawWithTaintedSecure_VulnerabilityIsNotReported2()
    {
        dbContext.Books.FromSqlRaw(@"Select * from dbo.Books where title =Title", taintedTitle);
        AssertNotVulnerable();
    }

    [Fact]
    public void GivenACoreDatabase_WhenCallingFromSqlInterpolatedWithTaintedSecure_VulnerabilityIsNotReported()
    {
        dbContext.Books.FromSqlInterpolated($"Select * from dbo.Books ({taintedTitle}");
        AssertNotVulnerable();
    }

    [Fact]
    public void GivenACoreDatabase_WhenCallingExecuteSqlInterpolatedSafe_VulnerabilityIsNotReported()
    {
        dbContext.Database.ExecuteSqlInterpolated(formatStr);
        AssertNotVulnerable();
    }

    [Fact]
    public void GivenACoreDatabase_WhenCallingExecuteSqlInterpolatedSafe_VulnerabilityIsNotReported2()
    {
        dbContext.Database.ExecuteSqlInterpolatedAsync(formatStr);
        AssertNotVulnerable();
    }

    [Fact]
    public void GivenACoreDatabase_WhenCallingExecuteSqlInterpolatedSafe_VulnerabilityIsNotReported3()
    {
        dbContext.Database.ExecuteSqlInterpolatedAsync(formatStr, CancellationToken.None);
        AssertNotVulnerable();
    }

    [Fact]
    public void GivenACoreDatabase_WhenCallingExecuteSqlRawSafe_VulnerabilityIsNotReported()
    {
        dbContext.Database.ExecuteSqlRaw(commandSafeNoParameters);
        AssertNotVulnerable();
    }

    [Fact]
    public void GivenACoreDatabase_WhenCallingExecuteSqlRawSafe_VulnerabilityIsNotReported2()
    {
        dbContext.Database.ExecuteSqlRaw(commandSafe, titleParam);
        AssertNotVulnerable();
    }

    [Fact]
    public void GivenACoreDatabase_WhenCallingExecuteSqlRawSafe_VulnerabilityIsNotReporte3d()
    {
        dbContext.Database.ExecuteSqlRaw(commandSafe, new List<DbParameter>() { titleParam });
        AssertNotVulnerable();
    }

    [Fact]
    public void GivenACoreDatabase_WhenCallingExecuteSqlRawAsyncSafe_VulnerabilityIsNotReported()
    {
        dbContext.Database.ExecuteSqlRawAsync(commandSafeNoParameters);
        AssertNotVulnerable();
    }

    [Fact]
    public void GivenACoreDatabase_WhenCallingExecuteSqlRawAsyncSafe_VulnerabilityIsNotReported2()
    {
        dbContext.Database.ExecuteSqlRawAsync(commandSafe, titleParam);
        AssertNotVulnerable();
    }

    [Fact]
    public void GivenACoreDatabase_WhenCallingExecuteSqlRawAsyncSafe_VulnerabilityIsNotReported3()
    {
        dbContext.Database.ExecuteSqlRawAsync(commandSafe, new List<DbParameter>() { titleParam });
        AssertNotVulnerable();
    }

    [Fact]
    public void GivenACoreDatabase_WhenCallingExecuteSqlRawAsyncSafe_VulnerabilityIsNotReporte4d()
    {
        dbContext.Database.ExecuteSqlRawAsync(commandSafeNoParameters, CancellationToken.None);
        AssertNotVulnerable();
    }

    [Fact]
    public void GivenACoreDatabase_WhenCallingExecuteSqlRawAsyncSafe_VulnerabilityIsNotReported5()
    {
        dbContext.Database.ExecuteSqlRawAsync(commandSafe, new List<DbParameter>() { titleParam }, CancellationToken.None);
        AssertNotVulnerable();
    }

    [Fact]
    public void GivenACoreDatabase_WhenCallingFromSqlRawSafe_VulnerabilityIsNotReported()
    {
        dbContext.Books.FromSqlRaw(querySafe, titleParam).ToList();
        AssertNotVulnerable();
    }

    [Fact]
    public void GivenACoreDatabase_WhenCallingFromSqlInterpolatedSafe_VulnerabilityIsNotReported()
    {
        dbContext.Books.FromSqlInterpolated($"SELECT * FROM Books where title = {titleParam}").ToList();
        AssertNotVulnerable();
    }

#endif

    [Fact]
    public void GivenACoreDatabase_WhenCallingExecuteNonQueryWithTainted_VulnerabilityIsReported()
    {
        var command = dbContext.Database.GetDbConnection().CreateCommand();
        command.CommandText = commandUnsafe;
        command.ExecuteNonQuery();
        dbContext.Database.CloseConnection();
        AssertVulnerable();
    }

    [Fact]
    public void GivenACoreDatabase_WhenCallingExecuteScalarWithTainted_VulnerabilityIsReported()
    {
        var command = dbContext.Database.GetDbConnection().CreateCommand();
        command.CommandText = queryUnsafe;
        command.ExecuteScalar();
        dbContext.Database.CloseConnection();
        AssertVulnerable();
    }

    [Fact]
    public void GivenACoreDatabase_WhenCallingToListSafe_VulnerabilityIsNotReported()
    {
        dbContext.Books.Where(x => x.Title == taintedTitle).ToList();
        AssertNotVulnerable();
    }

    [Fact]
    public void GivenACoreDatabase_WhenCallingFirstOrDefaultSafe_VulnerabilityIsNotReported()
    {
        new List<Book>() { dbContext.Books.FirstOrDefault(x => x.Title == taintedTitle) };
        AssertNotVulnerable();
    }

    [Fact]
    public void GivenACoreDatabase_WhenCallingLikeSafe_VulnerabilityIsNotReported()
    {
        (from c in dbContext.Books where EF.Functions.Like(c.Title, taintedTitle) select c).ToList();
        AssertNotVulnerable();
    }

    [Fact]
    public void GivenACoreDatabase_WhenCallingToListSafe_VulnerabilityIsNotReported2()
    {
        (from c in dbContext.Books where c.Title == taintedTitle select c).ToList();
        AssertNotVulnerable();
    }
    /*
    [Fact]
    public void tesstY()
    {
        var t = string.Concat("p.Title", taintedTitle, "p.Id", "p.Author");

        AssertUntaintedWithOriginalCallCheck(
            () => dbContext.Books.Where(p => string.Concat(p.Title, taintedTitle, p.Id, p.Author) == "Example").ToList(),
            () => dbContext.Books.Where(p => string.Concat(p.Title, taintedTitle, p.Id, p.Author) == "Example").ToList());
        
        var query = dbContext.Books.Where(p => string.Concat(p.Title, taintedTitle, p.Id, p.Author) == "Example").ToList();
    }*/

    [Fact]
    public void tesstY2()
    {
        var t = string.Format("%s-%s", taintedTitle, "rr");

        AssertUntaintedWithOriginalCallCheck(
            () => dbContext.Books.Where(p => string.Format("%s-%s", taintedTitle, "rr") == "Example").ToList(),
            () => dbContext.Books.Where(p => string.Format("%s-%s", taintedTitle, "rr") == "Example").ToList());

        var query = dbContext.Books.Where(p => string.Format("%s-%s", taintedTitle, "rr") == "Example").ToList();
    }

    [Fact]
    public void tesstY3()
    {
        var t = string.Concat("p.Title", taintedTitle, "p.Id", "p.Author");

        AssertUntaintedWithOriginalCallCheck(
            () => dbContext.Books.Where(p => string.Concat("p.Title", "taintedTitle", "p.Id", "p.Author") == "Example").ToList(),
            () => dbContext.Books.Where(p => string.Concat("p.Title", "taintedTitle", "p.Id", "p.Author") == "Example").ToList());

        var query = dbContext.Books.Where(p => string.Concat("p.Title", "taintedTitle", "p.Id", "p.Author") == "Example").ToList();
    }

    [Fact]
    public void tesstY4()
    {
        var t = string.Concat(taintedTitle, "p.Title");

        AssertUntaintedWithOriginalCallCheck(
            () => dbContext.Books.Where(p => string.Concat(taintedTitle, "p.Title") == "Example").ToList(),
            () => dbContext.Books.Where(p => string.Concat(taintedTitle, "p.Title") == "Example").ToList());

        var query = dbContext.Books.Where(p => string.Concat(taintedTitle, "p.Title") == "Example").ToList();
    }

    [Fact]
    public void tesstY433()
    {
        var t = string.Concat(taintedTitle, "p.Title");

        AssertUntaintedWithOriginalCallCheck(
            () => dbContext.Books.Where(p => aux(taintedTitle, "p.Title") == "Example").ToList(),
            () => dbContext.Books.Where(p => aux(taintedTitle, "p.Title") == "Example").ToList());

        var query = dbContext.Books.Where(p => aux(taintedTitle, "p.Title") == "Example").ToList();
    }

    private string aux(string s1, string s2)
    {
        return string.Concat(s1, s2);
    }
    
    [Fact]
    public void tesstY433rrr()
    {
        var res = dbContext.Books.Select(x => x.Author != "ee");
        AssertUntaintedWithOriginalCallCheck(
            () => res.Where(x => string.Format(taintedTitle, "ee") != "ww"),
            () => res.Where(x => string.Format(taintedTitle, "ee") != "ww"));

        var t = res.Where(x => string.Format(taintedTitle, "ee") != "ww");
    }

    [Fact]
    public void tesstY4333333()
    {
        var t = (from c in dbContext.Books where c.Title == string.Concat(taintedTitle, "eee") select c).ToList();
    }


    [Fact]
    public void tesstY43333343()
    {
        var t = (from c in dbContext.Books where c.Title == string.Concat(taintedTitle, "eee") select c).ToList();
    }

    [Fact]
    public void tesstY43333343333()
    {
        AssertUntaintedWithOriginalCallCheck(
            () => GetEstates().ToList().First(),
            () => GetEstates().ToList().First());
        
        var st = GetEstates().First();
    }

    public IQueryable<Book> GetEstates()
    {
        var allHomeFeat = GetHomeFeatures().ToList();
        var firstHomeFeat = allHomeFeat.FirstOrDefault(); // Assign to a local variable

        return from e in dbContext.Books
               select new Book
               {
                   Title = e.Title,
                   Author = firstHomeFeat.Author
               };
    }

    public IQueryable<Book> GetHomeFeatures()
    {
        return from f in dbContext.Books
               select new Book()
               {
                   Title = string.Format("{0}", f.Title),
               };
    }


    [Fact]
    public void tesstY433ds343()
    {
        var patients = GetHomeFeatures().Select(p => new Book()
        {
            Author = string.Format("{0}", p.Author),
            Id = sample(taintedTitle).ToString()
        });
    }

    private string sample(string v)
    {
        return v + "eee" + v;
    }


    private int ToInt32(int v)
    {
        return 77;
    }
}
#endif
