namespace OpenCredentials.Tests;

/// <summary>Rows for a <c>[TestCaseSource]</c>, written as a collection initializer: <c>{ "a", "b" }</c> is one case.</summary>
public sealed class CaseRows : List<object[]>
{
    public void Add(params object[] row) => base.Add(row);
}
