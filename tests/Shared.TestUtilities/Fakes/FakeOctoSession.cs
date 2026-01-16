using Meshmakers.Octo.Runtime.Contracts;

namespace Shared.TestUtilities.Fakes;

public class FakeOctoSession : IOctoSession
{
    private bool _inTransaction;

    public bool IsDisposed { get; private set; }
    public int TransactionStartCount { get; private set; }
    public int CommitCount { get; private set; }
    public int AbortCount { get; private set; }

    public void StartTransaction()
    {
        _inTransaction = true;
        TransactionStartCount++;
    }

    public Task CommitTransactionAsync()
    {
        _inTransaction = false;
        CommitCount++;
        return Task.CompletedTask;
    }

    public Task AbortTransactionAsync()
    {
        _inTransaction = false;
        AbortCount++;
        return Task.CompletedTask;
    }

    public bool IsInTransaction => _inTransaction;

    public void Dispose()
    {
        IsDisposed = true;
    }
}
