using System.Text.Json.Nodes;

namespace Curlpro;

/// <summary>
/// One thread per process waits on curlpro_result_wait and hands each finished
/// call to the task that started it.
/// </summary>
/// <remarks>
/// The ready queue is process-wide, so a second waiter would steal the first
/// one's results. A call can finish before its id is registered here (the start
/// call returns after the work began), so such ids are parked in
/// <c>Early</c> until <see cref="Run"/> claims them. A cancelled call still
/// reaches the queue; its id is in <c>Abandoned</c> and is skipped.
/// </remarks>
internal static class Completions
{
    private static readonly object Gate = new();
    private static readonly Dictionary<long, TaskCompletionSource<(IntPtr, int)>> Waiting = new();
    private static readonly HashSet<long> Early = new();
    private static readonly HashSet<long> Abandoned = new();
    private static Thread? _pump;

    /// <summary>Starts a call with <paramref name="start"/> and awaits its result frame.</summary>
    public static async Task<(JsonNode? Data, byte[] Body)> Run(Func<IntPtr> start, CancellationToken ct)
    {
        _ = Library.Version;
        var id = Interop.Envelope(start())!["request"]!.GetValue<long>();
        var tcs = new TaskCompletionSource<(IntPtr, int)>(TaskCreationOptions.RunContinuationsAsynchronously);
        lock (Gate)
        {
            if (Early.Remove(id)) Complete(id, tcs);
            else Waiting[id] = tcs;
            EnsurePump();
        }
        using (ct.Register(() => Cancel(id, tcs, ct)))
        {
            var (p, len) = await tcs.Task.ConfigureAwait(false);
            return Interop.Frame(p, len);
        }
    }

    private static void Cancel(long id, TaskCompletionSource<(IntPtr, int)> tcs, CancellationToken ct)
    {
        lock (Gate)
        {
            if (!Waiting.Remove(id)) return; // already completed
            Abandoned.Add(id);
        }
        // Aborts a request or a connect; a read or a receive only loses its wait,
        // so the caller closes that stream or socket.
        Native.curlpro_free(Native.curlpro_request_cancel(id));
        tcs.TrySetCanceled(ct);
    }

    private static void Complete(long id, TaskCompletionSource<(IntPtr, int)> tcs)
    {
        var p = Native.curlpro_result_take(id, out var len);
        if (!tcs.TrySetResult((p, len))) Native.curlpro_free(p);
    }

    private static void EnsurePump()
    {
        if (_pump is not null) return;
        _pump = new Thread(Pump) { IsBackground = true, Name = "curlpro completions" };
        _pump.Start();
    }

    private static void Pump()
    {
        while (true)
        {
            long id = Native.curlpro_result_wait(250);
            lock (Gate)
            {
                if (id == 0)
                {
                    // Nothing in flight: the thread ends, the next call starts another.
                    if (Waiting.Count == 0 && Native.curlpro_async_pending() == 0)
                    {
                        _pump = null;
                        return;
                    }
                    continue;
                }
                if (Abandoned.Remove(id)) continue;
                if (Waiting.Remove(id, out var tcs)) Complete(id, tcs);
                else Early.Add(id);
            }
        }
    }
}
