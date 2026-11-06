package io.curlpro;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ForkJoinPool;
import java.util.function.Supplier;

import static java.lang.foreign.ValueLayout.JAVA_INT;

/**
 * One daemon thread per process waits on curlpro_result_wait and completes the
 * future of the call that finished. The ready queue is process-wide, so a second
 * waiter would steal results. A call may finish before its id is registered
 * (early), and a cancelled one still arrives (abandoned).
 */
final class Completions {
    private Completions() {}

    private static final Object GATE = new Object();
    private static final Map<Long, CompletableFuture<Native.Frame>> WAITING = new HashMap<>();
    private static final Set<Long> EARLY = new HashSet<>();
    private static final Set<Long> ABANDONED = new HashSet<>();
    private static Thread pump;

    /** start makes a *_start call and returns its envelope. */
    @SuppressWarnings("unchecked")
    static CompletableFuture<Native.Frame> run(Supplier<MemorySegment> start) {
        Curlpro.version();
        long id = ((Number) ((Map<String, Object>) Native.envelope(start.get())).get("request")).longValue();
        var future = new CompletableFuture<Native.Frame>() {
            @Override
            public boolean cancel(boolean mayInterrupt) {
                synchronized (GATE) {
                    if (WAITING.remove(id) == null) return false;
                    ABANDONED.add(id);
                }
                // Aborts a request or a connect; a read or a receive only loses its wait.
                try {
                    Native.freeQuietly((MemorySegment) Native.request_cancel.invoke(id));
                } catch (Throwable ignored) {
                    // the call is gone either way
                }
                return super.completeExceptionally(new CancellationException("cancelled"));
            }
        };
        synchronized (GATE) {
            if (EARLY.remove(id)) complete(id, future);
            else WAITING.put(id, future);
            if (pump == null) pump = Thread.ofPlatform().daemon().name("curlpro completions").start(Completions::loop);
        }
        return future;
    }

    private static void complete(long id, CompletableFuture<Native.Frame> f) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment outLen = arena.allocate(JAVA_INT);
            var p = (MemorySegment) Native.result_take.invoke(id, outLen);
            var frame = Native.frame(p, outLen.get(JAVA_INT, 0));
            // Dependent stages run on the common pool, never on the pump thread.
            ForkJoinPool.commonPool().execute(() -> f.complete(frame));
        } catch (Throwable t) {
            ForkJoinPool.commonPool().execute(() -> f.completeExceptionally(t));
        }
    }

    private static void loop() {
        while (true) {
            long id;
            try {
                id = (long) Native.result_wait.invoke(250);
            } catch (Throwable t) {
                id = 0;
            }
            synchronized (GATE) {
                if (id == 0) {
                    long pending;
                    try {
                        pending = (long) Native.async_pending.invoke();
                    } catch (Throwable t) {
                        pending = 0;
                    }
                    if (WAITING.isEmpty() && pending == 0) {
                        pump = null;
                        return;
                    }
                    continue;
                }
                if (ABANDONED.remove(id)) continue;
                var f = WAITING.remove(id);
                if (f != null) complete(id, f);
                else EARLY.add(id);
            }
        }
    }
}
