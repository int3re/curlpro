// The Java binding end to end: offline fingerprint, the same fingerprint as a
// server saw it, parallel async requests, cancellation, a stream, an error code.
//
//   CURLPRO_LIBRARY=../../dist/curlpro.dll CURLPRO_PROFILES=../../profiles
//   java --enable-native-access=ALL-UNNAMED -cp target/classes examples/Example.java
import io.curlpro.Curlpro;
import io.curlpro.CurlproException;
import io.curlpro.Request;
import io.curlpro.Response;
import io.curlpro.Session;

import java.util.Map;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletableFuture;
import java.util.stream.IntStream;

public class Example {
    public static void main(String[] args) throws Exception {
        System.out.println("libcurlpro " + Curlpro.version());
        try (var s = new Session("chrome-156-windows")) {
            System.out.println("ja4 offline:   " + s.fingerprint("https://tls.peet.ws/").get("ja4"));

            Response r = s.get("https://tls.peet.ws/api/clean");
            System.out.println(r + "  (" + r.body().length + " bytes)");
            System.out.println("ja4 by server: " + ((Map<?, ?>) r.json()).get("ja4"));

            var futures = IntStream.range(0, 5).mapToObj(i -> s.getAsync("https://example.com/")).toList();
            CompletableFuture.allOf(futures.toArray(CompletableFuture[]::new)).join();
            System.out.println("async x5: " + futures.stream().map(f -> f.join().status() + " " + f.join().proto()).toList());

            var slow = s.getAsync("https://httpbin.org/delay/5");
            Thread.sleep(50);
            slow.cancel(true);
            try { slow.join(); System.out.println("cancel: not cancelled?"); }
            catch (CancellationException | java.util.concurrent.CompletionException e) { System.out.println("cancel: ok"); }

            try (var st = s.stream(Request.get("https://example.com/"))) {
                int total = 0, n;
                byte[] buf = new byte[1024];
                while ((n = st.read(buf, 0, buf.length)) > 0) total += n;
                System.out.println("stream: " + st.status() + " " + st.proto() + ", " + total + " bytes");
            }

            try (var bad = new Session("no-such-browser")) {
                System.out.println("unexpected: " + bad.profile());
            } catch (CurlproException e) {
                System.out.println("error code: " + e.code() + ", permanent: " + e.permanent());
            }
        }
        System.out.println("left open: " + Curlpro.debugCounts());
    }
}
