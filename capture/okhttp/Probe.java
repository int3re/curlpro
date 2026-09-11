// Drive okhttp at the capture stand so its ClientHello can be recorded.
//
// okhttp has no TLS of its own: it picks the cipher suites through
// ConnectionSpec, asks for ALPN and SNI, and the platform builds the
// ClientHello. On Android that platform is Conscrypt; on a desktop JVM it is
// SunJSSE, and the two produce different fingerprints. Which one is in use is
// therefore printed, not assumed.
//
//   java -cp "lib/*;." Probe <url> <runs> [conscrypt]
//
// The stand's certificate is self-signed, so verification is switched off —
// this talks only to localhost and exists only to be measured.

import java.net.InetAddress;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.List;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

public class Probe {
    public static void main(String[] args) throws Exception {
        String url = args.length > 0 ? args[0] : "https://www.example.com:8443/json/detail";
        int runs = args.length > 1 ? Integer.parseInt(args[1]) : 5;
        boolean conscrypt = args.length > 2 && args[2].equals("conscrypt");

        if (conscrypt) {
            // Inserted at position 1 so it is preferred over SunJSSE. okhttp
            // detects it through its own Platform lookup and switches to
            // ConscryptPlatform, which is what an Android build uses.
            Class<?> c = Class.forName("org.conscrypt.Conscrypt");
            Security.insertProviderAt(
                    (java.security.Provider) c.getMethod("newProvider").invoke(null), 1);
        }

        X509TrustManager trustAll = new X509TrustManager() {
            public void checkClientTrusted(X509Certificate[] c, String a) {}
            public void checkServerTrusted(X509Certificate[] c, String a) {}
            public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
        };

        System.out.println("okhttp       " + okhttp3.OkHttp.VERSION);
        System.out.println("jvm          " + System.getProperty("java.version"));

        for (int i = 0; i < runs; i++) {
            // A whole new client and a whole new SSLContext per run. Sharing
            // either one gives the stand a single ClientHello: the connection
            // pool reuses the handshake, and a shared context carries a session
            // cache, so the second handshake resumes and carries
            // pre_shared_key. The capture drops resumed handshakes — correctly,
            // a profile describes a first one — and the run would starve.
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(null, new TrustManager[]{trustAll}, new SecureRandom());
            SSLSocketFactory factory = ctx.getSocketFactory();

            OkHttpClient client = new OkHttpClient.Builder()
                    .sslSocketFactory(factory, trustAll)
                    .hostnameVerifier((h, s) -> true)
                    .connectionPool(new okhttp3.ConnectionPool(
                            0, 1, java.util.concurrent.TimeUnit.MILLISECONDS))
                    // Every name resolves to the stand. The point is the name
                    // itself: SunJSSE omits SNI for a hostname with no dot, so
                    // capturing against "localhost" produced a profile that
                    // never sends SNI at all — JA4 read t13i instead of t13d.
                    // An artefact of the measurement, not a property of okhttp.
                    // The stand's certificate already covers www.example.com.
                    .dns(h -> List.of(InetAddress.getByName("127.0.0.1")))
                    .build();

            if (i == 0) {
                System.out.println("tls provider " + ctx.getProvider().getName()
                        + " (" + ctx.getProvider().getVersionStr() + ")");
                System.out.println("suites       "
                        + factory.getDefaultCipherSuites().length + " enabled by default");
            }

            Request req = new Request.Builder().url(url).build();
            try (Response r = client.newCall(req).execute()) {
                System.out.println("  run " + (i + 1) + "/" + runs + "  "
                        + r.code() + " " + r.protocol());
                r.body().bytes();
            } catch (Exception e) {
                System.out.println("  run " + (i + 1) + "/" + runs + "  failed: " + e);
            }
            client.dispatcher().executorService().shutdown();
            client.connectionPool().evictAll();
            Thread.sleep(400);
        }
    }
}
