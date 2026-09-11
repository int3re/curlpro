// Does the real okhttp download the thing our reproduction of it cannot?
//
// Our profile declares okhttp's SETTINGS_INITIAL_WINDOW_SIZE of 16 MiB and
// dies with FLOW_CONTROL_ERROR on pypi.org/simple/, while the same download
// under Chrome's 6 MiB window succeeds and a local Go h2 server serves 40 MB
// through either without complaint. That leaves two possibilities: our HTTP/2
// layer mishandles a 16 MiB window against that particular server, or okhttp
// itself would fail the same way and the reproduction is faithful.
//
// Asking okhttp is the only way to tell them apart.
//
//   java -cp "lib/*;." Big <url> [conscrypt]

import java.security.Security;
import java.util.concurrent.TimeUnit;

import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

public class Big {
    public static void main(String[] args) throws Exception {
        String url = args.length > 0 ? args[0] : "https://pypi.org/simple/";
        boolean conscrypt = args.length > 1 && args[1].equals("conscrypt");

        if (conscrypt) {
            Class<?> c = Class.forName("org.conscrypt.Conscrypt");
            Security.insertProviderAt(
                    (java.security.Provider) c.getMethod("newProvider").invoke(null), 1);
        }

        OkHttpClient client = new OkHttpClient.Builder()
                .readTimeout(120, TimeUnit.SECONDS)
                .callTimeout(180, TimeUnit.SECONDS)
                .build();

        long t0 = System.currentTimeMillis();
        Request req = new Request.Builder().url(url).build();
        try (Response r = client.newCall(req).execute()) {
            byte[] body = r.body().bytes();
            System.out.printf("%s  %d  %s  %d bytes in %.1fs%n",
                    url, r.code(), r.protocol(), body.length,
                    (System.currentTimeMillis() - t0) / 1000.0);
        } catch (Exception e) {
            System.out.printf("%s  FAILED after %.1fs: %s%n",
                    url, (System.currentTimeMillis() - t0) / 1000.0, e);
        }
        client.dispatcher().executorService().shutdown();
        client.connectionPool().evictAll();
    }
}
