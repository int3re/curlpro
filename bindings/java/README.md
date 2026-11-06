# Java

`io.curlpro` — over the Foreign Function and Memory API (`java.lang.foreign`,
final since JDK 22). No JNI, no native glue, no dependencies (a small JSON
reader is included).

```java
try (var s = new Session("chrome-156-windows")) {
    System.out.println(s.fingerprint("https://example.com/").get("ja4"));   // offline

    Response r = s.get("https://example.com/");
    System.out.println(r.status() + " " + r.proto() + " " + r.body().length);

    CompletableFuture<Response> f = s.sendAsync(Request.get("https://example.com/").header("accept-language", "en"));
    f.cancel(true);   // aborts the request

    try (var in = s.stream(Request.get("https://example.com/big"))) { in.transferTo(out); }

    try (var ws = s.websocket("wss://example.com/socket")) {
        ws.send("hi");
        System.out.println(ws.receive().text());
    }
} catch (CurlproException e) {
    if (e.permanent()) throw e;   // configuration, profile_capability, proxy_auth
}
```

`sendAsync` uses the ABI's completion queue: one daemon thread waits on
`curlpro_result_wait` for every call in the process and completes the futures
on the common pool.

## Build and run

```bash
javac --release 22 -d target/classes $(find src/main/java -name '*.java')
CURLPRO_LIBRARY=../../dist/curlpro.dll CURLPRO_PROFILES=../../profiles \
  java --enable-native-access=ALL-UNNAMED -cp target/classes examples/Example.java
```

or `mvn package` with the [pom.xml](pom.xml). `--enable-native-access` silences
the restricted-method warning (on a module path, name the module instead).
The library is found through `CURLPRO_LIBRARY`, the `curlpro.library` system
property, the working directory, the jar itself (`io/curlpro/native/<platform>/`,
extracted to a temporary file — the released jar carries all six platforms),
then the system loader's search path. Profiles come from `CURLPRO_PROFILES`,
the signed bundle in the jar, or the plain profiles in the jar.
