// Prints the offline JA4 of chrome-156-windows for https://example.com/ — the
// value scripts/bindings-agree.sh compares across every binding.
import io.curlpro.Session;

public class Ja4 {
    public static void main(String[] args) {
        try (var s = new Session("chrome-156-windows")) {
            System.out.println(s.fingerprint("https://example.com/").get("ja4"));
        }
    }
}
