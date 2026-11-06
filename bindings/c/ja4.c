/* Prints the offline JA4 of chrome-156-windows for https://example.com/ — the
 * value scripts/bindings-agree.sh compares across every binding. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "curlpro.h"

int main(void) {
    const char *dir = getenv("CURLPRO_PROFILES");
    char *r = curlpro_profiles_load_dir(dir && *dir ? dir : "profiles");
    curlpro_free(r);
    char *s = curlpro_session_new("{\"profile\":\"chrome-156-windows\",\"default_headers\":true}");
    const char *p = strstr(s, "\"session\":");
    curlpro_handle id = p ? atoll(p + 10) : 0;
    curlpro_free(s);
    char *fp = curlpro_session_fingerprint(id, "https://example.com/");
    const char *j = strstr(fp, "\"ja4\":\"");
    if (!j) { fprintf(stderr, "%s\n", fp); return 1; }
    j += 7;
    printf("%.*s\n", (int)(strchr(j, '"') - j), j);
    curlpro_free(fp);
    curlpro_free(curlpro_session_close(id));
    return 0;
}
