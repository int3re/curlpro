/*
 * A minimal C program on top of include/curlpro.h.
 *
 * Build (Windows, MinGW):
 *   gcc -I../../include example.c ../../dist/curlpro.dll -o example.exe
 * Build (Linux/macOS):
 *   cc -I../../include example.c -L../../dist -lcurlpro -o example
 *
 * Run:
 *   ./example [profiles_dir] [url]
 *
 * JSON is handled with plain string search to keep the example dependency-free;
 * a real program would use a JSON library.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "curlpro.h"

/* Prints an envelope and reports whether it says ok. */
static int envelope_ok(const char *what, const char *env) {
    int ok = env && strstr(env, "\"ok\":true") != NULL;
    if (!ok) fprintf(stderr, "%s failed: %s\n", what, env ? env : "(null)");
    return ok;
}

/* Reads an integer field ("name":123) from JSON; 0 when absent. */
static long long json_int(const char *json, const char *name) {
    char key[64];
    snprintf(key, sizeof key, "\"%s\":", name);
    const char *p = strstr(json, key);
    return p ? atoll(p + strlen(key)) : 0;
}

/* Copies a string field ("name":"value") into out; empty when absent. */
static void json_str(const char *json, const char *name, char *out, size_t cap) {
    char key[64];
    snprintf(key, sizeof key, "\"%s\":\"", name);
    const char *p = strstr(json, key);
    out[0] = '\0';
    if (!p) return;
    p += strlen(key);
    size_t n = 0;
    while (p[n] && p[n] != '"' && n + 1 < cap) { out[n] = p[n]; n++; }
    out[n] = '\0';
}

/* Builds a request frame: [u32 LE json length][json][body]. */
static char *make_frame(const char *json, const char *body, size_t body_len, int *frame_len) {
    uint32_t jl = (uint32_t)strlen(json);
    size_t total = CURLPRO_FRAME_HEADER + jl + body_len;
    char *f = malloc(total);
    f[0] = (char)(jl & 0xff); f[1] = (char)((jl >> 8) & 0xff);
    f[2] = (char)((jl >> 16) & 0xff); f[3] = (char)((jl >> 24) & 0xff);
    memcpy(f + CURLPRO_FRAME_HEADER, json, jl);
    if (body_len) memcpy(f + CURLPRO_FRAME_HEADER + jl, body, body_len);
    *frame_len = (int)total;
    return f;
}

int main(int argc, char **argv) {
    const char *profiles = argc > 1 ? argv[1] : "../../profiles";
    const char *url = argc > 2 ? argv[2] : "https://example.com/";

    char *v = curlpro_version();
    printf("library: %s (header %s)\n", v, CURLPRO_ABI_VERSION_STRING);
    curlpro_free(v);

    char *loaded = curlpro_profiles_load_dir(profiles);
    if (!envelope_ok("load profiles", loaded)) { curlpro_free(loaded); return 1; }
    curlpro_free(loaded);

    char *s = curlpro_session_new("{\"profile\":\"chrome-156-windows\",\"timeout_ms\":20000}");
    if (!envelope_ok("session_new", s)) { curlpro_free(s); return 1; }
    curlpro_handle session = json_int(s, "session");
    curlpro_free(s);
    printf("session: %lld\n", session);

    char *fp = curlpro_session_fingerprint(session, url);
    if (envelope_ok("fingerprint", fp)) {
        char ja4[128];
        json_str(fp, "ja4", ja4, sizeof ja4);
        printf("ja4 (offline): %s\n", ja4);
    }
    curlpro_free(fp);

    char meta[512];
    snprintf(meta, sizeof meta, "{\"method\":\"GET\",\"url\":\"%s\"}", url);
    int frame_len = 0, out_len = 0;
    char *frame = make_frame(meta, NULL, 0, &frame_len);
    char *resp = curlpro_request(session, frame, frame_len, &out_len);
    free(frame);
    if (resp && out_len >= CURLPRO_FRAME_HEADER) {
        uint32_t ml = (uint8_t)resp[0] | (uint8_t)resp[1] << 8 | (uint8_t)resp[2] << 16 | (uint32_t)(uint8_t)resp[3] << 24;
        char *json = malloc(ml + 1);
        memcpy(json, resp + CURLPRO_FRAME_HEADER, ml);
        json[ml] = '\0';
        if (envelope_ok("request", json)) {
            char proto[32];
            json_str(json, "proto", proto, sizeof proto);
            printf("status: %lld, proto: %s, body: %d bytes\n", json_int(json, "status"), proto,
                   out_len - CURLPRO_FRAME_HEADER - (int)ml);
        }
        free(json);
    }
    curlpro_free(resp);

    char *closed = curlpro_session_close(session);
    curlpro_free(closed);
    return 0;
}
