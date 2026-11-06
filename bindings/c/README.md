# C and C++

Include [include/curlpro.h](../../include/curlpro.h) and link the library. The
header is plain C99 with `extern "C"` guards, so it compiles unchanged as C++.

```bash
gcc -I../../include example.c ../../dist/curlpro.dll -o example.exe       # Windows, MinGW
cc  -I../../include example.c -L../../dist -lcurlpro -o example           # Linux, macOS
./example ../../profiles https://example.com/
```

With MSVC, make an import library from the DLL first (`lib /def:curlpro.def
/out:curlpro.lib`, the `.def` listing the 45 exports), or load it with
`LoadLibrary`/`GetProcAddress`.

[example.c](example.c) loads profiles, opens a session, prints the offline JA4
and sends a request, building and parsing frames by hand. Rules worth keeping in
mind (all in [docs/C-ABI.md](../../docs/C-ABI.md)):

- free every returned `char *` with `curlpro_free`, never `free`;
- frames are binary: use `*out_len`, not `strlen`;
- send the browser defaults in the session config (`default_headers`,
  `follow_redirects`, `cookies`, `resume`… are `false` when missing);
- with the async calls, have exactly one thread call `curlpro_result_wait`.
