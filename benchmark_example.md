A benchmark example on a Dell XPS 13 7390 2-in-1 laptop. It has a 10th generation Intel(c) Core(TM) processor (microarchitecture codename "Ice Lake"[ICL]). The specifics are Intel(c) Core(TM) i7-1065G7 CPU 1.30GHz. This platform has 16 GB RAM, 48K L1d cache, 32K L1i cache, 512K L2 cache, and 8MiB L3 cache. The Intel(c) Turbo Boost Technology was turned off. 
The code was compiled with clang-9 and ran on Ubuntu 18.04.2 LTS.
The results are in CPU cycles.

SHA-256 Benchmark:
------------------
```
        msg     generic      avx (C)   avx (ossl)     avx2 (C)  avx2 (ossl)   avx512 (C)  sha ext (C) sha ext (ossl) 
    1 bytes        1024          791          754          821          724          879          287          288 
    2 bytes        1026          792          754          823          724          882          287          288 
    4 bytes        1024          791          753          823          725          878          288          288 
    8 bytes        1027          792          753          824          724          877          287          288 
   16 bytes        1023          777          728          820          702          877          288          283 
   32 bytes        1023          782          726          814          699          879          281          280 
   64 bytes        1992         1518         1394         1582         1342         1708          424          446 
  128 bytes        2906         2244         2051         2247         1918         2360          605          644 
  256 bytes        4721         3693         3363         3620         3121         3621          956         1027 
  512 bytes        8381         6595         5987         6373         5522         6318         1666         1797 
 1024 bytes       15566        12409        11236        11892        10339        11728         3104         3340 
 2048 bytes       29955        24038        21753        22925        19961        22507         5968         6424 
 4096 bytes       58970        47377        42843        45037        39326        44219        11692        12594 
 8192 bytes      116991        94007        84981        89160        78060        87494        23148        24936 
16384 bytes      232664       187280       169477       177774       154960       174157        45780        49741 
32768 bytes      464254       373359       337247       354136       309742       346105        91667        99088 
65536 bytes      927237       747417       675843       709146       620729       694132       183685       198528 
```

SHA-512 Benchmark:
------------------
```
        msg     generic      avx (C)   avx (ossl)     avx2 (C)  avx2 (ossl)   avx512 (C)
    1 bytes        1428         1026          972         1062          961         1139 
    2 bytes        1432         1023          969         1066          957         1138 
    4 bytes        1432         1025          973         1063          955         1138 
    8 bytes        1433         1026          973         1063          955         1138 
   16 bytes        1431         1018          969         1063          955         1137 
   32 bytes        1420         1019          967         1060          951         1135 
   64 bytes        1418         1019          962         1058          949         1132 
  128 bytes        2766         1963         1843         2042         1823         2211 
  256 bytes        4084         2891         2692         2951         2537         3114 
  512 bytes        6710         4738         4388         4725         4096         4810 
 1024 bytes       11932         8436         7779         8291         7206         8379 
 2048 bytes       22472        15837        14570        15389        13456        15458 
 4096 bytes       43792        30662        28283        29798        26022        29482 
 8192 bytes       85757        60456        55429        58261        50945        57625 
16384 bytes      169996       119761       109960       114952       101207       113801 
32768 bytes      338123       238652       219153       228957       201284       226530 
65536 bytes      675827       476242       437028       456221       402204       450687 
```
