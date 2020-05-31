# sha2-with-intrinsic

This sample code package is an optimized version of SHA256 and SHA512. 

The code is written by Nir Drucker and Shay Gueron, AWS Cryptographic Algorithms Group.

While C code is easier to maintain and review, the performance obtained by compilation (e.g., with gcc-9 and clang-9) is often slower than the performance of hand written assembly code (e.g., the code in this example). This sample code is made publicly available to help compiler designers understand this use case by reviewing the code and its generated assembler. We hope this information will improve compiler's abilities to generate efficient assembler. 

This sample code provides testing binaries but no shared or a static libraries. This is because the code is desgined to be used for benchmarking purposes only and not in final products.

The x86-64 AVX code is based on the paper:
- Gueron, S., Krasnov, V. Parallelizing message schedules to accelerate the computations of hash functions. J Cryptogr Eng 2, 241–253 (2012). https://doi.org/10.1007/s13389-012-0037-z
Some parts of the code were translated from (Perl)assembly (OpenSSL commit [13c5d744](https://github.com/openssl/openssl/tree/e32c608e0733d5b295c9aa119153133413c5d744)) to C.

The code version that uses Intel SHA Extensions instructions is based on the following reference:
- https://software.intel.com/en-us/articles/intel-sha-extensions

## License

This project is licensed under the Apache-2.0 License.

Dependencies
-----
This package requires 
- CMake 3 and above 
- A compiler that supports the required C intrinsics (e.g., AVX/ AVX2/ AVX512/ SHA_NI on x86-64 machines). For example, GCC-9 and Clang-9.
- An installation of OpenSSL for testing

BUILD
-----

To build the directory first create a working directory
```
mkdir build
cd build
```

Then, run CMake and compile
```
cmake -DCMAKE_BUILD_TYPE=Release ..
make
```

Additional CMake compilation flags:
 - TEST_SPEED               - Measure and prints the performance in cycles
 - ALTERNATIVE_AVX512_IMPL  - The X86-64 AVX512 extension provides a rotate intrinsic. Setting this flag tells the AVX/AVX2/AVX512 implementations to use this intrinsic. To test this implementation the binary should be compiled with this flag set.
 - DONT_USE_UNROLL_PRAGMA   - The code by default uses the unroll pragma. Use this flag to disable this.
 - ASAN/MSAN/TSAN/UBSAN     - Compiling using Address/Memory/Thread/Undefined-Behaviour sanitizer respectively. 
 - MONTE_CARLO_NUM_OF_TESTS - Set the number of Monte Carlo tests (default:100,000)

To clean - remove the `build` directory. Note that a "clean" is required prior to compilation with modified flags.

To format (`clang-format-9` or above is required):

`make format`

To use clang-tidy (`clang-tidy-9` is required):

```
CC=clang-9 cmake -DCMAKE_C_CLANG_TIDY="clang-tidy-9;--fix-errors;--format-style=file" ..
make 
```

Before committing code, please test it using
`tests/pre-commit-script.sh` 
This will run all the sanitizers and also `clang-format` and `clang-tidy` (requires clang-9 to be installed).

The package was compiled and tested with gcc-9 and clang-9 in 64-bit mode. 
Tests were run on a Linux (Ubuntu 18.04.4 LTS) OS on x86-64 and AARCH64 machines. 
Compilation on other platforms may require some adjustments.

Performance measurements
------------------------
When using the TEST_SPEED flag the performance measurements are reported in processor cycles (per single core). The results are obtained using the following methodology. Each measured function was isolated, run 25 times (warm-up), followed  by  100  iterations  that  were  clocked and averaged. To minimize the effect of background tasks running on the system, every experiment was repeated 10 times, and the minimum result is reported.

The library reports the results only for supported code by the OS/compiler. It also compares the results of the C with intrinsic code to the assembly code of OpenSSL commit [13c5d744](https://github.com/openssl/openssl/tree/e32c608e0733d5b295c9aa119153133413c5d744) (see [here](/src/openssl/README.md) for more details).

A benchmark example is found [here](benchmark_example.md).

Testing
-------
- The library uses OpenSSL for its testings. It compares the results of running its SHA256/SHA512 implementation to the OpenSSL results on strings in different lengths (0-1000 bytes). 
- The library was run using Address/Memory/Thread/Undefined-Behaviour sanitizers.
