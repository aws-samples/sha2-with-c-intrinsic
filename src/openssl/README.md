The code in this directory was copied from the compilation artifacts of OpenSSL commit [13c5d744](https://github.com/openssl/openssl/tree/e32c608e0733d5b295c9aa119153133413c5d744) Feb 24, 2020. 

To reproduce on a platform equipped with Intel 10th generation CPU:

```
git clone https://github.com/openssl/openssl
cd openssl
git checkout e32c608e0733d5b295c9aa119153133413c5d744
./config
make
```

and the files are found in:

```
./crypto/sha/sha256-x86_64.s
./crypto/sha/sha152-x86_64.s
```

These files include several implementations of SHA256 and SHA512 in x86-64 assembly. In particular, they include AVX/AVX2 implementations and for SHA256 also an implementation that uses the new SHA extension that is available on Intel's 10th generation CPUs.

The relevant implementation is chosen according to the value of the OPENSSL_ia32cap_P array.

On an AARCH64 machine, the files are found in:

```
./crypto/sha/sha256-armv8.S
./crypto/sha/sha512-armv8.S
```
The relevant implementation is chosen according to the value of the OPENSSL_armcap_P array.

To avoid symbols conflicts/mistakes the name of the function `sha256_block_data_order` was changed to `sha256_block_data_order_local`, the parameter `OPENSSL_ia32cap_P` was changed to `OPENSSL_ia32cap_P_local`, the parameter `OPENSSL_armcap_P` was changed to `OPENSSL_armcap_P_local` and in the aarch64 files the include files (dependencies) were removed.
