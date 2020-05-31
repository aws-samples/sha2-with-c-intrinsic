// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#if defined(X86_64)
// In OpenSSL the OPENSSL_ia32cap_P array holds the return values (in
// RAX,RBX,RCX,RDX registesrs) of executing the Intel CPUID leaf 7 instruction.
// The assembly code chooses the relevant SHA implementation according to this
// array.
unsigned int OPENSSL_ia32cap_P_local[4] = {0};
#endif

#if defined(AARCH64)
unsigned int OPENSSL_armcap_P_local = 0;
#endif
