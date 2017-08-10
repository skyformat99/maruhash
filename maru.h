/**
  Copyright © 2017 Odzhan. All Rights Reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are
  met:

  1. Redistributions of source code must retain the above copyright
  notice, this list of conditions and the following disclaimer.

  2. Redistributions in binary form must reproduce the above copyright
  notice, this list of conditions and the following disclaimer in the
  documentation and/or other materials provided with the distribution.

  3. The name of the author may not be used to endorse or promote products
  derived from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY AUTHORS "AS IS" AND ANY EXPRESS OR
  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
  DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
  INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
  STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
  ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
  POSSIBILITY OF SUCH DAMAGE. */

#ifndef MARU_H
#define MARU_H

#include <string.h>
#include <stdint.h>

#include "macros.h"

#define MARU_STR_LEN 32
#define MARU2_STR_LEN 32

#define MARU_KEY_LEN 8
#define MARU2_KEY_LEN 16

#define MARU_BLK_LEN 8
#define MARU2_BLK_LEN 16

#define MARU_INIT_H  0x654C37754C5E9939ULL // 729927007299270072992700729927
#define MARU_INIT_K  0x654C37754C5E9939ULL // 729927007299270072992700729927
#define MARU_INIT_J  0x63D71759D38EF6CAULL

typedef union _w32_t {
  uint8_t  b[4];
  uint32_t w;
} w32_t;

typedef union _w64_t {
  uint8_t  b[8];
  uint32_t w[2];
  uint64_t q; 
} w64_t;

typedef union _w128_t {
  uint8_t  b[16];
  uint32_t w[4];
  uint64_t q[2];  
} w128_t;

typedef union _w256_t {
  uint8_t  b[32];
  uint32_t w[8];
  uint64_t q[4];
} w256_t;

#ifdef __cplusplus
extern "C" {
#endif

  uint64_t maru (const char*, const void*);
  void maru2 (const char*, const void*, void*);
  uint64_t marux (const char*, const void*);

#ifdef __cplusplus
}
#endif

#endif
  
