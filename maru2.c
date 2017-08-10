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
  
#include "maru.h"

void encrypt(void *in, void *key, void *out)
{
    uint64_t x0, x1;
    uint64_t k0, k1, k2, k3;
    int      i, t;
    
    w128_t   *x=(w128_t*)in;
    w128_t   *y=(w128_t*)out;
    w256_t   *k=(w256_t*)key;
    
    // copy key to local space
    k0 = k->q[0]; k1 = k->q[1];
    k2 = k->q[2]; k3 = k->q[3];

    // copy buf to local space
    x0 = x->q[0]; x1 = x->q[1];

    for (i=0; i<34; i++)
    {
      // encrypt block
      x0 = (ROTR64(x0, 8) + x1) ^ k0;
      x1 =  ROTL64(x1, 3) ^ x0;
      
      // create next subkey
      k1 = (ROTR64(k1, 8) + k0) ^ i;
      k0 =  ROTL64(k0, 3) ^ k1;
      
      XCHG(k3, k2);
      XCHG(k3, k1);    
    }
    // xor with output
    y->q[0] ^= x0; 
    y->q[1] ^= x1;
}

// str : null terminated API string, not exceeding 32 bytes
// key : 128-bit key to encrypt string
// out : where to store 128-bit hash
void maru2(const char *str, const void *key, void *out) 
{
    w256_t   x;
    uint8_t  *p;
    w128_t   h, t;
    w256_t   k;
    int len, i;  

    // initialize key
    k.q[0] = ((uint64_t*)key)[0];
    k.q[1] = ((uint64_t*)key)[1];
    
    k.q[2] = k.q[0] ^ MARU_INIT_K; 
    k.q[3] = k.q[1] ^ MARU_INIT_J; 

    // initialize hash
    h.q[0] = 0; h.q[1] = 0;
    t.q[0] = 0; t.q[1] = 0; 
        
    // initialize local buffer for API string
    memset(&x, 0, sizeof(x));
    
    // obtain length of API, and copy to local buffer
    for (len=0; str[len] != 0 && len < MARU_STR_LEN; len++) {
      x.b[len] = str[len] ^ 6;
    }
    
    p = (uint8_t*)x.b;
    
    // encrypt API string
    while (len>0) {  
      encrypt(p, &k, &h);
      len -= MARU2_BLK_LEN;
      p += MARU2_BLK_LEN;
    }    
    // pad
    h.b[0] ^= (uint8_t)len;
    h.w[len&3] ^= 0x80;
    // return encrypted hash
    encrypt(&h, &k, &h);
    memcpy (out, &h, 16);
}

#ifdef TEST

#include <stdio.h>

const char *api_tbl[]=
{ "CreateProcessA",
  "LoadLibrayA",
  "GetProcAddress",
  "WSASocketA",
  "GetOverlappedResult",
  "WaitForSingleObject",
  "TerminateProcess",
  "CloseHandle"  };

const char *key_tbl[]=
{ "api_key1api_key1",
  "api_key2api_key2",
  "api_key3api_key3"  };

const char *api_hash[]=
{"527618f17d61aae18b646d8fa8808501",
"7c6c6b1eac478d80debb3fdc04c09554",
"9b5366af83c110685826c902b719245b",
"bafe25557aace2946119d7538e9ff932",
"474d26c6aac1ad2529ab5e5fc48f4086",
"fccd9271d6f00c7bd2a37120a4eda730",
"8f05eb9f321c71dd6de89362dc2e409f",
"bb5c414077a67894b07fdd245912b8cd",

"74036f28efe0ac9c256dadc7dd10b7d8",
"5107ea9c8a6ff2fc01a41818f609e01f",
"fa6920107505230a90b51d899036614e",
"55fd0a95eba1d803bd8cfba799cb9786",
"0f5b6a702f45754e4e1704302e4553c9",
"176da096256b777035740618a81fe14b",
"96e9a658c18bb9d24e2753da5be6aa07",
"1f7cbdc363cd3e258901113fe3c437e6",

"3fa15552737b61795d5318126ffb594a",
"17c2e4780452075fb8f0a6e1fd785e33",
"483594c47f5224b195fbf63a8026493d",
"0a5874d38f714f2bcd43157d89892d4f",
"045d4e53570d55428cf45b564a8030b0",
"103f2d075d5fd519ee9625f7692ccc7a",
"7299912ee2b3eadcea734d71acac1ded",
"0fdc9355366be1520248ab9714a2df2b" };
  
int _isxdigit (int c)
{
  return (c >= '0' && c <= '9') || 
         (c >= 'a' && c <= 'f') ||
         (c >= 'A' && c <= 'F');
}

int _isprint (int c)
{
  return 1;
}
uint32_t hex2bin (void *bin, const char *hex) {
    uint32_t len, i;
    uint32_t x;
    uint8_t *p=(uint8_t*)bin;
    
    len = strlen (hex);
    
    if ((len & 1) != 0) {
      return 0; 
    }
    
    for (i=0; i<len; i++) {
      if (_isxdigit((int)hex[i]) == 0) {
        return 0; 
      }
    }
    
    for (i=0; i<len / 2; i++) {
      sscanf (&hex[i * 2], "%2x", &x);
      p[i] = (uint8_t)x;
    } 
    return len / 2;
} 

void dump_hash(uint8_t *x)
{
  int i;
  putchar('\"');
  for (i=0; i<16; i++) {
    printf ("%02x", x[i]);
  } 
  putchar('\"');
}

int main(int argc, char *argv[])
{
  uint64_t   h, x, m, k;
  uint8_t    str[MARU2_STR_LEN+1], key[MARU2_KEY_LEN+1];
  int        i, j, equ;
  const char **p=api_hash;
  uint8_t    bin[16], res[16];
  
  if (argc<3) {
    printf ("\nRunning test...\n");
    for (i=0; i<sizeof(key_tbl)/sizeof(char*); i++) {
      putchar('\n');
      for (j=0; j<sizeof(api_tbl)/sizeof(char*); j++) {
        hex2bin((void*)&bin, *p++);
        // zero init key
        memset(key, 0, sizeof(key));
        // copy key
        strncpy((char*)key, key_tbl[i], MARU2_KEY_LEN);
        // hash string        
        maru2(api_tbl[j], key, res);        
        dump_hash(res);
        equ = memcmp(bin, res, 16)==0;
        printf (" = maru(\"%s\", \"%s\") : %s\n", 
          api_tbl[j], key, equ ? "OK" : "FAIL");
      }
    }
    putchar('\n');
    return 0;
  }
  memset(str, 0, sizeof(str));
  memset(key, 0, sizeof(key));
  
  strncpy((char*)str, argv[1], MARU2_STR_LEN);
  strncpy((char*)key, argv[2], MARU2_KEY_LEN); 

  maru2(str, key, bin);
  printf ("Maru hash = ");
  dump_hash(bin);  
  putchar('\n');
  return 0;
}
#endif

