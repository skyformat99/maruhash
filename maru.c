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

uint64_t encrypt(void *buf, void *key)
{
    uint32_t x0, x1;
    uint32_t k0, k1, k2, k3;
    int      i, t;
    
    w64_t    *x=(w64_t*)buf;
    w128_t   *k=(w128_t*)key;
    
    // copy key to local space
    k0 = k->w[0]; k1 = k->w[1];
    k2 = k->w[2]; k3 = k->w[3];

    // copy buf to local space
    x0 = x->w[0]; x1 = x->w[1];

    for (i=0; i<27; i++)
    {
      // encrypt block
      x0 = (ROTR32(x0, 8) + x1) ^ k0;
      x1 =  ROTL32(x1, 3) ^ x0;
      
      // create next subkey
      k1 = (ROTR32(k1, 8) + k0) ^ i;
      k0 =  ROTL32(k0, 3) ^ k1;
      
      XCHG(k3, k2);
      XCHG(k3, k1);    
    }
    x->w[0] = x0; x->w[1] = x1;
    return x->q;    
}

// str : null terminated API string, not exceeding 32 bytes
// key : 64-bit key to encrypt string
//
uint64_t maru(const char *str, const void *key) 
{
    w256_t   x;
    uint8_t  *p;
    w64_t    h;
    w128_t   k;
    int      len;  
      
    // initialize key
    k.q[0] = ((uint64_t*)key)[0];
    k.q[1] = k.q[0] ^ MARU_INIT_K; 

    // initialize hash
    h.q = 0;
    
    // initialize local buffer for API string
    memset(&x, 0, sizeof(x));
    
    // obtain length of API, and copy to local buffer
    for (len=0; str[len] != 0 && len < MARU_STR_LEN; len++) {
      x.b[len] = str[len] ^ 5;
    }
    
    p = (uint8_t*)x.b;
    
    // encrypt API string
    while (len>0) {  
      h.q ^= encrypt(p, &k);
      len -= MARU_BLK_LEN;
      p += MARU_BLK_LEN;
    }    
    // pad
    h.b[0] ^= (uint8_t)len;
    h.w[len&1] ^= 0x80;
    // return encrypted hash
    return encrypt(&h, &k);
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
{ "api_key1",
  "api_key2",
  "api_key3"  };

const char *api_hash[]=
{ "a905bb7836a12e2f",
  "adbb54cfe29cb7ce",
  "874da7739798ce0e",
  "1d52532e55e429f0",
  "14c64a6c64628d78",
  "bb2dcc0cce5c6494",
  "f4999b3f4d44c3fe",
  "b9372bbe2b595de2",

  "aa2f4e21e967b2dd",
  "ce602ea473a05cf6",
  "4ac25f5fce9cdb73",
  "eac5f56cc32b5a9a",
  "ab2b5105242c6206",
  "502891ee77cb481a",
  "e44bf17b4f7286f6",
  "537f03e076869311",

  "c183f605e22986fb",
  "d0bc8a3068770545",
  "23f0e4f12cb9404a",
  "3102e5f5416b9ab0",
  "8a1722b974d6ec2d",
  "5fc4de4ed3581051",
  "31dd7d8612b1b301",
  "624f12e454dc3d09" };
  
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

int main(int argc, char *argv[])
{
  uint64_t   h, x, m, k;
  uint8_t    str[MARU_STR_LEN+1], key[MARU_KEY_LEN+1];
  int        i, j;
  const char **p=api_hash;
  
  if (argc<3) {
    printf ("\nRunning test...\n");
    for (i=0; i<sizeof(key_tbl)/sizeof(char*); i++) {
      putchar('\n');
      for (j=0; j<sizeof(api_tbl)/sizeof(char*); j++) {
        hex2bin((void*)&h, *p++);
        // test vectors here need to be byte swapped
        h = SWAP64(h);
        // zero init key
        memset(key, 0, sizeof(key));
        // copy key
        strncpy((char*)key, key_tbl[i], MARU_KEY_LEN);
        // hash string        
        x = maru(api_tbl[j], key);        
        
        printf ("\n  \"%016llx\" = maru(\"%s\", \"%s\") : %s", 
          (unsigned long long)x, api_tbl[j], key, h==x ? "OK" : "FAIL");
      }
    }
    putchar('\n');
    return 0;
  }
  memset(str, 0, sizeof(str));
  memset(key, 0, sizeof(key));
  
  strncpy((char*)str, argv[1], MARU_STR_LEN);
  strncpy((char*)key, argv[2], MARU_KEY_LEN); 

  h = maru((const char*)str, key);
  
  printf ("\nMaru Hash = %llx\n", (unsigned long long)h);
  return 0;
}
#endif


