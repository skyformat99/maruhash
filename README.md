# About

Maru (*Ma-roo*) hash is a string hash function that uses the Davies-Meyer construction.

The Speck Block cipher is used for the underlying compression function, using 64-bit block, and 128-bit key as parameters.

Maru was written to demonstrate the use of key based hash algorithms in *Position Independent Code* (PIC), but may have other applications.

# Davies-Meyer construction

The Davies–Meyer single-block-length compression function feeds each block of the message (mi) as the key to a block cipher. 

![](https://github.com/odzhan/maruhash/blob/master/img/dm_simple.png)

It feeds the previous hash value (Hi-1) as the plain text to be encrypted. The output cipher text is then also XORed with the previous hash value (Hi-1) to produce the next hash value (Hi). 

In the first round when there is no previous hash value it uses a constant pre-specified initial value (H0). 

# The Maru constant

This constant does not have any special purpose.

It's simply used to initialize H0, and is the multiplicative inverse, (denoted by 1/x or x−1) of the prime number 137, converted to an integer.

More specifically.

* 0.00729927007299270072992700729927 is the multiplicative inverse of 137.
* Discard the first 2 zeros of fractional part and convert to 64-bit integer.
* The result is 0x654C37754C5E9939
 
Your results may differ depending on calculator, and please feel free to correct me if you believe the result is wrong.

# Prototype

The function takes a string as first parameter, and key as the second.
maru expects ***key*** to be a 64-bit value and ***str*** to be null terminated string.

	uint64_t maru (const void* str, const void* key);

# Compiling

For MSVC users, type: **nmake msvc**

For GNU C, type: **make gnu**

# License

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
  POSSIBILITY OF SUCH DAMAGE.

# Maru

This is Maru the cat.

![](https://github.com/odzhan/maruhash/blob/master/img/maru_cat.png)