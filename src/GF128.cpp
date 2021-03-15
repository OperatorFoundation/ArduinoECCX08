/*
 * Copyright (C) 2016 Southern Storm Software, Pty Ltd.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#include "GF128.h"
#include "utility/EndianUtil.h"
#include <string.h>
#include "ArduinoECCX08.h"

/**
 * \class GF128 GF128.h <GF128.h>
 * \brief Operations in the Galois field GF(2^128).
 *
 * This class contains helper functions for performing operations in
 * the Galois field GF(2^128) which is used as the basis of GCM and GHASH.
 * These functions are provided for use by other cryptographic protocols
 * that make use of GF(2^128).
 *
 * Most of the functions in this class use the field, polynomial, and
 * byte ordering conventions described in NIST SP 800-38D (GCM).  The one
 * exception is dblEAX() which uses the conventions of EAX mode instead.
 *
 * References: <a href="http://csrc.nist.gov/publications/nistpubs/800-38D/SP-800-38D.pdf">NIST SP 800-38D</a>
 *
 * \sa GCM, GHASH
 */

/**
 * \brief Initialize multiplication in the GF(2^128) field.
 *
 * \param H The hash state to be initialized.
 * \param key Points to the 16 byte authentication key which is assumed
 * to be in big-endian byte order.
 *
 * This function and the companion mul() are intended for use by other
 * classes that need access to the raw GF(2^128) field multiplication of
 * GHASH without the overhead of GHASH itself.
 *
 * \sa mul(), dbl()
 */
void GF128::mulInit(uint32_t H[4], const void *key)
{
#if defined(__AVR__)
    // Copy the key into H but leave it in big endian order because
    // we can correct for the byte order in mul() below.
    memcpy(H, key, 16);
#else
    // Copy the key into H and convert from big endian to host order.
    memcpy(H, key, 16);
#if defined(CRYPTO_LITTLE_ENDIAN)
    H[0] = be32toh(H[0]);
    H[1] = be32toh(H[1]);
    H[2] = be32toh(H[2]);
    H[3] = be32toh(H[3]);
#endif
#endif
}

/**
 * \brief Perform a multiplication in the GF(2^128) field.
 *
 * \param Y The first value to multiply, and the result.  This array is
 * assumed to be in big-endian order on entry and exit.
 * \param H The second value to multiply, which must have been initialized
 * by the mulInit() function.
 *
 * This function and the companion mulInit() are intended for use by other
 * classes that need access to the raw GF(2^128) field multiplication of
 * GHASH without the overhead of GHASH itself.
 *
 * \sa mulInit(), dbl()
 */
void GF128::mul(uint32_t Y[4], const uint32_t H[4])
{
  byte h[16];
  byte input[16];
  byte result[16];

  memcpy(h, H, 16);
  memcpy(input, Y, 16);

  ECCX08.aesMultiply(0, input, h, result);

  memcpy(result, Y, 16);
}

/**
 * \brief Doubles a value in the GF(2^128) field.
 *
 * \param V The value to double, and the result.  This array is
 * assumed to be in big-endian order on entry and exit.
 *
 * Block cipher modes such as <a href="https://en.wikipedia.org/wiki/Disk_encryption_theory#Xor-encrypt-xor_.28XEX.29">XEX</a>
 * are similar to CTR mode but instead of incrementing the nonce every
 * block, the modes multiply the nonce by 2 in the GF(2^128) field every
 * block.  This function is provided to help with implementing such modes.
 *
 * \sa dblEAX(), dblXTS(), mul()
 */
void GF128::dbl(uint32_t V[4])
{
#if defined(__AVR__)
    __asm__ __volatile__ (
        "ld r16,Z\n"
        "ldd r17,Z+1\n"
        "ldd r18,Z+2\n"
        "ldd r19,Z+3\n"
        "lsr r16\n"
        "ror r17\n"
        "ror r18\n"
        "ror r19\n"
        "std Z+1,r17\n"
        "std Z+2,r18\n"
        "std Z+3,r19\n"
        "ldd r17,Z+4\n"
        "ldd r18,Z+5\n"
        "ldd r19,Z+6\n"
        "ldd r20,Z+7\n"
        "ror r17\n"
        "ror r18\n"
        "ror r19\n"
        "ror r20\n"
        "std Z+4,r17\n"
        "std Z+5,r18\n"
        "std Z+6,r19\n"
        "std Z+7,r20\n"
        "ldd r17,Z+8\n"
        "ldd r18,Z+9\n"
        "ldd r19,Z+10\n"
        "ldd r20,Z+11\n"
        "ror r17\n"
        "ror r18\n"
        "ror r19\n"
        "ror r20\n"
        "std Z+8,r17\n"
        "std Z+9,r18\n"
        "std Z+10,r19\n"
        "std Z+11,r20\n"
        "ldd r17,Z+12\n"
        "ldd r18,Z+13\n"
        "ldd r19,Z+14\n"
        "ldd r20,Z+15\n"
        "ror r17\n"
        "ror r18\n"
        "ror r19\n"
        "ror r20\n"
        "std Z+12,r17\n"
        "std Z+13,r18\n"
        "std Z+14,r19\n"
        "std Z+15,r20\n"
        "mov r17,__zero_reg__\n"
        "sbc r17,__zero_reg__\n"
        "andi r17,0xE1\n"
        "eor r16,r17\n"
        "st Z,r16\n"
        : : "z"(V)
        : "r16", "r17", "r18", "r19", "r20"
    );
#else
    uint32_t V0 = be32toh(V[0]);
    uint32_t V1 = be32toh(V[1]);
    uint32_t V2 = be32toh(V[2]);
    uint32_t V3 = be32toh(V[3]);
    uint32_t mask = ((~(V3 & 0x01)) + 1) & 0xE1000000;
    V3 = (V3 >> 1) | (V2 << 31);
    V2 = (V2 >> 1) | (V1 << 31);
    V1 = (V1 >> 1) | (V0 << 31);
    V0 = (V0 >> 1) ^ mask;
    V[0] = htobe32(V0);
    V[1] = htobe32(V1);
    V[2] = htobe32(V2);
    V[3] = htobe32(V3);
#endif
}

/**
 * \brief Doubles a value in the GF(2^128) field using EAX conventions.
 *
 * \param V The value to double, and the result.  This array is
 * assumed to be in big-endian order on entry and exit.
 *
 * This function differs from dbl() that it uses the conventions of EAX mode
 * instead of those of NIST SP 800-38D (GCM).  The two operations have
 * equivalent security but the bits are ordered differently with the
 * value shifted left instead of right.
 *
 * References: https://en.wikipedia.org/wiki/EAX_mode,
 * http://web.cs.ucdavis.edu/~rogaway/papers/eax.html
 *
 * \sa dbl(), dblXTS(), mul()
 */
void GF128::dblEAX(uint32_t V[4])
{
#if defined(__AVR__)
    __asm__ __volatile__ (
        "ldd r16,Z+15\n"
        "ldd r17,Z+14\n"
        "ldd r18,Z+13\n"
        "ldd r19,Z+12\n"
        "lsl r16\n"
        "rol r17\n"
        "rol r18\n"
        "rol r19\n"
        "std Z+14,r17\n"
        "std Z+13,r18\n"
        "std Z+12,r19\n"
        "ldd r17,Z+11\n"
        "ldd r18,Z+10\n"
        "ldd r19,Z+9\n"
        "ldd r20,Z+8\n"
        "rol r17\n"
        "rol r18\n"
        "rol r19\n"
        "rol r20\n"
        "std Z+11,r17\n"
        "std Z+10,r18\n"
        "std Z+9,r19\n"
        "std Z+8,r20\n"
        "ldd r17,Z+7\n"
        "ldd r18,Z+6\n"
        "ldd r19,Z+5\n"
        "ldd r20,Z+4\n"
        "rol r17\n"
        "rol r18\n"
        "rol r19\n"
        "rol r20\n"
        "std Z+7,r17\n"
        "std Z+6,r18\n"
        "std Z+5,r19\n"
        "std Z+4,r20\n"
        "ldd r17,Z+3\n"
        "ldd r18,Z+2\n"
        "ldd r19,Z+1\n"
        "ld r20,Z\n"
        "rol r17\n"
        "rol r18\n"
        "rol r19\n"
        "rol r20\n"
        "std Z+3,r17\n"
        "std Z+2,r18\n"
        "std Z+1,r19\n"
        "st Z,r20\n"
        "mov r17,__zero_reg__\n"
        "sbc r17,__zero_reg__\n"
        "andi r17,0x87\n"
        "eor r16,r17\n"
        "std Z+15,r16\n"
        : : "z"(V)
        : "r16", "r17", "r18", "r19", "r20"
    );
#else
    uint32_t V0 = be32toh(V[0]);
    uint32_t V1 = be32toh(V[1]);
    uint32_t V2 = be32toh(V[2]);
    uint32_t V3 = be32toh(V[3]);
    uint32_t mask = ((~(V0 >> 31)) + 1) & 0x00000087;
    V0 = (V0 << 1) | (V1 >> 31);
    V1 = (V1 << 1) | (V2 >> 31);
    V2 = (V2 << 1) | (V3 >> 31);
    V3 = (V3 << 1) ^ mask;
    V[0] = htobe32(V0);
    V[1] = htobe32(V1);
    V[2] = htobe32(V2);
    V[3] = htobe32(V3);
#endif
}

/**
 * \brief Doubles a value in the GF(2^128) field using XTS conventions.
 *
 * \param V The value to double, and the result.  This array is
 * assumed to be in littlen-endian order on entry and exit.
 *
 * This function differs from dbl() that it uses the conventions of XTS mode
 * instead of those of NIST SP 800-38D (GCM).  The two operations have
 * equivalent security but the bits are ordered differently with the
 * value shifted left instead of right.
 *
 * References: <a href="http://libeccio.di.unisa.it/Crypto14/Lab/p1619.pdf">IEEE Std. 1619-2007, XTS-AES</a>
 *
 * \sa dbl(), dblEAX(), mul()
 */
void GF128::dblXTS(uint32_t V[4])
{
#if defined(__AVR__)
    __asm__ __volatile__ (
        "ld r16,Z\n"
        "ldd r17,Z+1\n"
        "ldd r18,Z+2\n"
        "ldd r19,Z+3\n"
        "lsl r16\n"
        "rol r17\n"
        "rol r18\n"
        "rol r19\n"
        "std Z+1,r17\n"
        "std Z+2,r18\n"
        "std Z+3,r19\n"
        "ldd r17,Z+4\n"
        "ldd r18,Z+5\n"
        "ldd r19,Z+6\n"
        "ldd r20,Z+7\n"
        "rol r17\n"
        "rol r18\n"
        "rol r19\n"
        "rol r20\n"
        "std Z+4,r17\n"
        "std Z+5,r18\n"
        "std Z+6,r19\n"
        "std Z+7,r20\n"
        "ldd r17,Z+8\n"
        "ldd r18,Z+9\n"
        "ldd r19,Z+10\n"
        "ldd r20,Z+11\n"
        "rol r17\n"
        "rol r18\n"
        "rol r19\n"
        "rol r20\n"
        "std Z+8,r17\n"
        "std Z+9,r18\n"
        "std Z+10,r19\n"
        "std Z+11,r20\n"
        "ldd r17,Z+12\n"
        "ldd r18,Z+13\n"
        "ldd r19,Z+14\n"
        "ldd r20,Z+15\n"
        "rol r17\n"
        "rol r18\n"
        "rol r19\n"
        "rol r20\n"
        "std Z+12,r17\n"
        "std Z+13,r18\n"
        "std Z+14,r19\n"
        "std Z+15,r20\n"
        "mov r17,__zero_reg__\n"
        "sbc r17,__zero_reg__\n"
        "andi r17,0x87\n"
        "eor r16,r17\n"
        "st Z,r16\n"
        : : "z"(V)
        : "r16", "r17", "r18", "r19", "r20"
    );
#else
    uint32_t V0 = le32toh(V[0]);
    uint32_t V1 = le32toh(V[1]);
    uint32_t V2 = le32toh(V[2]);
    uint32_t V3 = le32toh(V[3]);
    uint32_t mask = ((~(V3 >> 31)) + 1) & 0x00000087;
    V3 = (V3 << 1) | (V2 >> 31);
    V2 = (V2 << 1) | (V1 >> 31);
    V1 = (V1 << 1) | (V0 >> 31);
    V0 = (V0 << 1) ^ mask;
    V[0] = htole32(V0);
    V[1] = htole32(V1);
    V[2] = htole32(V2);
    V[3] = htole32(V3);
#endif
}
