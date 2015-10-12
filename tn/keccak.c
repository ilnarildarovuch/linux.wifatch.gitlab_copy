
/*
The Keccak sponge function, designed by Guido Bertoni, Joan Daemen,
Michaël Peeters and Gilles Van Assche. For more information, feedback or
questions, please refer to our website: http://keccak.noekeon.org/

Implementation by Ronny Van Keer,
hereby denoted as "the implementer".

To the extent possible under law, the implementer has waived all copyright
and related or neighboring rights to the source code in this file.
http://creativecommons.org/publicdomain/zero/1.0/

Endianness fixes and further downsizing by Team White.
*/

#define EXTRA_SMALL 1

#include <string.h>
#include <endian.h>
#include <inttypes.h>

#define cKeccakB    1600
#define cKeccakR    1088

typedef uint64_t tKeccakLane;

#define cKeccakNumberOfRounds   24

#define ROL(a, offset) (((a) << ((offset) & 63)) ^ ((a) >> (64 - ((offset) & 63))))

static const tKeccakLane KeccakF_RoundConstants[cKeccakNumberOfRounds] = {
        0x0000000000000001ULL,
        0x0000000000008082ULL,
        0x800000000000808aULL,
        0x8000000080008000ULL,
        0x000000000000808bULL,
        0x0000000080000001ULL,
        0x8000000080008081ULL,
        0x8000000000008009ULL,
        0x000000000000008aULL,
        0x0000000000000088ULL,
        0x0000000080008009ULL,
        0x000000008000000aULL,
        0x000000008000808bULL,
        0x800000000000008bULL,
        0x8000000000008089ULL,
        0x8000000000008003ULL,
        0x8000000000008002ULL,
        0x8000000000000080ULL,
        0x000000000000800aULL,
        0x800000008000000aULL,
        0x8000000080008081ULL,
        0x8000000000008080ULL,
        0x0000000080000001ULL,
        0x8000000080008008ULL
};

static const uint8_t KeccakF_RotationConstants[25] = {
        1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44
};

static const uint8_t KeccakF_PiLane[25] = {
        10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1
};

static const uint8_t KeccakF_Mod5[10] = {
        0, 1, 2, 3, 4, 0, 1, 2, 3, 4
};

static struct
{
        uint8_t state[cKeccakB / 8];
        int inqueue;
} Keccak_state;

static void Keccak_bss(void)
{
#if __BYTE_ORDER == __BIG_ENDIAN
        int i, j;

        uint8_t *o = (void *)Keccak_state.state;

        for (i = 0; i < cKeccakB / 64; ++i) {
                uint64_t t = ((tKeccakLane *) Keccak_state.state)[i];

                for (j = 0; j < 8; ++j) {
                        *o++ = t;
                        t >>= 8;
                }
        }
#endif
}

static void KeccakF(void)
{
        int round, x, y;
        tKeccakLane temp;
        tKeccakLane BC[5];
        tKeccakLane *state = (tKeccakLane *) Keccak_state.state;
        unsigned int lfsr = 1;

        Keccak_bss();

        for (round = 0; round < cKeccakNumberOfRounds; ++round) {
                // Theta
                for (x = 0; x < 5; ++x)
                        BC[x] = state[x] ^ state[5 + x] ^ state[10 + x] ^ state[15 + x] ^ state[20 + x];

                for (x = 0; x < 5; ++x) {
                        temp = BC[KeccakF_Mod5[x + 4]] ^ ROL(BC[KeccakF_Mod5[x + 1]], 1);

                        for (y = 0; y < 25; y += 5)
                                state[y + x] ^= temp;
                }

                // Rho Pi
                temp = state[1];
                for (x = 0; x < 24; ++x) {
                        BC[0] = state[KeccakF_PiLane[x]];
                        state[KeccakF_PiLane[x]] = ROL(temp, KeccakF_RotationConstants[x]);
                        temp = BC[0];
                }

                // Chi
                for (y = 0; y < 25; y += 5) {
                        for (x = 0; x < 5; ++x)
                                BC[x] = state[y + x];

                        for (x = 0; x < 5; ++x)
                                state[y + x] = BC[x] ^ ((~BC[KeccakF_Mod5[x + 1]]) & BC[KeccakF_Mod5[x + 2]]);
                }

                // Iota
#if EXTRA_SMALL
                for (y = 0; y < 7; ++y) {
                        if (lfsr & 1)
                                state[0] ^= ((tKeccakLane) 1) << ((1 << y) - 1);

                        lfsr = (lfsr << 1) ^ (lfsr & 0x80 ? 0x71 : 0x00);
                }
#else
                state[0] ^= KeccakF_RoundConstants[round];
#endif

        }

        Keccak_bss();
}

static void Keccak_Init(void)
{
        memset(&Keccak_state, 0, sizeof (Keccak_state));
}

static void Keccak_Update(const uint8_t * data, unsigned int len)
{
        while (len--) {
                Keccak_state.state[Keccak_state.inqueue++] ^= *data++;

                if (Keccak_state.inqueue == cKeccakR / 8) {
                        KeccakF();
                        Keccak_state.inqueue = 0;
                }
        }
}

static void Keccak_Final(uint8_t * out, int sha3)
{
        // Padding
        Keccak_state.state[Keccak_state.inqueue] ^= sha3 ? 6 : 1;
        Keccak_state.state[cKeccakR / 8 - 1] ^= 0x80;

        KeccakF();

        // Output
        memcpy(out, Keccak_state.state, 32);
}

static void crypto_hash(unsigned char *out, const unsigned char *in, unsigned long long inlen)
{
        Keccak_Init();
        Keccak_Update(in, inlen);
        Keccak_Final(out, 0);
}
