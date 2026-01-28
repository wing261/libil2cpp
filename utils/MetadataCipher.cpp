#include "MetadataCipher.h"

#include <algorithm> // std::min

namespace il2cpp
{
namespace utils
{
    // ==== 공통 유틸 ====

    static inline uint32_t RotL32(uint32_t v, int c)
    {
        return (v << c) | (v >> (32 - c));
    }

    static inline void QuarterRound(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d)
    {
        a += b; d ^= a; d = RotL32(d, 16);
        c += d; b ^= c; b = RotL32(b, 12);
        a += b; d ^= a; d = RotL32(d, 8);
        c += d; b ^= c; b = RotL32(b, 7);
    }

    static inline uint32_t LoadLE(const uint8_t* p)
    {
        return
            (uint32_t)p[0]       |
            (uint32_t)p[1] << 8  |
            (uint32_t)p[2] << 16 |
            (uint32_t)p[3] << 24;
    }

    static inline void StoreLE(uint32_t v, uint8_t* p)
    {
        p[0] = (uint8_t)(v & 0xFF);
        p[1] = (uint8_t)((v >> 8) & 0xFF);
        p[2] = (uint8_t)((v >> 16) & 0xFF);
        p[3] = (uint8_t)((v >> 24) & 0xFF);
    }

    // RFC 8439 ChaCha20 block: 64바이트 keystream 생성
    static void ChaCha20Block(
        uint8_t output[64],
        const uint8_t key[32],
        uint32_t counter,
        const uint8_t nonce[12])
    {
        static const uint32_t constants[4] =
        {
            0x61707865, // "expa"
            0x3320646e, // "nd 3"
            0x79622d32, // "2-by"
            0x6b206574  // "te k"
        };

        uint32_t state[16];

        state[0] = constants[0];
        state[1] = constants[1];
        state[2] = constants[2];
        state[3] = constants[3];

        // key (32 bytes → 8 words)
        state[4]  = LoadLE(key + 0);
        state[5]  = LoadLE(key + 4);
        state[6]  = LoadLE(key + 8);
        state[7]  = LoadLE(key + 12);
        state[8]  = LoadLE(key + 16);
        state[9]  = LoadLE(key + 20);
        state[10] = LoadLE(key + 24);
        state[11] = LoadLE(key + 28);

        // counter (32bit) + nonce (96bit)
        state[12] = counter;
        state[13] = LoadLE(nonce + 0);
        state[14] = LoadLE(nonce + 4);
        state[15] = LoadLE(nonce + 8);

        uint32_t working[16];
        for (int i = 0; i < 16; ++i)
            working[i] = state[i];

        // 20 rounds (10 double rounds)
        for (int i = 0; i < 10; ++i)
        {
            // column
            QuarterRound(working[0], working[4], working[8],  working[12]);
            QuarterRound(working[1], working[5], working[9],  working[13]);
            QuarterRound(working[2], working[6], working[10], working[14]);
            QuarterRound(working[3], working[7], working[11], working[15]);

            // diagonal
            QuarterRound(working[0], working[5], working[10], working[15]);
            QuarterRound(working[1], working[6], working[11], working[12]);
            QuarterRound(working[2], working[7], working[8],  working[13]);
            QuarterRound(working[3], working[4], working[9],  working[14]);
        }

        for (int i = 0; i < 16; ++i)
            working[i] += state[i];

        // 16 words → 64 bytes
        for (int i = 0; i < 16; ++i)
            StoreLE(working[i], output + 4 * i);
    }

    // ==== key / nonce (Editor C#과 반드시 동일해야 함) ====

    static const uint8_t kKey[32] =
    {
        0x83, 0x45, 0x12, 0xA9,
        0xC1, 0x6B, 0x39, 0x5F,
        0x77, 0x2D, 0x90, 0xE4,
        0xB8, 0xFA, 0x01, 0x3C,
        0x65, 0x9A, 0xDE, 0x07,
        0x44, 0x21, 0x58, 0xB3,
        0xCF, 0xEE, 0x72, 0x19,
        0x0D, 0xA4, 0x53, 0xF6
    };

    static const uint8_t kNonce[12] =
    {
        0x10, 0x32, 0x54, 0x76,
        0x98, 0xBA, 0xDC, 0xFE,
        0x01, 0x23, 0x45, 0x67
    };

    // ==== 헤더 구간에 ChaCha20 keystream XOR ====

    void CipherMetadataHeader(uint8_t* data, size_t size)
    {
        if (data == NULL || size == 0)
            return;

        uint32_t counter = 0; // Editor와 동일 시작 값
        size_t offset = 0;
        uint8_t block[64];

        while (offset < size)
        {
            ChaCha20Block(block, kKey, counter, kNonce);

            size_t bytesThisRound = std::min<size_t>(64, size - offset);
            for (size_t i = 0; i < bytesThisRound; ++i)
                data[offset + i] ^= block[i];

            ++counter;
            offset += bytesThisRound;
        }
    }

} // namespace utils
} // namespace il2cpp
