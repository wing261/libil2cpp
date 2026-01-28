#pragma once

#include <cstdint>
#include <cstddef>

namespace il2cpp
{
namespace utils
{
    // global-metadata.dat 헤더 일부를 ChaCha20 스트림 XOR로 암·복호화
    void CipherMetadataHeader(uint8_t* data, size_t size);
}
}
