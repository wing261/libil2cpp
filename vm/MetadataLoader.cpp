#include "il2cpp-config.h"
#include "MetadataLoader.h"

#include "os/File.h"
#include "os/Mutex.h"
#include "utils/MemoryMappedFile.h"
#include "utils/PathUtils.h"
#include "utils/Runtime.h"
#include "utils/Logging.h"
#include "utils/Memory.h"          // IL2CPP_MALLOC / IL2CPP_FREE
#include "utils/MetadataCipher.h"  // ChaCha20 기반 CipherMetadataHeader (사용자 정의)

#include <cstring>   // std::memcpy, std::strlen
#include <algorithm> // std::min

namespace il2cpp
{
namespace vm
{
    // global-metadata.dat 헤더 일부 복호화
    //
    // - global-metadata.dat 구조를 직접 알 필요 없이
    //   sanity(4) + version(4) 뒤에서 일정 길이만 ChaCha20 XOR
    //
    // - Editor 빌드 후처리에서 동일 규칙으로 암호화해야 함
    static void DecryptGlobalMetadataHeader(uint8_t* buffer, int64_t fileSize, const std::string& path)
    {
        // sanity(4) + version(4)는 최소 있어야 함
        if (fileSize < 8)
        {
            il2cpp::utils::Logging::Write(
                "ERROR: Metadata too small: %s (size=%lld)",
                path.c_str(), static_cast<long long>(fileSize));
            return;
        }

        const int32_t kMetadataMagic = 0xFAB11BAF;

        int32_t sanity = 0;
        std::memcpy(&sanity, buffer, sizeof(int32_t));

        if (sanity != kMetadataMagic)
        {
            il2cpp::utils::Logging::Write(
                "WARNING: Metadata sanity mismatch for %s (0x%08X), skip header decrypt.",
                path.c_str(), sanity);
            return;
        }

        // 암/복호화 시작 위치: sanity(4) + version(4) 뒤
        const size_t encOffset = 8;

        size_t maxSize = static_cast<size_t>(fileSize);
        if (maxSize <= encOffset)
        {
            il2cpp::utils::Logging::Write(
                "WARNING: Metadata file too small for header encrypt region: %s (size=%lld)",
                path.c_str(), static_cast<long long>(fileSize));
            return;
        }

        // 암/복호화 길이:
        //  - 헤더는 보통 0x150 근처이지만, 버전에 따라 다를 수 있으니
        //  - 0x200 바이트 정도만 XOR (Editor 쪽도 동일하게 맞춰야 함)
        const size_t kHeaderEncryptSize = 0x200;

        size_t encSize = std::min(kHeaderEncryptSize, maxSize - encOffset);

        il2cpp::utils::CipherMetadataHeader(buffer + encOffset, encSize);
    }

    void* MetadataLoader::LoadMetadataFile(const char* fileName)
    {
        // Unity 원본 코드와 동일한 경로 조합
        std::string resourcesDirectory = il2cpp::utils::PathUtils::Combine(
            il2cpp::utils::Runtime::GetDataDir(),
            il2cpp::utils::StringView<char>("Metadata"));

        std::string resourceFilePath = il2cpp::utils::PathUtils::Combine(
            resourcesDirectory,
            il2cpp::utils::StringView<char>(fileName, std::strlen(fileName)));

        int error = 0;
        il2cpp::os::FileHandle* handle = il2cpp::os::File::Open(
            resourceFilePath,
            kFileModeOpen,
            kFileAccessRead,
            kFileShareRead,
            kFileOptionsNone,
            &error);

        if (error != 0 || handle == NULL)
        {
            il2cpp::utils::Logging::Write(
                "ERROR: Could not open %s (error=%d)",
                resourceFilePath.c_str(), error);
            return NULL;
        }

        // 파일 크기
        int64_t fileSize = il2cpp::os::File::GetLength(handle, &error);
        if (error != 0 || fileSize <= 0)
        {
            il2cpp::utils::Logging::Write(
                "ERROR: Could not get length of %s (error=%d, size=%lld)",
                resourceFilePath.c_str(), error, static_cast<long long>(fileSize));

            il2cpp::os::File::Close(handle, &error);
            return NULL;
        }

        // 1) read-only mmap (원래 Unity 구현)
        void* mapped = il2cpp::utils::MemoryMappedFile::Map(handle);

        il2cpp::os::File::Close(handle, &error);
        if (error != 0 || mapped == NULL)
        {
            if (mapped != NULL)
                il2cpp::utils::MemoryMappedFile::Unmap(mapped);

            il2cpp::utils::Logging::Write(
                "ERROR: Failed to map metadata file %s (error=%d)",
                resourceFilePath.c_str(), error);
            return NULL;
        }

        // 2) mmap 데이터를 Heap 버퍼로 복사 (여기에만 ChaCha20 XOR 수행)
        uint8_t* buffer = static_cast<uint8_t*>(
            IL2CPP_MALLOC(static_cast<size_t>(fileSize)));

        if (buffer == NULL)
        {
            il2cpp::utils::Logging::Write(
                "ERROR: Failed to allocate %lld bytes for metadata %s",
                static_cast<long long>(fileSize), resourceFilePath.c_str());

            il2cpp::utils::MemoryMappedFile::Unmap(mapped);
            return NULL;
        }

        std::memcpy(buffer, mapped, static_cast<size_t>(fileSize));

        // mmap 해제 (이후 buffer만 사용)
        il2cpp::utils::MemoryMappedFile::Unmap(mapped);

        // 3) global-metadata.dat 인 경우에만 헤더 복호화
        if (fileName != NULL &&
            std::strcmp(fileName, "global-metadata.dat") == 0)
        {
            DecryptGlobalMetadataHeader(buffer, fileSize, resourceFilePath);
        }

        return buffer;
    }

    void MetadataLoader::UnloadMetadataFile(void* fileBuffer)
    {
        // 이제는 mmap이 아니라 Heap 버퍼이므로 Unmap이 아니라 FREE
        if (fileBuffer != NULL)
            IL2CPP_FREE(fileBuffer);
    }

} // namespace vm
} // namespace il2cpp
