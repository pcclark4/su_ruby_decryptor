#include <stdio.h>
#include <stdint.h>

#include <windows.h>

void log_win32_error(const char *funcName);

int main(int argc, char *argv[]) {
    if (argc < 2) {
        puts("No file name specified\n");
        goto retn;
    }

    FILE *stream;
    errno_t openResult = fopen_s(&stream, argv[1], "rb");
    if (openResult != 0) {
        char errBuffer[128];
        if (!strerror_s(errBuffer, 128, openResult)) {
            puts(errBuffer);
        } else {
            puts("Failed to open file\n");
        }
        goto retn;
    }

    if (fseek(stream, 0, SEEK_END) != 0) {
        puts("Failed to seek to EOF\n");
        fclose(stream);
        goto retn;
    }

    long fileSize = ftell(stream);

    if (fileSize < 0) {
        puts("Failed to read current file position\n");
        fclose(stream);
        goto retn;
    }

    if (fileSize <= 22) {
        puts("Your file is much too small\n");
        fclose(stream);
        goto retn;
    }

    rewind(stream);

    size_t rbsVerSize = 6;
    char * const rbsVer = malloc(rbsVerSize + 1); // Room for null term char
    memset(rbsVer, 0, rbsVerSize + 1);
    size_t numRead = fread_s(rbsVer, rbsVerSize, 1, rbsVerSize, stream);
    if (numRead < rbsVerSize) {
        puts("Failed to read RBS version\n");
        fclose(stream);
        goto retn;
    }
    fileSize -= rbsVerSize;

    if (strcmp(rbsVer, "RBS2.0") != 0) {
        printf("RBS version %s not supported\n", rbsVer);
        fclose(stream);
        goto retn;
    }

    size_t initVectorSize = 16;
    uint8_t * const initVector = malloc(initVectorSize);
    memset(initVector, 0, initVectorSize);
    numRead = fread_s(initVector, initVectorSize, 1, initVectorSize, stream);
    if (numRead < initVectorSize) {
        puts("Failed to read initialization vector");
        fclose(stream);
        goto retn;
    }
    fileSize -= initVectorSize;

    BYTE * const encryptedRuby = malloc(fileSize + 1); // Room for null term char
    memset(encryptedRuby, 0, fileSize + 1);
    numRead = fread_s(encryptedRuby, fileSize, 1, fileSize, stream);
    if (numRead < fileSize) {
        puts("Failed to read encrypted Ruby code");
        fclose(stream);
        goto retn;
    }

    fclose(stream);

    HCRYPTPROV hProv;
    if (!CryptAcquireContextW(&hProv, NULL, MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES,
                              CRYPT_NEWKEYSET | CRYPT_VERIFYCONTEXT)) {
        log_win32_error("CryptAcquireContextW");
        goto end;
    }

    BYTE keyBlob[44] = {
            0x08, 0x02, 0x0, 0x0, 0x10, 0x66, 0x0, 0x0,
            0x20, 0x0, 0x0, 0x0,
            0x39, 0x6e, 0x67, 0x0ef, 0x0f4, 0x95, 0x12, 0x8c,
            0x39, 0x21, 0x4a, 0x0b4, 0x0f5, 0x0ba, 0x0ec, 0x0f8,
            0x0e2, 0x91, 0x0ec, 0x78, 0x0a3, 0x0e8, 0x2b, 0x8b,
            0x94, 0x23, 0x0d, 0x0a, 0x84, 0x2e, 0x0ff, 0x18
    };

    HCRYPTKEY hKey;
    if (!CryptImportKey(hProv, keyBlob, 44, 0, 0, &hKey)) {
        log_win32_error("CryptImportKey");
        goto release_context;
    }

    DWORD mode = CRYPT_MODE_CBC;
    if (!CryptSetKeyParam(hKey, KP_MODE, (const BYTE *) &mode, 0)) {
        log_win32_error("CryptSetKeyParam(KP_MODE)");
        goto release_key;
    }

    if (!CryptSetKeyParam(hKey, KP_IV, initVector, 0)) {
        log_win32_error("CryptSetKeyParam(KP_IV)");
        goto release_key;
    }

    if (!CryptDecrypt(hKey, 0, TRUE, 0, encryptedRuby, &fileSize)) {
        log_win32_error("CryptDecrypt");
        goto release_key;
    }

    puts(encryptedRuby);

release_key:
    if (!CryptDestroyKey(hKey)) {
        log_win32_error("CryptDestroyKey");
    }

release_context:
    if (!CryptReleaseContext(hProv, 0)) {
        log_win32_error("CryptReleaseContext");
    }

end:
    free(initVector);
    free(encryptedRuby);

retn:
    return 0;
}

void log_win32_error(const char *funcName) {
    DWORD messageId = GetLastError();
    LPSTR lpBuffer;
    if (FormatMessageA(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
            NULL,
            messageId,
            0,
            &lpBuffer,
            0,
            NULL
    )) {
        printf("%s failed with error: %s", funcName, lpBuffer);
    } else {
        printf("%s failed with error: %lu\n", funcName, messageId);
    }
}
