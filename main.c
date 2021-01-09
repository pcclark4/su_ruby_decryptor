#include <stdio.h>
#include <memory.h>
#include <stdlib.h>
#include <stdint.h>

#include <windows.h>
#include <wincrypt.h>

void log_win32_error(const char *funcName);

int main(int argc, char *argv[]) {
    if (argc < 2) {
        puts("No file name specified\n");
        goto retn;
    }

    uint8_t *initializationVector = 0;
    uint8_t *buffer = 0;

    size_t numConverted;
    size_t wideStrSize = 256;
    wchar_t *wideStr = malloc(wideStrSize);
    mbstowcs_s(&numConverted, wideStr, wideStrSize / 2, argv[1], wideStrSize);
    FILE *stream;
    errno_t openResult = _wfopen_s(
            &stream,
            wideStr,
            L"rb"
    );

    if (openResult != 0) {
        printf("It didn't work :(\n");
        return 1;
    }

    fseek(stream, 0, SEEK_END);
    long filePos = ftell(stream);
    rewind(stream);

    if (filePos <= 6) {
        buffer = 0;
        fclose(stream);
    } else {
        uint8_t *v14 = malloc(6);
        memset(v14, 0, 6);
        buffer = v14;
        fread(buffer, 1, 6, stream);
        filePos -= 6;

        uint8_t *v16 = malloc(16);
        initializationVector = v16;
        memset(v16, 0, 16);
        fread(initializationVector, 1, 16, stream);
        filePos -= 16;

    }

    BYTE *encryptedRuby = malloc(filePos);;
    memset(encryptedRuby, 0, filePos);
    fread(encryptedRuby, 1, filePos, stream);
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

    if (!CryptSetKeyParam(hKey, KP_IV, initializationVector, 0)) {
        log_win32_error("CryptSetKeyParam(KP_IV)");
        goto release_key;
    }

    if (!CryptDecrypt(hKey, 0, TRUE, 0, encryptedRuby, &filePos)) {
        log_win32_error("CryptDecrypt");
        goto release_key;
    }

release_key:
    if (!CryptDestroyKey(hKey)) {
        log_win32_error("CryptDestroyKey");
    }

release_context:
    if (!CryptReleaseContext(hProv, 0)) {
        log_win32_error("CryptReleaseContext");
    }

end:
    puts(encryptedRuby);
    free(buffer);
    free(initializationVector);
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
        printf("%s failed with error: ", funcName);
        puts(lpBuffer);
    } else {
        printf("%s failed with error: %lu\n", funcName, messageId);
    }
}
