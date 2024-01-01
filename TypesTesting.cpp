// TypesTesting.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#define SECURITY_WIN32

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "secur32.lib")
#pragma comment(lib, "crypt32.lib")

#define SEC_SUCCESS(Status) ((Status) >= 0)

#include <windows.h>
#include <winsock.h>

#include <sspi.h>
#include <schannel.h>

#include <iostream>

#include <stdio.h>
#include <stdlib.h>

//  SspiExample.h


void InitStuff();
void StartServer();
PCCERT_CONTEXT getServerCertificate();

void PrintHexDump(DWORD length, PBYTE buffer);

static LPWSTR pSspiPackageName = new wchar_t[1024];

static ULONG g_cbMaxMessage = 0;
static PBYTE g_pInBuf = NULL;
static PBYTE g_pOutBuf = NULL;

int main()
{
    InitStuff();

    PSecPkgInfo pkgInfo;
    SECURITY_STATUS ss;

    ss = QuerySecurityPackageInfoW(
        pSspiPackageName,
        &pkgInfo);

    g_cbMaxMessage = pkgInfo->cbMaxToken;

    g_pOutBuf = (PBYTE)malloc(g_cbMaxMessage);

    StartServer();

}

void InitStuff()
{
    WSADATA wsaData;

    if (WSAStartup(MAKEWORD(2, 2), &wsaData))
    {
        fprintf(stderr, "Could not initialize winsock: \n");
        exit(1);
    }

    wcscpy_s(pSspiPackageName, 1024, L"Microsoft Unified Security Protocol Provider");
}

void StartServer()
{
    SOCKET listenSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (listenSocket == INVALID_SOCKET) {
        std::cerr << "Socket creation failed" << std::endl;
        exit(1);
    }

    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(12121); // HTTPS port
    serverAddr.sin_addr.s_addr = INADDR_ANY;

    if (bind(listenSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        std::cerr << "Bind failed" << std::endl;
        closesocket(listenSocket);
        WSACleanup();
        exit(1);
    }

    if (listen(listenSocket, SOMAXCONN) == SOCKET_ERROR) {
        std::cerr << "Listen failed" << std::endl;
        closesocket(listenSocket);
        WSACleanup();
        exit(1);
    }

    SOCKET ClientSocket = INVALID_SOCKET;

    

    SCHANNEL_CRED schannelCredentials;
    CredHandle credentialsHandle;

    PCCERT_CONTEXT pCert = getServerCertificate();

    ZeroMemory(&schannelCredentials, sizeof(schannelCredentials));
    schannelCredentials.dwVersion = SCHANNEL_CRED_VERSION;
    schannelCredentials.cCreds = 1;
    schannelCredentials.paCred = &pCert;
    schannelCredentials.grbitEnabledProtocols = SP_PROT_TLS1_X;

    // Good link: https://github.com/ithewei/libhv/blob/a5b374492accbee7b3c69399415bf925691d64cb/ssl/wintls.c#L102

    SEC_E_INTERNAL_ERROR;


    SECURITY_STATUS ss;

    ss = AcquireCredentialsHandle(
        nullptr,
        pSspiPackageName,
        SECPKG_CRED_INBOUND,
        nullptr,
        &schannelCredentials,
        nullptr,
        nullptr,
        &credentialsHandle,
        nullptr
    );

    if (ss != SEC_E_OK) {
        std::cerr << "Acquiring creds handle failed!" << std::endl;
        fprintf(stderr, "Acquiring creds handle failed with error: '0x%08x' \n", ss);
        closesocket(listenSocket);
        WSACleanup();
        exit(1);
    }

    ClientSocket = accept(listenSocket, NULL, NULL);
    if (ClientSocket == INVALID_SOCKET) {
        printf("accept failed with error: %d\n", WSAGetLastError());
        closesocket(listenSocket);
        WSACleanup();
        exit(1);
    }

    printf("Client connected ... Exiting ... \n");

    char buffer[1024];

    int bytesRead = 0;

    bytesRead = recv(ClientSocket, buffer, 1024, 0);

    PrintHexDump(bytesRead, (byte*)buffer);

    printf("Bytes read: %d\n", bytesRead);


    SecBufferDesc inputSecBufferDesc;
    SecBufferDesc outputSecBufferDesc;

    ULONG contextAttributes = 0;


    SecBuffer inputSecBuffers[2];

    SecBuffer         outputSecBuffer;

    DWORD cbOut = g_cbMaxMessage;

    inputSecBuffers[0].BufferType = SECBUFFER_TOKEN;
    inputSecBuffers[0].cbBuffer = bytesRead;
    inputSecBuffers[0].pvBuffer = buffer;

    inputSecBuffers[1].BufferType = SECBUFFER_EMPTY;
    inputSecBuffers[1].cbBuffer = 0;
    inputSecBuffers[1].pvBuffer = nullptr;

    inputSecBufferDesc.ulVersion = SECBUFFER_VERSION;
    inputSecBufferDesc.cBuffers = 2;
    inputSecBufferDesc.pBuffers = inputSecBuffers;

    outputSecBufferDesc.ulVersion = SECBUFFER_VERSION;
    outputSecBufferDesc.cBuffers = 1;
    outputSecBufferDesc.pBuffers = &outputSecBuffer;

    outputSecBuffer.cbBuffer = g_cbMaxMessage;
    outputSecBuffer.BufferType = SECBUFFER_TOKEN;
    outputSecBuffer.pvBuffer = g_pOutBuf;
       
    //outputSecBufferDesc.ulVersion = SECBUFFER_VERSION;
    //outputSecBufferDesc.cBuffers = 0;

    //char outputBuffer[1024];

    //outputSecBufferDesc.pBuffers = &outputBuffer;;

    CtxtHandle context;

    SECURITY_STATUS status;

    status = AcceptSecurityContext(
        &credentialsHandle, // phCredential
        nullptr, // phContext
        &inputSecBufferDesc, // pInput
        0, // fContextReq
        SECURITY_NATIVE_DREP, // TargetDataRep
        &context, // phNewContext
        &outputSecBufferDesc,
        &contextAttributes,
        nullptr
    );

    if (!SEC_SUCCESS(status))
    {
        fprintf(stderr, "AcceptSecurityContext failed: 0x%08x\n", status);
        exit(1);
    }

    fprintf(stderr, "AcceptSecurityContext succeeded: 0x%08x\n", status);

    if (status == SEC_I_CONTINUE_NEEDED) {
        // TODO: Proceed from here. Read more at https://learn.microsoft.com/en-us/windows/win32/secauthn/acceptsecuritycontext--schannel#return-value
        // Basically we need to send token to client then call back AcceptSecurityContext again bla bla bla :)
        //fprintf(stderr, "Need to continue but not implemented ...\n", status);

        //exit(1);
    }

    cbOut = outputSecBuffer.cbBuffer;

    printf("Token buffer generated (%lu bytes):\n", cbOut);

    //PrintHexDump(outputSecBuffer.cbBuffer, (PBYTE)outputSecBuffer.pvBuffer);

    int bytesSent = send(ClientSocket, (const char*)(g_pOutBuf),cbOut, 0);

    fprintf(stderr, "Bytes sent: %lu\n", bytesSent);


    // Read back from client

    bytesRead = recv(ClientSocket, buffer, 1024, 0);

    PrintHexDump(bytesRead, (byte*)buffer);

    printf("Bytes read: %d\n", bytesRead);


    status = AcceptSecurityContext(
        &credentialsHandle, // phCredential
        &context, // phContext
        &inputSecBufferDesc, // pInput
        0, // fContextReq
        SECURITY_NATIVE_DREP, // TargetDataRep
        nullptr, // phNewContext
        &outputSecBufferDesc,
        &contextAttributes,
        nullptr
    );

    if (!SEC_SUCCESS(status))
    {
        fprintf(stderr, "AcceptSecurityContext failed: 0x%08x\n", status);
        exit(1);
    }

    fprintf(stderr, "AcceptSecurityContext succeeded: 0x%08x\n", status);

    send(ClientSocket, "Mixa", _countof("Mixa"), 0);

    SecPkgContext_StreamSizes streamSizes;

    status = QueryContextAttributes(&context, SECPKG_ATTR_STREAM_SIZES, &streamSizes);

    if (!SEC_SUCCESS(status))
    {
        fprintf(stderr, "QueryContextAttributes failed: 0x%08x\n", status);
        exit(1);
    }

    // Prepare encrypted message
    SecBufferDesc encryptedMessageSecBufferDesc;

    encryptedMessageSecBufferDesc.cBuffers = 4;
    encryptedMessageSecBufferDesc.ulVersion = SECBUFFER_VERSION;

    SecBuffer encryptedMessageSecBuffers[4];

    encryptedMessageSecBufferDesc.pBuffers = encryptedMessageSecBuffers;

    PBYTE encryptedMessageOutBuffer = NULL;
    encryptedMessageOutBuffer = (PBYTE)malloc(g_cbMaxMessage);

    encryptedMessageSecBuffers[0].BufferType = SECBUFFER_STREAM_HEADER;
    encryptedMessageSecBuffers[0].cbBuffer = streamSizes.cbHeader;
    encryptedMessageSecBuffers[0].pvBuffer = encryptedMessageOutBuffer;


    encryptedMessageSecBuffers[1].BufferType = SECBUFFER_DATA;
    encryptedMessageSecBuffers[1].cbBuffer = 4;
    encryptedMessageSecBuffers[1].pvBuffer = (void*)(encryptedMessageOutBuffer + streamSizes.cbHeader);

    encryptedMessageSecBuffers[2].BufferType = SECBUFFER_STREAM_TRAILER;
    encryptedMessageSecBuffers[2].cbBuffer = streamSizes.cbTrailer;
    encryptedMessageSecBuffers[2].pvBuffer = (void*)(encryptedMessageOutBuffer + streamSizes.cbHeader + 4);

    encryptedMessageSecBuffers[3].BufferType = SECBUFFER_EMPTY;
    encryptedMessageSecBuffers[3].cbBuffer = 0;
    encryptedMessageSecBuffers[3].pvBuffer = nullptr;

    void* destination = encryptedMessageOutBuffer;

    strcpy_s((char*)(encryptedMessageSecBuffers[1].pvBuffer), 5, "Mixa");

    status = EncryptMessage(&context, 0, &encryptedMessageSecBufferDesc, 0);

    if (!SEC_SUCCESS(status))
    {
        fprintf(stderr, "EncryptMessage failed: 0x%08x\n", status);
        exit(1);
    }

    int msgLength = encryptedMessageSecBuffers[0].cbBuffer + encryptedMessageSecBuffers[1].cbBuffer + encryptedMessageSecBuffers[2].cbBuffer;

    send(ClientSocket, (const char*)encryptedMessageOutBuffer, msgLength, 0);
}

PCCERT_CONTEXT getServerCertificate()
{
    HCERTSTORE hMyCertStore = NULL;
    PCCERT_CONTEXT aCertContext = NULL;

    //-------------------------------------------------------
    // Open the My store, also called the personal store.
    // This call to CertOpenStore opens the Local_Machine My 
    // store as opposed to the Current_User's My store.

    hMyCertStore = CertOpenStore(CERT_STORE_PROV_SYSTEM,
        X509_ASN_ENCODING,
        0,
        CERT_SYSTEM_STORE_CURRENT_USER,
        L"MY");

    hMyCertStore = CertOpenSystemStore(0, L"MY");

    DWORD dwCertCount = 0;

    if (hMyCertStore == NULL)
    {
        printf("Error opening MY store for server.\n");
        goto cleanup;
    }
    //-------------------------------------------------------
    // Search for a certificate with some specified
    // string in it. This example attempts to find
    // a certificate with the string "example server" in
    // its subject string. Substitute an appropriate string
    // to find a certificate for a specific user.

    aCertContext = CertFindCertificateInStore(hMyCertStore,
        X509_ASN_ENCODING,
        0,
        CERT_FIND_ANY,
        "TlsPlay", // use appropriate subject name
        NULL
    );

    if (aCertContext == NULL)
    {
        printf("Error retrieving server certificate.");
        goto cleanup;
    }
cleanup:
    if (hMyCertStore)
    {
        CertCloseStore(hMyCertStore, 0);
    }
    return aCertContext;
}

void PrintHexDump(DWORD length, PBYTE buffer)
{
    DWORD i, count, index;
    CHAR rgbDigits[] = "0123456789abcdef";
    CHAR rgbLine[100];
    char cbLine;

    for (index = 0; length;
        length -= count, buffer += count, index += count)
    {
        count = (length > 16) ? 16 : length;

        sprintf_s(rgbLine, 100, "%4.4x  ", index);
        cbLine = 6;

        for (i = 0; i < count; i++)
        {
            rgbLine[cbLine++] = rgbDigits[buffer[i] >> 4];
            rgbLine[cbLine++] = rgbDigits[buffer[i] & 0x0f];
            if (i == 7)
            {
                rgbLine[cbLine++] = ':';
            }
            else
            {
                rgbLine[cbLine++] = ' ';
            }
        }
        for (; i < 16; i++)
        {
            rgbLine[cbLine++] = ' ';
            rgbLine[cbLine++] = ' ';
            rgbLine[cbLine++] = ' ';
        }

        rgbLine[cbLine++] = ' ';

        for (i = 0; i < count; i++)
        {
            if (buffer[i] < 32 || buffer[i] > 126)
            {
                rgbLine[cbLine++] = '.';
            }
            else
            {
                rgbLine[cbLine++] = buffer[i];
            }
        }

        rgbLine[cbLine++] = 0;
        printf("%s\n", rgbLine);
    }
}  // end PrintHexDump