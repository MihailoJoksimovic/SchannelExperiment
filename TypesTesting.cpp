// TypesTesting.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#define SECURITY_WIN32

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "secur32.lib")
#pragma comment(lib, "crypt32.lib")

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

static LPWSTR pSspiPackageName = new wchar_t[1024];

int main()
{
    InitStuff();

    PSecPkgInfo pkgInfo;
    SECURITY_STATUS ss;

    ss = QuerySecurityPackageInfoW(
        pSspiPackageName,
        &pkgInfo);

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

    /*
    ClientSocket = accept(listenSocket, NULL, NULL);
    if (ClientSocket == INVALID_SOCKET) {
        printf("accept failed with error: %d\n", WSAGetLastError());
        closesocket(listenSocket);
        WSACleanup();
        exit(1);
    }*/

    SCHANNEL_CRED schannelCredentials;
    CredHandle credentialsHandle;

    PCCERT_CONTEXT pCert = getServerCertificate();

    ZeroMemory(&schannelCredentials, sizeof(schannelCredentials));
    schannelCredentials.dwVersion = SCHANNEL_CRED_VERSION;
    schannelCredentials.cCreds = 1;
    schannelCredentials.paCred = &pCert;
    schannelCredentials.grbitEnabledProtocols = SP_PROT_TLS1_X;

    // Good link: https://github.com/ithewei/libhv/blob/a5b374492accbee7b3c69399415bf925691d64cb/ssl/wintls.c#L102

    

    SECURITY_STATUS ss;

    ss = AcquireCredentialsHandle(
        nullptr,
        pSspiPackageName,
        SECPKG_CRED_OUTBOUND,
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

    printf("Client connected ... Exiting ... \n");
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