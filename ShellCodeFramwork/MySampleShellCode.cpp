#include "stdafx.h"
#include "MySampleShellCode.h"

CMySampleShellCode::CMySampleShellCode()
{
    char szWs2_32Dll[] = { 'W', 's', '2', '_', '3', '2', '.', 'd', 'l', 'l', 0 };

    char szWSAStartup[] = { 'W', 'S', 'A', 'S', 't', 'a', 'r', 't', 'u', 'p', 0 };
    char szWSACleanup[] = { 'W', 'S', 'A', 'C', 'l', 'e', 'a', 'n', 'u', 'p', 0 };
    char szGetaddrinfo[] = { 'g', 'e', 't', 'a', 'd', 'd', 'r', 'i', 'n', 'f', 'o', 0 };
    char szFreeaddrinfo[] = { 'f', 'r', 'e', 'e', 'a', 'd', 'd', 'r', 'i', 'n', 'f', 'o', 0 };
    char szSocket[] = { 's', 'o', 'c', 'k', 'e', 't', 0 };
    char szClosesocket[] = { 'c', 'l', 'o', 's', 'e', 's', 'o', 'c', 'k', 'e', 't', 0 };
    char szBind[] = { 'b', 'i', 'n', 'd', 0 };
    char szListen[] = { 'l', 'i', 's', 't', 'e', 'n', 0 };
    char szAccept[] = { 'a', 'c', 'c', 'e', 'p', 't', 0 };
    char szSend[] = { 's', 'e', 'n', 'd', 0 };
    char szRecv[] = { 'r', 'e', 'c', 'v', 0 };
    char szShutdown[] = { 's', 'h', 'u', 't', 'd', 'o', 'w', 'n', 0 };

    WSAStartup = (WSASTARTUP)GetAPIAddress(szWs2_32Dll, szWSAStartup);
    WSACleanup = (WSAClEANUP)GetAPIAddress(szWs2_32Dll, szWSACleanup);
    getaddrinfo = (GETADDRINFO)GetAPIAddress(szWs2_32Dll, szGetaddrinfo);
    freeaddrinfo = (FREEADDRINFO)GetAPIAddress(szWs2_32Dll, szFreeaddrinfo);
    socket = (_SOCKET)GetAPIAddress(szWs2_32Dll, szSocket);
    closesocket = (CLOSESOCKET)GetAPIAddress(szWs2_32Dll, szClosesocket);
    bind = (BIND)GetAPIAddress(szWs2_32Dll, szBind);
    listen = (LISTEN)GetAPIAddress(szWs2_32Dll, szListen);
    accept = (ACCEPT)GetAPIAddress(szWs2_32Dll, szAccept);
    send = (SEND)GetAPIAddress(szWs2_32Dll, szSend);
    recv = (RECV)GetAPIAddress(szWs2_32Dll, szRecv);
    shutdown = (SHUTDOWN)GetAPIAddress(szWs2_32Dll, szShutdown);
}

CMySampleShellCode::~CMySampleShellCode()
{
}

void CMySampleShellCode::Run()
{
    int iResult = 0;
    WSADATA WsaData;
    struct addrinfo *result = nullptr, *ptr = nullptr, hints;
    char szDeafultPort[] = { '5', '5', '5', '5', 0 };
    SOCKET ListenSocket = INVALID_SOCKET;
    SOCKET ClientSocket = INVALID_SOCKET;

    bool bWsaStartupOk = false;
    bool bGetAddrInfoOk = false;

    const int DEFAULT_BUFLEN = 512;
    char recvbuf[DEFAULT_BUFLEN];
    int iSendResult;
    int recvbuflen = DEFAULT_BUFLEN;

    iResult = WSAStartup(MAKEWORD(2, 2), &WsaData);
    if (iResult != 0)
    {
        goto _exit;
    }
    else
    {
        bWsaStartupOk = true;
    }

    memset(&hints, 0, sizeof(addrinfo));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;

    iResult = getaddrinfo(nullptr, szDeafultPort, &hints, &result);
    if (iResult != 0)
    {
        goto _exit;
    }
    else
    {
        bGetAddrInfoOk = true;
    }

    ListenSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (ListenSocket == INVALID_SOCKET)
    {
        goto _exit;
    }

    iResult = bind(ListenSocket, result->ai_addr, (int)result->ai_addrlen);
    if (iResult != 0)
    {
        goto _exit;
    }

    if (listen(ListenSocket, SOMAXCONN) == SOCKET_ERROR)
    {
        goto _exit;
    }

    while (1)
    {
        ClientSocket = accept(ListenSocket, nullptr, nullptr);
        if (ClientSocket == INVALID_SOCKET)
        {
            break;
        }

        do {
            iResult = recv(ClientSocket, recvbuf, recvbuflen, 0);
            if (iResult > 0) {
                iSendResult = send(ClientSocket, recvbuf, iResult, 0);
                if (iSendResult == SOCKET_ERROR) {
                    break;
                }
            }
            else
            {
                break;
            }
        } while (iResult > 0);

        shutdown(ClientSocket, SD_SEND);
        closesocket(ClientSocket);
    }

_exit:
    if (bGetAddrInfoOk)
    {
        freeaddrinfo(result);
    }
    if (ListenSocket != INVALID_SOCKET)
    {
        closesocket(ListenSocket);
    }
    if (bWsaStartupOk)
    {
        WSACleanup();
    }

    return;
}
