#pragma once

#include "ShellCode.h"
#include "MyWinsock.h"

typedef int (_stdcall *WSASTARTUP)(WORD, LPWSADATA);
typedef int (_stdcall *WSAClEANUP)(void);
typedef int (_stdcall *GETADDRINFO)(const char* , const char*, const ADDRINFOA*, PADDRINFOA*);
typedef void (_stdcall *FREEADDRINFO)(struct addrinfo *);
typedef SOCKET (_stdcall *_SOCKET)(int, int, int);  // Ϊ�˷�ֹ����SOCKET�ṹ��������socket API����������SOCKETǰ���_��ʾ����һ������ָ������
typedef int (_stdcall *CLOSESOCKET)(SOCKET);
typedef int (_stdcall *BIND)(SOCKET, const struct sockaddr *, int);
typedef int (_stdcall *LISTEN)(SOCKET, int);
typedef SOCKET (_stdcall *ACCEPT)(SOCKET, struct sockaddr *, int *);
typedef int (_stdcall *SEND)(SOCKET, const char *, int, int);
typedef int (_stdcall *RECV)(SOCKET, char *, int, int);
typedef int (_stdcall *SHUTDOWN)(SOCKET, int);

class CMySampleShellCode :
    public CShellCode
{
protected:
    WSASTARTUP WSAStartup;
    WSAClEANUP WSACleanup;
    GETADDRINFO getaddrinfo;
    FREEADDRINFO freeaddrinfo;
    _SOCKET socket;
    CLOSESOCKET closesocket;
    BIND bind;
    LISTEN listen;
    ACCEPT accept;
    SEND send;
    RECV recv;
    SHUTDOWN shutdown;

public:
    CMySampleShellCode();
    ~CMySampleShellCode();

    void Run();
};

