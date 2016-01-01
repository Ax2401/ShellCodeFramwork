#pragma once

#define WSADESCRIPTION_LEN      256
#define WSASYS_STATUS_LEN       128

typedef struct WSAData {
    WORD                    wVersion;
    WORD                    wHighVersion;
#ifdef _WIN64
    unsigned short          iMaxSockets;
    unsigned short          iMaxUdpDg;
    char FAR *              lpVendorInfo;
    char                    szDescription[WSADESCRIPTION_LEN + 1];
    char                    szSystemStatus[WSASYS_STATUS_LEN + 1];
#else
    char                    szDescription[WSADESCRIPTION_LEN + 1];
    char                    szSystemStatus[WSASYS_STATUS_LEN + 1];
    unsigned short          iMaxSockets;
    unsigned short          iMaxUdpDg;
    char *              lpVendorInfo;
#endif
} WSADATA, *LPWSADATA;

typedef USHORT ADDRESS_FAMILY;

typedef struct sockaddr {
    ADDRESS_FAMILY sa_family;           // Address family.
    CHAR sa_data[14];                   // Up to 14 bytes of direct address.
} SOCKADDR, *PSOCKADDR, *LPSOCKADDR;

typedef struct addrinfo {
    int             ai_flags;
    int             ai_family;
    int             ai_socktype;
    int             ai_protocol;
    size_t          ai_addrlen;
    char            *ai_canonname;
    struct sockaddr  *ai_addr;
    struct addrinfo  *ai_next;
} ADDRINFOA, *PADDRINFOA;

typedef unsigned int SOCKET;
#define INVALID_SOCKET  (SOCKET)(~0)
#define SOCKET_ERROR            (-1)
#define SOMAXCONN       0x7fffffff

typedef unsigned long ULONG_PTR, *PULONG_PTR;
typedef ULONG_PTR DWORD_PTR, *PDWORD_PTR;
#define MAKEWORD(a, b) ((WORD)(((BYTE)(((DWORD_PTR)(a)) & 0xff)) | ((WORD)((BYTE)(((DWORD_PTR)(b)) & 0xff))) << 8))

//
// Although AF_UNSPEC is defined for backwards compatibility, using
// AF_UNSPEC for the "af" parameter when creating a socket is STRONGLY
// DISCOURAGED.  The interpretation of the "protocol" parameter
// depends on the actual address family chosen.  As environments grow
// to include more and more address families that use overlapping
// protocol values there is more and more chance of choosing an
// undesired address family when AF_UNSPEC is used.
//
#define AF_UNSPEC       0               // unspecified
#define AF_UNIX         1               // local to host (pipes, portals)
#define AF_INET         2               // internetwork: UDP, TCP, etc.
#define AF_IMPLINK      3               // arpanet imp addresses
#define AF_PUP          4               // pup protocols: e.g. BSP
#define AF_CHAOS        5               // mit CHAOS protocols
#define AF_NS           6               // XEROX NS protocols
#define AF_IPX          AF_NS           // IPX protocols: IPX, SPX, etc.
#define AF_ISO          7               // ISO protocols
#define AF_OSI          AF_ISO          // OSI is ISO
#define AF_ECMA         8               // european computer manufacturers
#define AF_DATAKIT      9               // datakit protocols
#define AF_CCITT        10              // CCITT protocols, X.25 etc
#define AF_SNA          11              // IBM SNA
#define AF_DECnet       12              // DECnet
#define AF_DLI          13              // Direct data link interface
#define AF_LAT          14              // LAT
#define AF_HYLINK       15              // NSC Hyperchannel
#define AF_APPLETALK    16              // AppleTalk
#define AF_NETBIOS      17              // NetBios-style addresses
#define AF_VOICEVIEW    18              // VoiceView
#define AF_FIREFOX      19              // Protocols from Firefox
#define AF_UNKNOWN1     20              // Somebody is using this!
#define AF_BAN          21              // Banyan
#define AF_ATM          22              // Native ATM Services
#define AF_INET6        23              // Internetwork Version 6
#define AF_CLUSTER      24              // Microsoft Wolfpack
#define AF_12844        25              // IEEE 1284.4 WG AF
#define AF_IRDA         26              // IrDA
#define AF_NETDES       28              // Network Designers OSI & gateway

#if(_WIN32_WINNT < 0x0501)
#define AF_MAX          29
#else //(_WIN32_WINNT < 0x0501)

#define AF_TCNPROCESS   29
#define AF_TCNMESSAGE   30
#define AF_ICLFXBM      31

#if(_WIN32_WINNT < 0x0600)
#define AF_MAX          32
#else //(_WIN32_WINNT < 0x0600)
#define AF_BTH          32              // Bluetooth RFCOMM/L2CAP protocols
#if(_WIN32_WINNT < 0x0601)
#define AF_MAX          33
#else //(_WIN32_WINNT < 0x0601)
#define AF_LINK         33
#define AF_MAX          34
#endif //(_WIN32_WINNT < 0x0601)
#endif //(_WIN32_WINNT < 0x0600)

#endif //(_WIN32_WINNT < 0x0501)

/*
* Types
*/
#define SOCK_STREAM     1               /* stream socket */
#define SOCK_DGRAM      2               /* datagram socket */
#define SOCK_RAW        3               /* raw-protocol interface */
#define SOCK_RDM        4               /* reliably-delivered message */
#define SOCK_SEQPACKET  5               /* sequenced packet stream */

//
// Protocols.  The IPv6 defines are specified in RFC 2292.
//
typedef enum {
#if(_WIN32_WINNT >= 0x0501)
    IPPROTO_HOPOPTS = 0,  // IPv6 Hop-by-Hop options
#endif//(_WIN32_WINNT >= 0x0501)
    IPPROTO_ICMP = 1,
    IPPROTO_IGMP = 2,
    IPPROTO_GGP = 3,
#if(_WIN32_WINNT >= 0x0501)
    IPPROTO_IPV4 = 4,
#endif//(_WIN32_WINNT >= 0x0501)
#if(_WIN32_WINNT >= 0x0600)
    IPPROTO_ST = 5,
#endif//(_WIN32_WINNT >= 0x0600)
    IPPROTO_TCP = 6,
#if(_WIN32_WINNT >= 0x0600)
    IPPROTO_CBT = 7,
    IPPROTO_EGP = 8,
    IPPROTO_IGP = 9,
#endif//(_WIN32_WINNT >= 0x0600)
    IPPROTO_PUP = 12,
    IPPROTO_UDP = 17,
    IPPROTO_IDP = 22,
#if(_WIN32_WINNT >= 0x0600)
    IPPROTO_RDP = 27,
#endif//(_WIN32_WINNT >= 0x0600)

#if(_WIN32_WINNT >= 0x0501)
    IPPROTO_IPV6 = 41, // IPv6 header
    IPPROTO_ROUTING = 43, // IPv6 Routing header
    IPPROTO_FRAGMENT = 44, // IPv6 fragmentation header
    IPPROTO_ESP = 50, // encapsulating security payload
    IPPROTO_AH = 51, // authentication header
    IPPROTO_ICMPV6 = 58, // ICMPv6
    IPPROTO_NONE = 59, // IPv6 no next header
    IPPROTO_DSTOPTS = 60, // IPv6 Destination options
#endif//(_WIN32_WINNT >= 0x0501)

    IPPROTO_ND = 77,
#if(_WIN32_WINNT >= 0x0501)
    IPPROTO_ICLFXBM = 78,
#endif//(_WIN32_WINNT >= 0x0501)
#if(_WIN32_WINNT >= 0x0600)
    IPPROTO_PIM = 103,
    IPPROTO_PGM = 113,
    IPPROTO_L2TP = 115,
    IPPROTO_SCTP = 132,
#endif//(_WIN32_WINNT >= 0x0600)
    IPPROTO_RAW = 255,

    IPPROTO_MAX = 256,
    //
    //  These are reserved for internal use by Windows.
    //
    IPPROTO_RESERVED_RAW = 257,
    IPPROTO_RESERVED_IPSEC = 258,
    IPPROTO_RESERVED_IPSECOFFLOAD = 259,
    IPPROTO_RESERVED_WNV = 260,
    IPPROTO_RESERVED_MAX = 261
} IPPROTO, *PIPROTO;

//
//  Flags used in "hints" argument to getaddrinfo()
//      - AI_ADDRCONFIG is supported starting with Vista
//      - default is AI_ADDRCONFIG ON whether the flag is set or not
//        because the performance penalty in not having ADDRCONFIG in
//        the multi-protocol stack environment is severe;
//        this defaulting may be disabled by specifying the AI_ALL flag,
//        in that case AI_ADDRCONFIG must be EXPLICITLY specified to
//        enable ADDRCONFIG behavior
//

#define AI_PASSIVE                  0x00000001  // Socket address will be used in bind() call
#define AI_CANONNAME                0x00000002  // Return canonical name in first ai_canonname
#define AI_NUMERICHOST              0x00000004  // Nodename must be a numeric address string
#define AI_NUMERICSERV              0x00000008  // Servicename must be a numeric port number

#define AI_ALL                      0x00000100  // Query both IP6 and IP4 with AI_V4MAPPED
#define AI_ADDRCONFIG               0x00000400  // Resolution only if global address configured
#define AI_V4MAPPED                 0x00000800  // On v6 failure, query v4 and convert to V4MAPPED format

#define AI_NON_AUTHORITATIVE        0x00004000  // LUP_NON_AUTHORITATIVE
#define AI_SECURE                   0x00008000  // LUP_SECURE
#define AI_RETURN_PREFERRED_NAMES   0x00010000  // LUP_RETURN_PREFERRED_NAMES

#define AI_FQDN                     0x00020000  // Return the FQDN in ai_canonname
#define AI_FILESERVER               0x00040000  // Resolving fileserver name resolution
#define AI_DISABLE_IDN_ENCODING     0x00080000  // Disable Internationalized Domain Names handling
#define AI_EXTENDED                 0x80000000      // Indicates this is extended ADDRINFOEX(2/..) struct

/*
* WinSock 2 extension -- manifest constants for shutdown()
*/
#define SD_RECEIVE      0x00
#define SD_SEND         0x01
#define SD_BOTH         0x02
