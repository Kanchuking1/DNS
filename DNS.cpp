#include "pch.h"

#pragma comment(lib, "Ws2_32.lib")

#define loop(count) for(int i = 0; i < count; i++)

constexpr int MAX_DNS_SIZE = 512;
constexpr int MAX_ATTEMPTS = 3;

// Flags
constexpr int DNS_QUERY_FLAG = 0;
constexpr int DNS_RESPONSE_FLAG = (1 << 15);
constexpr int DNS_STDQUERY_FLAG = 0;
constexpr int DNS_AUTHORATIVE_ANSWER_FLAG = (1 << 10);
constexpr int DNS_TRUNCATED_FLAG = (1 << 9);
constexpr int DNS_RECURSION_DESIRED_FLAG = (1 << 8);
constexpr int DNS_RECURSION_AVAILABLE_FLAG = (1 << 7);

// Response codes
constexpr int DNS_OK = 0;
constexpr int DNS_FORMAT = 1;
constexpr int DNS_SERVERFAIL = 2;
constexpr int DNS_ERROR = 3;
constexpr int DNS_NOTIMPL = 4;
constexpr int DNS_REFUSED = 5;

// DNS Query types
constexpr int DNS_TYPE_A = 1;
constexpr int DNS_TYPE_NS = 2;
constexpr int DNS_TYPE_CNAME = 5;
constexpr int DNS_TYPE_PTR = 12;
constexpr int DNS_TYPE_HINFO = 13;
constexpr int DNS_TYPE_MX = 15;
constexpr int DNS_TYPE_AXFR = 252;
constexpr int DNS_TYPE_ANY = 255;

constexpr int DNS_INET = 1;
constexpr int DNS_PORT = 53;

using namespace std;

#pragma pack(push, 1)
class QueryHeader {
public:
    u_short type;
    u_short headerClass;
};

class FixedDNSheader {
public:
    u_short id;
    u_short flags;
    u_short questions;
    u_short answers;
    u_short authority;
    u_short additional;
};

class DNSanswerHdr {
    u_short type;
    u_short headerClass;
    u_int ttl;
    u_short len;
};

#pragma pack(pop)

string reverseIP(string ip);
void makeDNSquestion(char* buf, char* host);
void connectToDNS();

int main(int argc, char** argv)
{
    if (argc != 3) {
        cout << "Only 2 command line arguments allowed... <Look up string> <DNS server IP>" << endl;
        exit(-1);
    }

    string lookupString = argv[1];
    string dnsIp = argv[2];

    printf("Lookup\t: %s\n", lookupString.c_str());

    DWORD lookupIP = inet_addr(lookupString.c_str());

    bool isDomain = false;

    if (lookupIP == INADDR_NONE) {
        isDomain = true;
    }
    else {
        lookupString = reverseIP(lookupString) + ".in-addr.arpa";
    }

    int packetSize = strlen(lookupString.c_str()) + 2 + sizeof(FixedDNSheader) + sizeof(QueryHeader);
    char* packet = new char[packetSize];

    FixedDNSheader* dh = (FixedDNSheader*)packet;
    QueryHeader* qh = (QueryHeader*)(packet + packetSize - sizeof(QueryHeader));

    if (isDomain) {
        qh->type = htons(DNS_TYPE_A);
    }
    else {
        qh->type = htons(DNS_TYPE_PTR);
    }

    qh->headerClass = htons(DNS_INET);

    dh->id = htons(1);
    dh->flags = htons(DNS_QUERY_FLAG | DNS_RECURSION_DESIRED_FLAG | DNS_STDQUERY_FLAG);
    dh->questions = htons(1);
    dh->answers = htons(0);
    dh->authority = htons(0);
    dh->additional = htons(0);

    printf("Query\t: %s, type %d, TXID 0x%04d\nServer\t: %s\n", 
        lookupString.c_str(),
        htons(qh->type), 
        htons(dh->id),
        dnsIp.c_str());
    printf("********************************\n");

    makeDNSquestion((char*)(dh + 1), (char*)lookupString.c_str());

    loop(MAX_ATTEMPTS) {
        printf("Attempt %d with %d bytes... ", i, packetSize);
        clock_t timer = clock();

        WSADATA wsaData;
        WORD wVersionRequested = MAKEWORD(2, 2);
        if (WSAStartup(wVersionRequested, &wsaData) != 0) {
            WSACleanup();
            return 0;
        }

        SOCKET sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock == INVALID_SOCKET) {
            cerr << "Invalid Socket : " << WSAGetLastError() << endl;
            closesocket(sock);
            WSACleanup();
            return 0;
        }

        // Bind socket and check for errors
        struct sockaddr_in local;
        memset(&local, 0, sizeof(local));

        local.sin_family = AF_INET;
        local.sin_addr.s_addr = INADDR_ANY;
        local.sin_port = htons(0);

        if (bind(sock, (struct sockaddr*)&local, sizeof(local)) == SOCKET_ERROR) {
            closesocket(sock);
            WSACleanup();
            return 0;
        }

        struct sockaddr_in remote;
        memset(&remote, 0, sizeof(remote));
        remote.sin_family = AF_INET;
        remote.sin_addr.S_un.S_addr = inet_addr(dnsIp.c_str()); // server’s IP
        remote.sin_port = htons(DNS_PORT); // DNS port on server

        if (sendto(sock, packet, packetSize, 0, (struct sockaddr*)&remote, sizeof(remote)) == SOCKET_ERROR) {
            printf("Socket send error %d\n", WSAGetLastError());
            closesocket(sock);
            WSACleanup();
            return 0;
        }

        fd_set fd{};
        FD_ZERO(&fd);
        FD_SET(sock, &fd);
        timeval timeout{};
        timeout.tv_sec = 10;
        timeout.tv_usec = 0;
        int available = select(0, &fd, NULL, NULL, &timeout);

        if (available < 0) {
            printf("failed with %d on recv\n", WSAGetLastError());
            break;
        } else if (available == 0) {
            printf("timeout in %d ms\n", (int)(1000 * ((double)clock() - (double)timer) / (double)CLOCKS_PER_SEC));
        }

        if (available > 0) {
            char responseBuffer[MAX_DNS_SIZE];
            struct sockaddr_in response;
            int size = sizeof(response);
            int bytes = 0;

            if ((bytes = recvfrom(sock, responseBuffer, MAX_DNS_SIZE, 0, (struct sockaddr*)&response, &size)) == SOCKET_ERROR) {
                printf("Response Error %d\n", WSAGetLastError());
                WSACleanup();
                closesocket(sock);
                return 0;
            }

            int secondsSinceStart = (int)((1000 * ((double)clock() - (double)timer)) / (double)CLOCKS_PER_SEC);

            printf(" response in %d ms with %d bytes\n", secondsSinceStart, bytes);

            if (response.sin_addr.s_addr != remote.sin_addr.s_addr || response.sin_port != remote.sin_port) {
                printf("Incorrect IP and port\n");
                WSACleanup();
                delete[] packet;
                return 0;
            }

            char* result = strstr(responseBuffer, packet);

            if (result == NULL) {
                printf("Fixed DNS Header not found\n");
                WSACleanup();
                closesocket(sock);
                delete[] packet;
                return 0;
            }

            result += sizeof(FixedDNSheader);
            FixedDNSheader* resultFdh = (FixedDNSheader*)responseBuffer;

            if (bytes < sizeof(FixedDNSheader)) {
                printf("\t++ Invalid reply: packet smaller than fixed DNS Header\n");
                WSACleanup();
                closesocket(sock);
                delete[] packet;
                return 0;
            }

            printf("\tTXID 0x%04x flags 0x%04x questions %d answers %d authority %d additional %d\n",
                htons(resultFdh->id),
                htons(resultFdh->flags),
                htons(resultFdh->questions),
                htons(resultFdh->answers),
                htons(resultFdh->authority),
                htons(resultFdh->additional));

            break;
        }
    }
}

string reverseIP(string ip) {
    string res = "";

    loop(4) {
        int pos = ip.find('.');
        res = ip.substr(0, pos) + res;
        if (pos != string::npos) {
            res = "." + res;
            ip = ip.substr(pos + 1);
        }
    }

    return res;
}

void makeDNSquestion(char* buf, char* host) {
    int i = 0;
    char* hostItr = host;
    char* currEnd;
    int currSize = 0;

    while (hostItr) {
        currEnd = strchr(hostItr, '.');
        if (currEnd == NULL) {
            currSize = strlen(hostItr);
        } else {
            currSize = currEnd - hostItr;
        }
        buf[i++] = currSize;
        memcpy(buf + i, hostItr, currSize);
        i += currSize;
        hostItr = (currEnd)?currEnd + 1:NULL;
    }
}