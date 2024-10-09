#include "pch.h"

#pragma comment(lib, "Ws2_32.lib")

#define loop(count) for(int i = 0; i < count; i++)

constexpr int MAX_DNS_SIZE = 512;
constexpr int MAX_ATTEMPTS = 3;

// Flags
constexpr int DNS_QUERY_FLAG = (0 << 15);
constexpr int DNS_RESPONSE_FLAG = (1 << 15);
constexpr int DNS_STDQUERY_FLAG = (0 << 11);
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
public:
    u_short type;
    u_short headerClass;
    u_int ttl;
    u_short len;
};

#pragma pack(pop)

string reverseIP(string ip);
void makeDNSquestion(char* buf, char* host);
int parseQuestions(char* result, FixedDNSheader* resultFdh, char* responseBuffer, char* packet);
int parseAnswers(char* result, FixedDNSheader* resultFdh, char* responseBuffer, char* packet, int bytes, string sectionName, u_short sectionCount);

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
        }
        else if (available == 0) {
            printf("timeout in %d ms\n", (int)(1000 * ((double)clock() - (double)timer) / (double)CLOCKS_PER_SEC));
            continue;
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

            if (resultFdh->id != dh->id) {
                printf("\t++ invalid reply: TXID mismatch, sent 0x%04x, received 0x%04x\n",
                    htons(dh->id),
                    htons(resultFdh->id));
                WSACleanup();
                closesocket(sock);
                delete[] packet;
                return 0;
            }

            int Rcode = htons(resultFdh->flags) & 0x000f;
            if ((Rcode) == 0) {
                printf("\tsucceeded with Rcode = %d\n", Rcode);
            }
            else {
                printf("\tfailed with Rcode = %d\n", Rcode);
                delete[] packet;
                WSACleanup();
                return 0;
            }

            int qSize = parseQuestions(result, resultFdh, responseBuffer, packet);
            if (qSize == 0) {
                return 0;
            }
            result += qSize;

            int ansSize = parseAnswers(result, resultFdh, responseBuffer, packet, bytes, "answers", htons(resultFdh->answers));
            if (ansSize == 0 && resultFdh->answers > 0) {
                return 0;
            }
            result += ansSize;

            int authSize = parseAnswers(result, resultFdh, responseBuffer, packet, bytes, "authority", htons(resultFdh->authority));
            if (authSize == 0 && resultFdh->authority > 0) {
                return 0;
            }
            result += authSize;

            int addSize = parseAnswers(result, resultFdh, responseBuffer, packet, bytes, "additional", htons(resultFdh->additional));
            if (authSize == 0 && resultFdh->authority > 0) {
                return 0;
            }
            result += authSize;

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
        }
        else {
            currSize = currEnd - hostItr;
        }
        buf[i++] = currSize;
        memcpy(buf + i, hostItr, currSize);
        i += currSize;
        hostItr = (currEnd != NULL) ? currEnd + 1 : NULL;
        buf[i] = 0;
    }
}

int parseQuestions(char* result, FixedDNSheader* resultFdh, char* responseBuffer, char* packet) {
    // Parse Questions
    char* startPtr = result;
    if (htons(resultFdh->questions > 0)) {
        printf("\t------------ [questions] ----------\n");

        loop(htons(resultFdh->questions)) {
            string questionOutput = "\t";
            bool printDot = false;

            while (true) {
                int blockSize = result[0];
                if (blockSize == 0) {
                    questionOutput += " ";
                    result++;
                    break;
                }
                if (blockSize + result - responseBuffer > MAX_DNS_SIZE) {
                    printf("\t++ Invalid record: RR value length stretches the answer beyond the packet\n");
                    delete[] packet;
                    WSACleanup();
                    return false;
                }
                if (printDot) {
                    questionOutput += ".";
                }
                else {
                    printDot = true;
                }
                result++;
                char temp[MAX_DNS_SIZE];
                memcpy(temp, result, blockSize);
                temp[blockSize] = '\0';
                questionOutput += temp;
                result += blockSize;
            }
            printf("%s", questionOutput.c_str());
            QueryHeader* qh = (QueryHeader*)result;
            printf("type %d class %d\n", htons(qh->type), htons(qh->headerClass));
            result += sizeof(QueryHeader);
        }
    }

    return result - startPtr;
}

char* jump(char* responseBuffer, char* result, char* resultHeader, int bytes, bool isDNSAnswer) {
    if (result[0] == 0) {
        return result + 1;
    }

    if ((unsigned char)result[0] >= 0xC0) {
        // Compressed, so jump
        int offset = (((unsigned char)result[0] & 0x3F) << 8) + (unsigned char)result[1];
        bool flag = false;
        if (responseBuffer + offset - resultHeader > 0 && responseBuffer + offset - resultHeader < sizeof(FixedDNSheader)) {
            if (isDNSAnswer) {
                printf("\n");
            }
            printf("\t++ Invalid record: jump into fixed DNS header\n");
            flag = true;
        }
        else if (result + 1 - responseBuffer >= bytes) {
            if (isDNSAnswer) {
                printf("\n");
            }
            printf("\t++ Invalid record: truncated jump offset\n");
            flag = true;
        }
        else if (offset > bytes) {
            if (isDNSAnswer) {
                printf("\n");
            }
            printf("\t++ Invalid record: jump beyond packet boundary\n");
            flag = true;
        }
        else if (*((unsigned char*)(responseBuffer + offset)) >= 0XC0) {
            if (isDNSAnswer) {
                printf("\n");
            }
            printf("\t++ Invalid record: jump loop\n");
            flag = true;
        }

        if (flag) {
            WSACleanup();
            exit(-1);
        }

        jump(responseBuffer, responseBuffer + offset, resultHeader, bytes, isDNSAnswer);
        return result + 2;
    }
    else {
        // uncompressed, read next word
        int blockSize = result[0];
        if (blockSize == 0) {
            return 0;
        }
        result++;

        if (result + blockSize - responseBuffer >= bytes) {
            if (isDNSAnswer) {
                printf("\n");
            }

            // Output error statement
            printf("\t++ Invalid record: truncated name\n");

            // Cleanup and exit the program
            WSACleanup();
            exit(0);
        }
        
        char temp = result[blockSize];
        result[blockSize] = '\0';
        
        printf("%s", result);

        result[blockSize] = temp;
        result += blockSize;

        if (result[0] != 0) {
            printf(".");
        }
        else {
            printf(" ");
        }

        result = jump(responseBuffer, result, resultHeader, bytes, isDNSAnswer);
        return result;
    }
}

int parseAnswers(char* result, FixedDNSheader* resultFdh, char* responseBuffer, char* packet, int bytes, string sectionName, u_short sectionCount) {
    char* startPtr = result;
    if (sectionCount > 0) {
        printf("\t------------ [%s] ------------\n", sectionName.c_str());

        loop(sectionCount) {
            if (result - responseBuffer >= bytes) {
                printf("\t++ Invalid section: not enough records\n");
                WSACleanup();
                delete packet;
                return 0;
            }

            if (result + (int)sizeof(DNSanswerHdr) - responseBuffer > bytes) {
                printf("\t++ Invalid record: truncated RR answer header\n");
                WSACleanup();
                delete packet;
                return 0;
            }

            char* resultStart = strstr(responseBuffer, packet);
            printf("\t");
            result = jump(responseBuffer, result, resultStart, bytes, false);
            DNSanswerHdr* dah = (DNSanswerHdr*)result;
            result += sizeof(DNSanswerHdr);

            int answerType = (int)htons(dah->type);

            switch (answerType) {
            case DNS_TYPE_A:
                printf("A ");
                if (result + (int)htons(dah->len) - responseBuffer > bytes) {
                    printf("\n\t++ Invalid record: RR value length stretches the answer beyond the packet\n");
                    delete packet;
                    return 0;
                }

                printf("%d.", 16 * (unsigned char(result[0]) >> 4) + (unsigned char(result[0]) & 0x0f));
                printf("%d.", 16 * (unsigned char(result[1]) >> 4) + (unsigned char(result[1]) & 0x0f));
                printf("%d.", 16 * (unsigned char(result[2]) >> 4) + (unsigned char(result[2]) & 0x0f));
                printf("%d ", 16 * (unsigned char(result[3]) >> 4) + (unsigned char(result[3]) & 0x0f));

                printf(" TTL = %d\n", htonl(dah->ttl));
                result += 4;
                break;
            case DNS_TYPE_PTR:
                printf("PTR ");
                if (result + (int)htons(dah->len) - responseBuffer > bytes) {
                    printf("\n\t++ Invalid record: RR value length stretches the answer beyond the packet\n");
                    delete packet;
                    return false;
                }
                result = jump(responseBuffer, result, resultStart, bytes, true);
                printf(" TTL = %d\n", (int)htonl(dah->ttl));
                break;
            case DNS_TYPE_NS:
                printf("NS ");
                if (result + (int)htons(dah->len) - responseBuffer > bytes) {
                    printf("\n\t++ Invalid record: RR value length stretches the answer beyond the packet\n");
                    delete packet;
                    return false;
                }
                result = jump(responseBuffer, result, resultStart, bytes, true);
                printf(" TTL = %d\n", (int)htonl(dah->ttl));
                break;
            case DNS_TYPE_CNAME:
                printf("CNAME ");
                if (result + (int)htons(dah->len) - responseBuffer > bytes) {
                    printf("\n\t++ Invalid record: RR value length stretches the answer beyond the packet\n");
                    delete packet;
                    return false;
                }
                result = jump(responseBuffer, result, resultStart, bytes, true);
                printf(" TTL = %d\n", (int)htonl(dah->ttl));
                break;
            }
        }
    }

    return result - startPtr;
}