#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include "sendSSID.h"
#include <stdlib.h>


void usage()
{
    printf("syntax: pcap <interface> <ssid>\n");
    printf("sample: pcap wlan0 iptime\n");
}

typedef struct
{
    char *dev_;
} Param;

Param param = {
    .dev_ = NULL};

bool parse(Param *param, int argc, char *argv[])
{
    if (argc != 3)
    {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}

int main(int argc, char *argv[]) 
{

    if (!parse(&param, argc, argv))
        return -1;

    unsigned char *SSID = argv[2];

    Bframe  Bf;

    unsigned char *Interface = argv[1];

    Bf.radio_tap[0] = 0x00;
    Bf.radio_tap[1] = 0x00;
    Bf.radio_tap[2] = 0x20;
    Bf.radio_tap[3] = 0x00;
    Bf.radio_tap[4] = 0x00;
    Bf.radio_tap[5] = 0x00;
    Bf.radio_tap[6] = 0x00;
    Bf.radio_tap[7] = 0x00;
    Bf.radio_tap[8] = 0x00;
    Bf.radio_tap[9] = 0x00;
    Bf.radio_tap[10] = 0x00;
    Bf.radio_tap[11] = 0x00;
    Bf.radio_tap[12] = 0x00;
    Bf.radio_tap[13] = 0x00;
    Bf.radio_tap[14] = 0x00;
    Bf.radio_tap[15] = 0x00;
    Bf.radio_tap[16] = 0x00;
    Bf.radio_tap[17] = 0x00;
    Bf.radio_tap[18] = 0x00;
    Bf.radio_tap[19] = 0x00;
    Bf.radio_tap[20] = 0x00;
    Bf.radio_tap[21] = 0x00;
    Bf.radio_tap[22] = 0x00;
    Bf.radio_tap[23] = 0x00;
    Bf.radio_tap[24] = 0x00;
    Bf.radio_tap[25] = 0x00;
    Bf.radio_tap[26] = 0x00;
    Bf.radio_tap[27] = 0x00;
    Bf.radio_tap[28] = 0x00;
    Bf.radio_tap[29] = 0x00;
    Bf.radio_tap[30] = 0x00;
    Bf.radio_tap[31] = 0x00;
    Bf.radio_tap[32] = 0x00;
    Bf.radio_tap[33] = 0x00;

    Bf.Frame_Control_Field = 0x0080;
    Bf.duration = 0x0000;

    Bf.receiver_address[1] = 0xff;
    Bf.receiver_address[0] = 0xff;
    Bf.receiver_address[2] = 0xff;
    Bf.receiver_address[3] = 0xff;
    Bf.receiver_address[4] = 0xff;
    Bf.receiver_address[5] = 0xff;

    Bf.source_address[0] = 0x22;
    Bf.source_address[1] = 0x11;
    Bf.source_address[2] = 0x44;
    Bf.source_address[3] = 0x33;
    Bf.source_address[4] = 0x66;
    Bf.source_address[5] = 0x55;

    Bf.BSSID[0] = 0x22;
    Bf.BSSID[1] = 0x11;
    Bf.BSSID[2] = 0x44;
    Bf.BSSID[3] = 0x33;
    Bf.BSSID[4] = 0x66;
    Bf.BSSID[5] = 0x55;

    Bf.frag_seq_number = 0x2800;
    
    Bf.fixed_tag[0] = 0x00;
    Bf.fixed_tag[1] = 0x00;
    Bf.fixed_tag[2] = 0x00;
    Bf.fixed_tag[3] = 0x00;
    Bf.fixed_tag[4] = 0x00;
    Bf.fixed_tag[5] = 0x00;
    Bf.fixed_tag[6] = 0x00;
    Bf.fixed_tag[7] = 0x00;
    Bf.fixed_tag[8] = 0x00;
    Bf.fixed_tag[9] = 0x00;
    Bf.fixed_tag[10] = 0x00;
    Bf.fixed_tag[11] = 0x00;

    Bf.ssid_name = (u_char *)malloc(strlen(SSID) + 1);
    strcpy(Bf.ssid_name, SSID);
    //sizeof(u_char)*strlen(SSID)
    Bf.ssidpad = 0x00;
    Bf.ssid_len = strlen(Bf.ssid_name);

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap = pcap_open_live(Interface, BUFSIZ, 1, 1000, errbuf);


    if (pcap == NULL)
    {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }

    while(true){
    //printf("%d\n", sizeof(Bf));
    printf("Bf size: %d\n", sizeof(Bf));
    printf("len: %d\n", strlen(Bf.ssid_name));
    //printf("%s\n", argv[2]);
    printf("%s\n", Bf.ssid_name);
        if(pcap_sendpacket(pcap, (u_char *)&Bf, sizeof(Bf)) != 0){
            fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(pcap));
            return -1;
        }
        else{
            printf("packet send!!\n");
            //printf("%s", Bf.ssid_name);
            pcap_sendpacket(pcap, (u_char *)&Bf, sizeof(Bf) - 8 + Bf.ssid_len);
        }
    }
    free(Bf.ssid_name);
    pcap_close(pcap);
}