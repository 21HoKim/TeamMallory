#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include "information.h"

void usage()
{
    printf("syntax: pcap <interface>\n");
    printf("sample: pcap wlan0\n");
}

typedef struct
{
    char *dev_;
} Param;

Param param = {
    .dev_ = NULL};

bool parse(Param *param, int argc, char *argv[])
{
    if (argc != 2)
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

    unsigned char *Interface = argv[1];
    //unsigned char *AP_MAC = argv[2]; //AP Mac Address

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap = pcap_open_live(Interface, BUFSIZ, 1, 1000, errbuf);

    if (pcap == NULL)
    {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }

    while(true){
      struct pcap_pkthdr* header;
		  const u_char* packet;
		  int res = pcap_next_ex(pcap, &header, &packet);
		  if (res == 0) continue;
		  if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
              printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			  break;
		  }

        radio *rad = (radio *)packet;
        prob *prb = (prob *)(packet + (rad->hdr_len));
        ssid *sid = (ssid *)(packet + (rad->hdr_len+sizeof(prob)) + 12);

        printf("source address : ");

        for(int i = 0 ; i < MAC_ADDR_LEN ; i++){
            printf("%02x", prb->mac_src[i]);
            if(i < MAC_ADDR_LEN - 1){
                printf(":");
            }
        }
        printf("\t");

        //(prob *)(packet + 48);
        printf("BSS ID : ");
        for(int i = 0 ; i < MAC_ADDR_LEN ; i++){
            printf("%02x", prb -> mac_bssid[i]);
            if(i < MAC_ADDR_LEN - 1){
                printf(":");    
            }
        }
        printf("\t");
        
        printf("SSID : ");
        if(sid->tag_length > 30){
            printf("\n");
            continue;
        }
        else{
            for(int i = 0 ; i < sid->tag_length ; i++){
                printf("%c", *(packet+70+i));
            }
            printf("\n");
        }


    }
    pcap_close(pcap);
}