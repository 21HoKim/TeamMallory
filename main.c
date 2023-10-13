#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

void usage()
{
    printf("syntax: pcap <interface> <AP mac>\n");
    printf("sample: pcap wlan0 11:22:33:44:55:66\n");
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
    unsigned char *AP_MAC = argv[2];
    unsigned char *STA_MAC = argv[3];

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap = pcap_open_live(Interface, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL)
    {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }

    /*
    
    
    여기서부터 코드 작성
    
    
    */


    pcap_close(pcap);
}
