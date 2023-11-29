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

    if (!parse(&param, argc, argv)) //프로그램 인자값 검사
        return -1;

    unsigned char *Interface = argv[1]; //네트워크 인터페이스
    unsigned char *AP_MAC = argv[2]; //AP의 Mac Address

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap = pcap_open_live(Interface, BUFSIZ, 1, 1000, errbuf); //해당 함수를 사용하면 네트워크 인터페이스와 연결된 포인터를 만든다.

    if (pcap == NULL)
    {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf); //에러 메시지 출력
        return -1;
    }
    while(true){
      struct pcap_pkthdr* header;
		  const u_char* packet; //패킷의 첫번째 주소를 가리키는 포인터
		  int res = pcap_next_ex(pcap, &header, &packet);  //packet에 packet의 주소가 들어감, pcap_next_ex 함수는 다음 패킷을 받는 함수.
		  if (res == 0) continue;
		  if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			  printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			  break;
		  }
    }
    pcap_close(pcap);
}
