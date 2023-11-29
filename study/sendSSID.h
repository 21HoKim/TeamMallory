#define MAC_ADDR_LEN 6

typedef struct beacon_frame{ //must be 24
    unsigned char radio_tap[32]; //32
    unsigned short Frame_Control_Field; //0x0080
    unsigned short duration; //0x0000
    unsigned char receiver_address[MAC_ADDR_LEN]; //DA ff:ff:ff:ff:ff:ff
    unsigned char source_address[MAC_ADDR_LEN]; //SA 22:11:44:33:66:55
    unsigned char BSSID[MAC_ADDR_LEN]; //22:11:44:33:66:55
    unsigned short frag_seq_number; //0x0000
    unsigned char fixed_tag[12]; ///0x00 12time
    unsigned char ssidpad; //0x00
    unsigned char ssid_len; //0x??
    unsigned char *ssid_name; //size is 8
} Bframe;