#define MAC_ADDR_LEN 6

typedef struct radiotap_header{ //must be 32
    unsigned char hdr_rev;
    unsigned char hdr_pad;
    unsigned char hdr_len;
    unsigned char presentFlags[4]; //variable or invariant not distinguished.
    unsigned char Flags;
    unsigned char data_rate;
    unsigned char channel_freq;
    unsigned char channel_flags[2];
    unsigned char antenna_signal;
    unsigned char signal_quality;
    unsigned char rx_flags[3];
    unsigned char antenna; //if antenna is 1 -> end of antenna signal //all  of sum = 18 
} __attribute__((packed, aligned(32))) radio;

typedef struct probe_response{ //must be 24
    unsigned char ctrl_field[2];
    unsigned char duration[2];
    unsigned char mac_rec[MAC_ADDR_LEN]; //receiver length=6
    //unsigned char mac_des[MAC_ADDR_LEN]; //destination
    //unsigned char mac_trs[MAC_ADDR_LEN]; //transmi
    unsigned char mac_src[MAC_ADDR_LEN]; //source
    unsigned char mac_bssid[MAC_ADDR_LEN];
    unsigned char frag_seq_number[2]; // fragment number + sequence number
} prob; //__attribute__((packed, aligned(24))) probe; -> aligned must be the square of 2.

typedef struct ssid_parameter_set{
    unsigned char tag_number;
    unsigned char tag_length;
}ssid;