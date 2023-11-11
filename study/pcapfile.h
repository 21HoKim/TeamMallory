#pragma once
#include <stdio.h>
typedef unsigned int uint;
typedef unsigned short ushort;
typedef unsigned char uchar;

typedef struct _PFHeader PFHeader;
struct _PFHeader{
    uint magic;
    ushort major;
    ushort minor;
    uint gmt_to_local;
    uint timestamp;
    uint max_caplen;
    uint linktype;
};

typedef struct _PACKETHEADER PackHeader;
struct _PACKETHEADER{
    uint captime;
    uint caputime;
    uint caplen;
    uint packlen;
};

#define PF_MAGIC 0xA1B2C3D4
#define LT_ETHER 0x01
void ParseEther(FILE *fp);
int ParsePCapFile(FILE *fp, PFHeader *pfh);