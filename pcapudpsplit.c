#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

typedef struct pcap_hdr_s {
        uint32_t magic_number;   /* magic number */
        uint16_t version_major;  /* major version number */
        uint16_t version_minor;  /* minor version number */
        int32_t  thiszone;       /* GMT to local correction */
        uint32_t sigfigs;        /* accuracy of timestamps */
        uint32_t snaplen;        /* max length of captured packets, in octets */
        uint32_t network;        /* data link type */
} pcap_hdr_t;

typedef struct pcaprec_hdr_s {
        uint32_t ts_sec;         /* timestamp seconds */
        uint32_t ts_usec;        /* timestamp microseconds */
        uint32_t incl_len;       /* number of octets of packet saved in file */
        uint32_t orig_len;       /* actual length of packet */
} pcaprec_hdr_t;

pcap_hdr_t gh;
pcaprec_hdr_t h;

int main() {
	int no=0;
	char buf[65535];
	fread(&gh,sizeof(gh),1,stdin);
	for(;;) {
		if(fread(&h,sizeof(h),1,stdin)!=1) break;
		sprintf(buf,"%08u.pkt",no);
		FILE *f=fopen(buf,"w");
		if(fread(buf,h.incl_len,1,stdin)!=1) { fclose(f); break; }

		int dataoff=6+6+2; // ethernet dst+src+type/len
		dataoff+=(buf[dataoff]&0xf)*4; // ip
		dataoff+=8; // udp

		if(dataoff>h.incl_len) { abort(); }
		fwrite(buf+dataoff,h.incl_len-dataoff,1,f);
		fclose(f);
		no++;
	}
	return 0;
}


