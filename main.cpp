#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h> // ntohs
#include <time.h>      // 시간 입력

#include "header_gruop.h"

void beacon_frame()
{
    time_t t=time(nullptr);
    struct tm *tm =localtime(&t);

    printf("[%d.%d.%d %d:%d ]\n",tm->tm_year+1900,tm->tm_mon+1,tm->tm_mday,tm->tm_hour,tm->tm_min);
}


int main(int argc, char* argv[])
{
    if (argc > 1) printf("error\n");

    char errbuf[PCAP_ERRBUF_SIZE];      //size 256
    const char *dev = argv[1];
    pcap_t* handle = pcap_open_live("wlan0",BUFSIZ,1,100,errbuf);
    if(handle == nullptr )
    {
        printf("찾을 수 없습니다.\n");
        return -1;
    }

    while(1)
    {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle,&header,&packet);
        if(res ==0) continue;
        if(res ==-1 || res == -2) break;
        struct ieee80211_radiotap_header *radiotap_header= (struct ieee80211_radiotap_header *)packet;
        struct ieee80211_beacon_frame * beacon_header = (struct ieee80211_beacon_frame *)(packet + radiotap_header->it_len);
        //struct ieee80211_beacon_frame * beacon_header = (struct ieee80211_beacon_frame *)(packet + 18);

        //printf("Radio tap first :: %x\n",radiotap_header->it_version);
        //printf("Pad :: %x\n",radiotap_header->it_pad);
        //printf("Header Length :: %x \n",radiotap_header->it_len);
        //printf("present :: %x \n", ntohl(radiotap_header->it_present));
        //printf("Flag :: %x \n", radiotap_header->it_Flags);
        //printf("DataRate :: %x\n",radiotap_header->it_dataRate);
        //printf("ChannelFrequency :: %x \n", radiotap_header->it_channelfrequency);
        //printf("Channel Flags :: %x \n",radiotap_header->it_channelflags);
        //printf("Antenna Signal :: %x \n",radiotap_header->it_Antennasignal);
        //printf("Antenna :: %x \n", radiotap_header->it_Antenna);
        //printf("Rxflags :: %x \n",radiotap_header->it_Rxflags);
        //printf("Radio Tap END::_______________\n");
        printf("%x\n",ntohs(beacon_header->j_Frame_control));

        printf("Length of Radio tap Hedaer :: %d \n",radiotap_header->it_len);


        /*
        if(ntohs(beacon_header->j_Frame_control) == 0x8000)
        {
            printf("Beacon Check Code :: %x\n",ntohs(beacon_header->j_Frame_control));
            beacon_frame();
        }
        */

    }



    return 0;
}
