#include <stdio.h>
#include <iostream>
#include <pcap.h>
#include <arpa/inet.h> // ntohs
#include <time.h>      // 시간 입력
#include <stdlib.h>     // system, strtol
#include <unistd.h>     //sleepr
#include <map>          //map
#include <cstring>     //memcpy
#include "header_gruop.h"

using namespace std;

static std::map<uint48,data_map > m;
static map<uint48,data_map>::iterator it;

void bssid(const u_char * packet)
{
    struct ieee80211_radiotap_header *radiotap_header= (struct ieee80211_radiotap_header *)packet;
    struct ieee80211_beacon_frame * beacon_header = (struct ieee80211_beacon_frame *)(packet + radiotap_header->it_len);


    struct data_map data;



    m.insert(std::make_pair(beacon_header->j_BSSID,data));
    //data.it_Antennasignal = radiotap_header->it_Antennasignal;

    it = m.find(beacon_header->j_BSSID);
    if(it !=m.end())
    {
        it->second.beacons ++;
        //printf("Find Mac");
    }

    for(it = m.begin();it!=m.end();++it)
    {
        printf("%17llx ",it->first);
        //printf("  %3d ",radiotap_header->it_Antennasignal);
        memcpy(&data.it_Antennasignal,&radiotap_header->it_Antennasignal,sizeof(radiotap_header->it_Antennasignal));
        printf("%5d ",it->second.it_Antennasignal);

        printf("%8d ", it->second.beacons);
        printf("\n");
    }






    //printf("  %3d ",(char)radiotap_header->it_Antennasignal);
    //printf("        %3d ",(*it).second.beacons);
    //printf("        %3d ",(*it).second.beacons);
}




void beacon_frame(const u_char* packet)
{
    struct ieee80211_radiotap_header * radiotap = (struct ieee80211_radiotap_header *)packet;
    struct ieee80211_beacon_frame * beacon_header = (struct ieee80211_beacon_frame *)(packet + radiotap->it_len);
    struct ieee80211_wireless_lan * wire_data = (struct ieee80211_wireless_lan *)(packet + radiotap->it_len +20);


    time_t t=time(nullptr);
    struct tm *tm =localtime(&t);
    system("clear");

    //--------- Chennal

    //printf("-----------------:: %d \n",(radiotap->it_channelfrequency - 2412)/5+1 );  //채널 계산
    //printf("Channel Check :: %d \n",radiotap->it_channelfrequency);

    printf("CH: %d || [%d.%d.%d %d:%d ]\n",(radiotap->it_channelfrequency - 2412)/5+1,tm->tm_year+1900,tm->tm_mon+1,tm->tm_mday,tm->tm_hour,tm->tm_min);

    //printf("경과시간 : %d \n",tm->);
    //sleep(3);

    printf("BSSID               PWR     Beacons     #Data,   #/s  CH   MB   ENC   CIPHER   AUTH     ESSID\n");
    printf("--------------------------------------------------------------------------------------------\n");
    printf("A8:11:11:11:11:11   %d         %d        %d     %d  %d   %d    %d       %d     %d   JBU_CCIT\n",32,321,12,21,21,21,21,12,21);
    bssid(packet);



    printf("\n");


    sleep(1);


}






int main(int argc, char* argv[])
{

    if (argc > 1) printf("error\n");

    char errbuf[PCAP_ERRBUF_SIZE];      //size 256
    const char *dev = argv[1];
    pcap_t* handle = pcap_open_live("wlan1",BUFSIZ,1,100,errbuf);
    if(handle == nullptr )
    {
        // for(int i=0; i<10; ++i)
        //{
        printf("Search Wlan0...\n");

        system("ifconfig wlan0 down");
        system("iwconfig wlan0 mode monitor");
        system("ifconfig wlan0 up");

        //  if(handle != nullptr)
        //      break;

        //  if(i==9)
        //      printf("찾을 수 없습니다.\n");
        //      return -1;
        //}



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

        //printf("%x\n",ntohs(beacon_header->j_Frame_control));

        if(ntohs(beacon_header->j_Frame_control) == 0x8000)
        {
            //printf("Beacon Check Code :: %x\n",ntohs(beacon_header->j_Frame_control));
            beacon_frame(packet);
        }


    }



    return 0;
}
