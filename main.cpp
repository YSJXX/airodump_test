#include <stdio.h>
#include <iostream>
#include <pcap.h>
#include <arpa/inet.h> // ntohs
#include <time.h>      // 시간 입력
#include <stdlib.h>     // system, strtol
#include <unistd.h>     //sleepr
#include <map>          //map
#include "header_gruop.h"
using namespace std;

void bssid(const u_char * packet)
{
    struct ieee80211_radiotap_header *radiotap_header= (struct ieee80211_radiotap_header *)packet;
    struct ieee80211_beacon_frame * beacon_header = (struct ieee80211_beacon_frame *)(packet + radiotap_header->it_len);



    std::map<int,struct data_map > m;
    struct data_map data;


    int check=0;
    int key;
    m[key] = data;
    auto it = m.begin();


    for(int i=0;i<6;++i) if(beacon_header->j_Source_address[i] == data.j_BSSID[i]) ++check;
    //value 찾는 코드 다시 짜야함 위에 코드.
    if(SAME_MAC != check)       // 새로운 mac 추가
    {
        for(int i=0; i<6;++i)
        {
            //(*it).second.j_BSSID[i] = beacon_header->j_Source_address[i] ;
            data.j_BSSID[i] = beacon_header->j_Source_address[i];
        }

        for(int i=0; i<6; ++i)
        {
            if(i<5)
                printf("%02x:",data.j_BSSID[i]);
            else
                printf("%02x", data.j_BSSID[i]);
        }
    }
    else {
        //++(*it).second.beacons;
        //++data.beacons;
        std::cout<<"################################TESTING"<<'\n';
    }





    printf("  %3d ",(char)radiotap_header->it_Antennasignal);
    //printf("        %3d ",(*it).second.beacons);
    printf("        %3d ",data.beacons);


}




void beacon_frame(const u_char* packet)
{
    struct ieee80211_radiotap_header * radiotap = (struct ieee80211_radiotap_header *)packet;
    struct ieee80211_beacon_frame * beacon_header = (struct ieee80211_beacon_frame *)(packet + radiotap->it_len);



    time_t t=time(nullptr);
    struct tm *tm =localtime(&t);
    // system("clear");

    //--------- Chennal

    //printf("-----------------:: %d \n",(radiotap->it_channelfrequency - 2412)/5+1 );  //채널 계산
    //printf("Channel Check :: %d \n",radiotap->it_channelfrequency);

    printf("CH: %d || [%d.%d.%d %d:%d ]\n",(radiotap->it_channelfrequency - 2412)/5+1,tm->tm_year+1900,tm->tm_mon+1,tm->tm_mday,tm->tm_hour,tm->tm_min);



    //printf("경과시간 : %d \n",tm->);
    //sleep(3);

    printf("BSSID               PWR     Beacons     #Data,   #/s  CH   MB   ENC   CIPHER   AUTH     ESSID\n");
    printf("--------------------------------------------------------------------------------------------\n");
    printf("A*:11:11:11:11:11   %d         %d        %d     %d  %d   %d    %d       %d     %d   JBU_CCIT\n",32,321,12,21,21,21,21,12,21);
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
            printf("####TEST MAC :: %llx \n",beacon_header->j_BSSID);

            //printf("Beacon Check Code :: %x\n",ntohs(beacon_header->j_Frame_control));
            //beacon_frame(packet);
        }


    }



    return 0;
}
