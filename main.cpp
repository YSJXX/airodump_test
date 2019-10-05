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

static struct data_map data;
static std::map<uint48,data_map > m;
static map<uint48,data_map>::iterator it;


void mac(uint48 mac_addr)
{
    //uint8_t temp[6];
    //temp[0]= mac_addr;
    //u_int8_t*p=(u_int8_t*)&mac_addr;
    u_int8_t *ptr = reinterpret_cast<u_int8_t*>(&mac_addr);
    printf("%02x:%02x:%02x:%02x:%02x:%02x ",ptr[0],ptr[1],ptr[2],ptr[3],ptr[4],ptr[5]);
}

void printf_p()
{
    for(auto it = m.begin(); it!=m.end(); ++it)
    {
        mac(it->first);
        //printf("%5d ",radiotap->it_Antennasignal);
        printf("%5d ",it->second.it_Antennasignal);
        printf("%10d ", it->second.beacons);
        printf("\n");
    }

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

    map<uint48,data_map>::iterator iter;

    if(m.count(beacon_header->j_BSSID))
    {
        iter = m.find(beacon_header->j_BSSID);
        //printf("TEST2************************\n");
        memcpy(&iter->second.it_Antennasignal,&radiotap->it_Antennasignal,1);
        iter->second.beacons ++;
        printf_p();
        //sleep(1);
    }
    else
    {
        m.insert(std::make_pair(beacon_header->j_BSSID,data));
        memcpy(&it->second.it_Antennasignal,&radiotap->it_Antennasignal,1);
        printf_p();
        it++;
        //sleep(1);
    }
}






int main(int argc, char* argv[])
{

    if (argc > 1) printf("error\n");

    char errbuf[PCAP_ERRBUF_SIZE];      //size 256
    const char *dev = argv[1];
    pcap_t* handle = pcap_open_live("wlan0",BUFSIZ,1,100,errbuf);
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




    int x=0;
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

            if( x == 0)
            {
                m.insert(std::make_pair(beacon_header->j_BSSID,data));
                it=m.begin();
            }
                //printf("Beacon Check Code :: %x\n",ntohs(beacon_header->j_Frame_control));
            beacon_frame(packet);

        }
    }

    return 0;
}
