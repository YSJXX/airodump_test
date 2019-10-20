#include <stdio.h>
#include <iostream>
#include <pcap.h>
#include <pthread.h>
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
//static map<uint48,data_map>::iterator it;

void mac(uint48 mac_addr)
{
    u_int8_t *ptr = reinterpret_cast<u_int8_t*>(&mac_addr);
    printf("%02x:%02x:%02x:%02x:%02x:%02x ",ptr[0],ptr[1],ptr[2],ptr[3],ptr[4],ptr[5]);
}

void *display (void* a)
{
    while(true)
    {
        printf("BSSID               PWR     Beacons  #Data, #/s  CH  MB  ENC  CIPHER  AUTH   ESSID\n");
        printf("-------------------------------------------------------------------------------------\n");
        for(auto it = m.begin(); it!=m.end(); ++it)
        {
            mac(it->first);
            printf("%5d ",it->second.it_Antennasignal);
            printf("%10d ",it->second.beacons);
            printf("%15d ",it->second.channel);
            printf("                ");
            for(int i=0;i<20;i++)//it->second.ESSID[i]=='\0'
            {
                //printf("TEST\n");
                printf("%c",it->second.ESSID[i]);
            }
            printf("\n");
        }
        sleep(1);
        system("clear");

    }

}

void *save_data (void* arg)
{
    char errbuf[PCAP_ERRBUF_SIZE];      //size 256
    pcap_t* handle = pcap_open_live("wlan1",BUFSIZ,1,100,errbuf);
    while(true)
    {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle,&header,&packet);
        if(res ==0) continue;
        if(res ==-1 || res == -2) break;

        struct ieee80211_radiotap_header *radiotap_header= (struct ieee80211_radiotap_header *)packet;
        if(radiotap_header->it_len == 0x000d) continue;         //len 13: only tcpreplay code
        struct ieee80211_beacon_frame * beacon_header = (struct ieee80211_beacon_frame *)(packet + radiotap_header->it_len);
        struct tag_ssid * ssid =(struct tag_ssid *)(packet + radiotap_header->it_len +24+12);       // 24: beacon length ,12 fixed parameters length

        const u_int8_t * point =(packet + radiotap_header->it_len +24+12);

        if(ntohs(beacon_header->j_Frame_control) == 0x8000)
        {
            int a=0;
            while(true)
            {
                //printf("%x\n",*(point));
                if(*(point) == 0x30)                //RSN number
                {
                    printf("TEST3333333333333333 |%x|\n",*(point+8));
                    if(*(point+8)==0x02)          //pairwise suite count : 1
                    {
                        a=4;
                        printf("11111111111111111111TEST\n");
                        sleep(5);
                    }
                    //printf("TEST2222 |%x|\n",*(point+12+a));
                    switch(*(point+13+a))         //Cipher_Suite_type :
                    {
                    case 1:
                    {
                        printf("WEP-40\n");
                        break;
                    }
                    case 2:
                    {
                        printf("TKIP\n");
                        break;
                    }
                    case 4:
                    {
                        printf("CCMP\n");
                        break;
                    }
                    default:
                    {
                        printf(" x \n");
                        break;
                    }

                    }
                    printf("AKM: %x\n",*(point+16+a));
                    switch(*(point+16+a))         //AKM type:
                    {
                    case 1:
                    {
                        printf("MGT\n");
                        break;
                    }
                    case 2:
                    {
                        printf("PSK\n");
                        break;
                    }
                    default:
                    {
                        printf(" x \n");
                        break;
                    }
                    }

                    printf("------------\n");
                    break;
                }
                point += *(point+1)+2;        //tag length 만큼 더하기.
                if(*(point)=='\0')         // not found
                {
                    printf("OPN\n");
                    break;
                }
            }

            m.insert(std::make_pair(beacon_header->j_BSSID,data));      // 없다면 추가 있으면 아무것도 하지 않음.
            uint16_t channel = ((radiotap_header->it_channelfrequency-2412)/5+1);
            map<uint48,data_map>::iterator iter;
            iter= m.find(beacon_header->j_BSSID);
            if(iter != m.end())
            {
                for(int i=0;i<ssid->tag_length;i++)
                    memcpy(&iter->second.ESSID[i],&ssid->SSID[i],1);

                memcpy(&iter->second.it_Antennasignal,&radiotap_header->it_Antennasignal,1);
                memcpy(&iter->second.channel,&channel,1);
                ++iter->second.beacons;


            }
        }
    }
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

    printf("------| 종료 : 1 |-----\n");
    pthread_t display_thread,back_thread;

    //pthread_create(&display_thread,nullptr,display,nullptr);
    pthread_create(&back_thread,nullptr,save_data,nullptr);
    int x=0;
    while(true)
    {
        scanf("%d",&x);
        if(x==1) return 0;
    }



}
