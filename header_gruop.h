#include <pcap.h>
#include <map>
#include <cstring>
#include <string>

#define SAME_MAC 6

#ifndef HEADER_GRUOP_H
#define HEADER_GRUOP_H

#endif // HEADER_GRUOP_H

#pragma once


struct uint48{
    unsigned long long v:48;
}__attribute__((packed));           // and push pop

bool operator<(uint48 const& n1, uint48 const& n2)
{
    return n1.v < n2.v || (n1.v > n2.v);
}


struct ieee80211_radiotap_header {
    u_int8_t it_version;
    u_int8_t it_pad;
    u_int16_t it_len;
    u_int32_t it_present;
    u_int8_t it_Flags;
    u_int8_t it_dataRate;
    u_int16_t it_channelfrequency;
    u_int16_t it_channelflags;
    u_int8_t it_Antennasignal;
    u_int8_t it_Antenna;
    u_int16_t it_Rxflags;
};

struct ieee80211_beacon_frame{
    u_int16_t j_Frame_control;
    u_int16_t j_Duration;
    uint48 j_Destination_address;
    uint48 j_Source_address;
    uint48 j_BSSID;
    u_int16_t j_SequenceControl;
};

struct data_map{
    u_int8_t j_BSSID[6];
    u_int8_t it_Antennasignal;
    u_int8_t beacons;
    u_int8_t sharp_data;
    u_int8_t sharp_s;
    u_int8_t channel;
    u_int8_t MB;
    u_int8_t encrypt;
    u_int8_t cipher;
    u_int8_t auth;
    u_int8_t ESSID;

};

struct ieee80211_wireless_lan
{
    struct fixed_parameters{
        u_int64_t timestamp;
        u_int16_t beacon_interval;
        u_int16_t capabilities_info;
    };
    struct tag_parameters{
        u_int8_t tag_number;
        u_int8_t tag_length;
        u_int8_t SSID[];
    };
};
