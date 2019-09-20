#ifndef HEADER_GRUOP_H
#define HEADER_GRUOP_H

#endif // HEADER_GRUOP_H
#include <pcap.h>


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
    u_int8_t j_Destination_address[6];
    u_int8_t j_Source_address[6];
    u_int8_t j_BSSID[6];
    u_int16_t j_SequenceControl;
};

