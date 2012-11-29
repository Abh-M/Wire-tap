//
//  Analyzer.h
//  Wiretap
//
//  Created by Abhineet on 10/11/12.
//  Copyright (c) 2012 Abhineet. All rights reserved.
//

#ifndef __Wiretap__Analyzer__
#define __Wiretap__Analyzer__

#include <iostream>
#include "PCH.h"
#include "Helpers.h"

using namespace std;
class Analyzer {

    string pcapFile;
    pcap_t *handle;

//    Maps for layer 1
    map<string, int> ethernetUniqueSrcAddrMap;
    map<string, int> ethernetUniqueDesAddrMap;
    map<int,int> uniqueNetworkLayerProtocolsMap;
    

//    Maps for layer 2
    map<string, int> ipUniqueSrcAddrMap;
    map<string, int> ipUniqueDesAddrMap;
    map<int,int>     ipUniqueTTLMap;
    
    
    //Maps for unique ARP participants
    int totalARPPackets;
    map<string, string> arpSrcMacAndIpMap;
    map<string, string> arpDesMacAndIpMap;
    
//    map<string,map<string,int> > arpSrcMacIpCntMap;
//    map<string,map<string,int> > arpDesMacIpCntMap;
    
    //map for unique transport layer protocols
    map<int,int> uniqueTransportLayerProtocolsMap;
    
    
    //Maps for transport layer info
    map<int,int> tcpUniqueSrcPortsMap;
    map<int,int> tcpUniqueDesPortsMap;
    map<string,int> tcpUniqueFlagCombinationsMap;
    int totalTCPPackets;
    
    
    
    map<int,int> tcpUniqueTCPOptionsMap;
    
    //ICMP Maps
    map<int,map<int,int> > icmpTypeCodeMap;
    map<string,int> icmpUniqueSrcAddressMap;
    map<string,int> icmpUniqueDesAddressMap;
    int totalICMPPackets;
    

    map<int,int> udpUniqueSrcPortsMap;
    map<int,int> udpUniqueDesPortsMap;
    int totalUDPPackets;
    
    
    int totalV6Packets;
    int totalV4Packets;
    
    int totalPackets;
    int minPacketSize;
    int maxPacketSize;
    int avgPacketSize;

    
    void analyzeEthernetHeader(struct ether_header *kHeader);
    void analyzeIPHeader(struct ip *kHeader);
    
public:
    Analyzer();
    Analyzer(string kFile);
    bool startAnalyzing();
    void getUniqueEtherAddressResult();
    void getPacketSizeStats();
    void getUniqueNetworkLayerProtoclsResult();
    void getUniqueSrcIPResult();
    void getUniqueDesIPResult();
    void getUniqueTTLResult();
    void getUniqueARPParticipantsResult();
    void getUniqueTransportLayerProtocolsResult();
    void analyzeTCPHeader(struct tcphdr *kHeader);
    void analyzeUDPHeader(struct udphdr *kHeader);

    void getUniqueTCPPortsResult();
    void getUniqueUDPPortsResult();
    void getTCPFlagCombinationsResult();
    void getTCPOptionsResult();
    void getICMPTypeCodeResult();
    void getICMPSrcIPResult();
    void getICMPDesIPResult();
//    void getARPSrcMACIPResult();
    


};

#endif /* defined(__Wiretap__Analyzer__) */
