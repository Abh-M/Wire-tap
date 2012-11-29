//
//  Helpers.h
//  Wiretap
//
//  Created by Abhineet on 09/11/12.
//  Copyright (c) 2012 Abhineet. All rights reserved.
//

#ifndef __Wiretap__Helpers__
#define __Wiretap__Helpers__

#include <iostream>
#include "PCH.h"
#include "Globals.h"

using namespace std;
void logIpHeader(struct ip *kIpHdr, int tabs, int nxtline);
void logEthernetHeader(struct ether_header *ehdr, int tabs, int nxtline);
string getEthDestinationAddress(struct ether_header *kHeader);
string getEthSourceAddress(struct ether_header *kHeader);
srcDesIpv4 getIpPairForIpHeader(struct ip *kIpHdr);
void logTCPHeader(struct tcphdr *kHeader);
void logUDPHeader(struct udphdr *header);
string getFlagCombinationForTCPHeader(struct tcphdr *kHeader);
bool isBroadCastEtherAddress(string macAddr);


#endif /* defined(__Wiretap__Helpers__) */
