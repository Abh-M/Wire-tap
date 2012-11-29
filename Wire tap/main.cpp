//
//  main.cpp
//  Wiretap
//
//  Created by Abhineet on 25/11/12.
//  Copyright (c) 2012 Abhineet. All rights reserved.
//
#include "PCH.h"
#include "Helpers.h"
#include "Globals.h"
#include "Analyzer.h"
using namespace std;
int main(int argc, const char * argv[])
{
    string filename("/Users/abhineet/Github/Wiretap/Wiretap/traceroute.pcap");
    Analyzer *kAnalyzer = new Analyzer(filename);
    kAnalyzer->startAnalyzing();
//    kAnalyzer->getPacketSizeStats();
//    kAnalyzer->getUniqueEtherAddressResult();
//    kAnalyzer->getUniqueNetworkLayerProtoclsResult();
//    kAnalyzer->getUniqueSrcIPResult();
//    kAnalyzer->getUniqueDesIPResult();
//    kAnalyzer->getUniqueTTLResult();
    kAnalyzer->getUniqueARPParticipantsResult();
//    kAnalyzer->getUniqueTransportLayerProtocolsResult();
//    kAnalyzer->getUniqueTCPPortsResult();
//    kAnalyzer->getUniqueUDPPortsResult();
//    kAnalyzer->getTCPFlagCombinationsResult();
//    kAnalyzer->getTCPOptionsResult();
//    kAnalyzer->getICMPTypeCodeResult();
//    kAnalyzer->getICMPSrcIPResult();
//    kAnalyzer->getICMPDesIPResult();
    //kAnalyzer->getARPSrcMACIPResult();
    return 0;
}

