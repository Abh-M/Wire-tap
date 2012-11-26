//
//  Analyzer.cpp
//  Wiretap
//
//  Created by Abhineet on 10/11/12.
//  Copyright (c) 2012 Abhineet. All rights reserved.
//

#include "Analyzer.h"



Analyzer::Analyzer()
{
    //initialize
}


Analyzer::Analyzer(string kFile)
{
    cout<<"\nFile to scan: "<<kFile;
    this->pcapFile = kFile;
    
}



void Analyzer::analyzeEthernetHeader(struct ether_header *kHeader)
{
    
    //extact source and destination address
    string srcEthAddr =  getEthSourceAddress(kHeader);
    string desEthAddr =  getEthDestinationAddress(kHeader);
    
    
    
    int cnt = this->ethernetUniqueSrcAddrMap[srcEthAddr];
    this->ethernetUniqueSrcAddrMap[srcEthAddr] = cnt+1;
    
    cnt = this->ethernetUniqueDesAddrMap[desEthAddr];
    this->ethernetUniqueDesAddrMap[desEthAddr] = cnt+1;
    
    int networkProtocol = ntohs(kHeader->ether_type);
    cnt = this->uniqueNetworkLayerProtocolsMap[networkProtocol];
    this->uniqueNetworkLayerProtocolsMap[networkProtocol] = cnt+1;
    
}


void Analyzer::getPacketSizeStats()
{
    cout<<"\n--------------------------------------------";
    cout<<"\n| Packet Size Stats                        |";
    cout<<"\n--------------------------------------------";
    cout<<"\n Total Packets       : "<<this->totalPackets;
    cout<<"\n Maximum Packet Size : "<<this->maxPacketSize;
    cout<<"\n Minimum Packet Size : "<<this->minPacketSize;
    cout<<"\n Average Packet Size : "<<this->avgPacketSize;
    cout<<"\n++++++++++++++++++++++++++++++++++++++++++++";
}


void Analyzer::getUniqueNetworkLayerProtoclsResult()
{
    
    cout<<"\n\n\n-----------------Network Layer Protocols-----------------\n\n";
    
    const char *thcol1 = "Protocol Number";
    const char *thcol2 = "Number of packets";
    const char *thcol3 = "Percentage %";
    int col_1_width = (int)strlen(thcol1)+3;
    int col_2_width = (int)strlen(thcol2)+3;
    int col_3_width = (int)strlen(thcol3)+3;
    
    cout.width(col_1_width);
    cout.fill(' ');
    cout <<left<<thcol1;
    
    
    cout.width(col_2_width);
    cout.fill(' ');
    cout<<left<<thcol2;
    
    
    cout.width(col_3_width);
    cout.fill(' ');
    cout<<left<<(thcol3);
    cout<<endl;
    
    for( map<int,int>::iterator itr= this->uniqueNetworkLayerProtocolsMap.begin(); itr!=this->uniqueNetworkLayerProtocolsMap.end(); ++itr)
    {
        cout.width(col_1_width);
        cout.fill(' ');
        cout <<left<<(*itr).first;
        cout.width(col_2_width);
        cout.fill(' ');
        cout<<left<<(*itr).second;
        cout.width(col_3_width);
        cout.fill(' ');
        cout <<setprecision(3)<<(((float)(*itr).second)/this->totalPackets)*100;
        cout<<endl;
    }
    
    
}


void Analyzer::getUniqueSrcIPResult()
{
    cout<<"\n\n\n-----------------Source IP address-----------------\n\n";
    
    const char *thcol1 = "IP Address";
    const char *thcol2 = "Number of packets";
    const char *thcol3 = "Percentage %";
    int col_1_width = (int)strlen(thcol1)+10;
    int col_2_width = (int)strlen(thcol2)+3;
    int col_3_width = (int)strlen(thcol3)+3;
    
    cout.width(col_1_width);
    cout.fill(' ');
    cout <<left<<thcol1;
    
    
    cout.width(col_2_width);
    cout.fill(' ');
    cout<<left<<thcol2;
    
    
    cout.width(col_3_width);
    cout.fill(' ');
    cout<<left<<(thcol3);
    cout<<endl;
    
    for( map<string,int>::iterator itr= this->ipUniqueSrcAddrMap.begin(); itr!=this->ipUniqueSrcAddrMap.end(); ++itr)
    {
        cout.width(col_1_width);
        cout.fill(' ');
        cout <<left<<(*itr).first;
        cout.width(col_2_width);
        cout.fill(' ');
        cout<<left<<(*itr).second;
        cout.width(col_3_width);
        cout.fill(' ');
        cout <<setprecision(3)<<(((float)(*itr).second)/this->totalV4Packets)*100;
        cout<<endl;
    }
    
    
    
}


void Analyzer::getUniqueTTLResult()
{
    cout<<"\n\n\n-----------------TTLs in IP Packets-----------------\n\n";
    
    const char *thcol1 = "TTL";
    const char *thcol2 = "Number of packets";
    const char *thcol3 = "Percentage %";
    int col_1_width = (int)strlen(thcol1)+10;
    int col_2_width = (int)strlen(thcol2)+3;
    int col_3_width = (int)strlen(thcol3)+3;
    
    cout.width(col_1_width);
    cout.fill(' ');
    cout <<left<<thcol1;
    
    
    cout.width(col_2_width);
    cout.fill(' ');
    cout<<left<<thcol2;
    
    
    cout.width(col_3_width);
    cout.fill(' ');
    cout<<left<<(thcol3);
    cout<<endl;
    
    for( map<int,int>::iterator itr= this->ipUniqueTTLMap.begin(); itr!=this->ipUniqueTTLMap.end(); ++itr)
    {
        cout.width(col_1_width);
        cout.fill(' ');
        cout <<left<<(*itr).first;
        cout.width(col_2_width);
        cout.fill(' ');
        cout<<left<<(*itr).second;
        cout.width(col_3_width);
        cout.fill(' ');
        cout <<setprecision(3)<<(((float)(*itr).second)/this->totalV4Packets)*100;
        cout<<endl;
    }
    
    
}


void Analyzer::getUniqueDesIPResult()
{
    cout<<"\n\n\n-----------------Destination IP Address-----------------\n\n";
    
    const char *thcol1 = "IP Address";
    const char *thcol2 = "Number of packets";
    const char *thcol3 = "Percentage %";
    int col_1_width = (int)strlen(thcol1)+10;
    int col_2_width = (int)strlen(thcol2)+3;
    int col_3_width = (int)strlen(thcol3)+3;
    
    cout.width(col_1_width);
    cout.fill(' ');
    cout <<left<<thcol1;
    
    
    cout.width(col_2_width);
    cout.fill(' ');
    cout<<left<<thcol2;
    
    
    cout.width(col_3_width);
    cout.fill(' ');
    cout<<left<<(thcol3);
    cout<<endl;
    
    for( map<string,int>::iterator itr= this->ipUniqueDesAddrMap.begin(); itr!=this->ipUniqueDesAddrMap.end(); ++itr)
    {
        cout.width(col_1_width);
        cout.fill(' ');
        cout <<left<<(*itr).first;
        cout.width(col_2_width);
        cout.fill(' ');
        cout<<left<<(*itr).second;
        cout.width(col_3_width);
        cout.fill(' ');
        cout <<setprecision(3)<<(((float)(*itr).second)/this->totalV4Packets)*100;
        cout<<endl;
    }
    
    
    
}




void Analyzer::getUniqueEtherAddressResult()
{
    cout<<"\n\n\n-----------------Source Ethernet Address-----------------\n\n";
    const char *thcol1 = "MAC Address";
    const char *thcol2 = "Number of packets";
    const char *thcol3 = "Percentage %";
    int col_1_width = (int)strlen(thcol1)+15;
    int col_2_width = (int)strlen(thcol2)+3;
    int col_3_width = (int)strlen(thcol3)+3;
    
    cout.width(col_1_width);
    cout.fill(' ');
    cout <<left<<thcol1;
    
    
    cout.width(col_2_width);
    cout.fill(' ');
    cout<<left<<thcol2;
    
    
    cout.width(col_3_width);
    cout.fill(' ');
    cout<<left<<(thcol3);
    cout<<endl;
    for( map<string,int>::iterator itr= this->ethernetUniqueSrcAddrMap.begin(); itr!=this->ethernetUniqueSrcAddrMap.end(); ++itr)
    {
        cout.width(col_1_width);
        cout.fill(' ');
        cout <<left<<(*itr).first;
        cout.width(col_2_width);
        cout.fill(' ');
        cout<<left<<(*itr).second;
        cout.width(col_3_width);
        cout.fill(' ');
        cout <<setprecision(3)<<(((float)(*itr).second)/this->totalPackets)*100;
        cout<<endl;
    }
    
    
    cout<<"\n\n--------------Destination Ethernet Address--------------\n\n";
    
    cout.width(col_1_width);
    cout.fill(' ');
    cout <<left<<thcol1;
    
    
    cout.width(col_2_width);
    cout.fill(' ');
    cout<<left<<thcol2;
    
    
    cout.width(col_3_width);
    cout.fill(' ');
    cout<<left<<(thcol3);
    cout<<endl;
    
    
    
    for( map<string,int>::iterator itr= this->ethernetUniqueDesAddrMap.begin(); itr!=this->ethernetUniqueDesAddrMap.end(); ++itr)
    {
        cout.width(col_1_width);
        cout.fill(' ');
        cout <<left<<(*itr).first;
        cout.width(col_2_width);
        cout.fill(' ');
        cout<<left<<(*itr).second;
        cout.width(col_3_width);
        cout.fill(' ');
        cout <<setprecision(3)<<(((float)(*itr).second)/this->totalPackets)*100;
        cout<<endl;
        
        
    }
    
    
    
}



void Analyzer::getUniqueARPParticipantsResult()
{
    cout<<"\n\n\n-----------------Unique ARP Participants-----------------\n\n";
    const char *thcol1 = "MAC ADDRESS";
    const char *thcol2 = " / ";
    const char *thcol3 = "IP ADDRESS";
    int col_1_width = (int)strlen(thcol1)+15;
    int col_2_width = (int)strlen(thcol2)+3;
    int col_3_width = (int)strlen(thcol3)+3;
    
    cout.width(col_1_width);
    cout.fill(' ');
    cout <<left<<thcol1;
    
    
    cout.width(col_2_width);
    cout.fill(' ');
    cout<<left<<thcol2;
    
    
    cout.width(col_3_width);
    cout.fill(' ');
    cout<<left<<(thcol3);
    cout<<endl;
    for( map<string,string>::iterator itr= this->arpSrcMacAndIpMap.begin(); itr!=this->arpSrcMacAndIpMap.end(); ++itr)
    {
        cout.width(col_1_width);
        cout.fill(' ');
        cout <<left<<(*itr).first;
        cout.width(col_2_width);
        cout.fill(' ');
        cout<<left<<"/";
        cout.width(col_3_width);
        cout.fill(' ');
        cout<<(*itr).second;
        cout<<endl;
    }
    
    
}

void Analyzer::getUniqueTransportLayerProtocolsResult()
{
    
    
    cout<<"\n\n\n-----------------Transport Layer Protocols-----------------\n\n";
    
    const char *thcol1 = "Protocol Number";
    const char *thcol2 = "Number of packets";
    const char *thcol3 = "Percentage %";
    int col_1_width = (int)strlen(thcol1)+3;
    int col_2_width = (int)strlen(thcol2)+3;
    int col_3_width = (int)strlen(thcol3)+3;
    
    cout.width(col_1_width);
    cout.fill(' ');
    cout <<left<<thcol1;
    
    
    cout.width(col_2_width);
    cout.fill(' ');
    cout<<left<<thcol2;
    
    
    cout.width(col_3_width);
    cout.fill(' ');
    cout<<left<<(thcol3);
    cout<<endl;
    
    for( map<int,int>::iterator itr= this->uniqueTransportLayerProtocolsMap.begin(); itr!=this->uniqueTransportLayerProtocolsMap.end(); ++itr)
    {
        cout.width(col_1_width);
        cout.fill(' ');
        cout <<left<<(*itr).first;
        cout.width(col_2_width);
        cout.fill(' ');
        cout<<left<<(*itr).second;
        cout.width(col_3_width);
        cout.fill(' ');
        cout <<setprecision(3)<<(((float)(*itr).second)/this->totalV4Packets)*100;
        cout<<endl;
    }
    
}

void Analyzer::getUniqueTCPPortsResult()
{
    cout<<"\n\n\n-----------------TCP Source Ports-----------------\n\n";
    const char *thcol1 = "Ports";
    const char *thcol2 = "Number of packets";
    const char *thcol3 = "Percentage %";
    int col_1_width = (int)strlen(thcol1)+15;
    int col_2_width = (int)strlen(thcol2)+3;
    int col_3_width = (int)strlen(thcol3)+3;
    
    cout.width(col_1_width);
    cout.fill(' ');
    cout <<left<<thcol1;
    
    
    cout.width(col_2_width);
    cout.fill(' ');
    cout<<left<<thcol2;
    
    
    cout.width(col_3_width);
    cout.fill(' ');
    cout<<left<<(thcol3);
    cout<<endl;
    for( map<int,int>::iterator itr= this->tcpUniqueSrcPortsMap.begin(); itr!=this->tcpUniqueSrcPortsMap.end(); ++itr)
    {
        cout.width(col_1_width);
        cout.fill(' ');
        cout <<left<<(*itr).first;
        cout.width(col_2_width);
        cout.fill(' ');
        cout<<left<<(*itr).second;
        cout.width(col_3_width);
        cout.fill(' ');
        cout <<setprecision(3)<<(((float)(*itr).second)/this->totalTCPPackets)*100;
        cout<<endl;
    }
    
    
    cout<<"\n\n--------------TCP Destination Port--------------\n\n";
    
    cout.width(col_1_width);
    cout.fill(' ');
    cout <<left<<thcol1;
    
    
    cout.width(col_2_width);
    cout.fill(' ');
    cout<<left<<thcol2;
    
    
    cout.width(col_3_width);
    cout.fill(' ');
    cout<<left<<(thcol3);
    cout<<endl;
    
    
    
    for( map<int,int>::iterator itr= this->tcpUniqueSrcPortsMap.begin(); itr!=this->tcpUniqueSrcPortsMap.end(); ++itr)
    {
        cout.width(col_1_width);
        cout.fill(' ');
        cout <<left<<(*itr).first;
        cout.width(col_2_width);
        cout.fill(' ');
        cout<<left<<(*itr).second;
        cout.width(col_3_width);
        cout.fill(' ');
        cout <<setprecision(3)<<(((float)(*itr).second)/this->totalTCPPackets)*100;
        cout<<endl;
        
        
    }
    
}


void Analyzer::getTCPFlagCombinationsResult()
{
    cout<<"\n\n\n-----------------Flag Combinations in TCP Packets-----------------\n\n";
    
    const char *thcol1 = " FLAG COMBINATIONS";
    const char *thcol2 = "Number of packets";
    const char *thcol3 = "Percentage %";
    int col_1_width = (int)strlen(thcol1)+60;
    int col_2_width = (int)strlen(thcol2)+3;
    int col_3_width = (int)strlen(thcol3)+3;
    
    cout.width(col_1_width);
    cout.fill(' ');
    cout <<left<<thcol1;
    
    
    cout.width(col_2_width);
    cout.fill(' ');
    cout<<left<<thcol2;
    
    
    cout.width(col_3_width);
    cout.fill(' ');
    cout<<left<<(thcol3);
    cout<<endl;
    
    for( map<string,int>::iterator itr= this->tcpUniqueFlagCombinationsMap.begin(); itr!=this->tcpUniqueFlagCombinationsMap.end(); ++itr)
    {
        cout.width(col_1_width);
        cout.fill(' ');
        cout <<left<<(*itr).first;
        cout.width(col_2_width);
        cout.fill(' ');
        cout<<left<<(*itr).second;
        cout.width(col_3_width);
        cout.fill(' ');
        cout <<setprecision(3)<<(((float)(*itr).second)/this->totalTCPPackets)*100;
        cout<<endl;
    }
    
    
}

void Analyzer::getUniqueUDPPortsResult()
{
    cout<<"\n\n\n-----------------UDP Source Ports-----------------\n\n";
    const char *thcol1 = "Ports";
    const char *thcol2 = "Number of packets";
    const char *thcol3 = "Percentage %";
    int col_1_width = (int)strlen(thcol1)+15;
    int col_2_width = (int)strlen(thcol2)+3;
    int col_3_width = (int)strlen(thcol3)+3;
    
    cout.width(col_1_width);
    cout.fill(' ');
    cout <<left<<thcol1;
    
    
    cout.width(col_2_width);
    cout.fill(' ');
    cout<<left<<thcol2;
    
    
    cout.width(col_3_width);
    cout.fill(' ');
    cout<<left<<(thcol3);
    cout<<endl;
    for( map<int,int>::iterator itr= this->udpUniqueSrcPortsMap.begin(); itr!=this->udpUniqueSrcPortsMap.end(); ++itr)
    {
        cout.width(col_1_width);
        cout.fill(' ');
        cout <<left<<(*itr).first;
        cout.width(col_2_width);
        cout.fill(' ');
        cout<<left<<(*itr).second;
        cout.width(col_3_width);
        cout.fill(' ');
        cout <<setprecision(3)<<(((float)(*itr).second)/this->totalUDPPackets)*100;
        cout<<endl;
    }
    
    
    cout<<"\n\n--------------UDP Destination Port--------------\n\n";
    
    cout.width(col_1_width);
    cout.fill(' ');
    cout <<left<<thcol1;
    
    
    cout.width(col_2_width);
    cout.fill(' ');
    cout<<left<<thcol2;
    
    
    cout.width(col_3_width);
    cout.fill(' ');
    cout<<left<<(thcol3);
    cout<<endl;
    
    
    
    for( map<int,int>::iterator itr= this->udpUniqueDesPortsMap.begin(); itr!=this->udpUniqueDesPortsMap.end(); ++itr)
    {
        cout.width(col_1_width);
        cout.fill(' ');
        cout <<left<<(*itr).first;
        cout.width(col_2_width);
        cout.fill(' ');
        cout<<left<<(*itr).second;
        cout.width(col_3_width);
        cout.fill(' ');
        cout <<setprecision(3)<<(((float)(*itr).second)/this->totalUDPPackets)*100;
        cout<<endl;
        
        
    }
    
}


void Analyzer::getTCPOptionsResult()
{
    
    
    cout<<"\n\n\n-----------------TCP  Options-----------------\n\n";
    
    const char *thcol1 = "Option Kind";
    const char *thcol2 = "Number of packets";
    const char *thcol3 = "Percentage %";
    int col_1_width = (int)strlen(thcol1)+3;
    int col_2_width = (int)strlen(thcol2)+3;
    int col_3_width = (int)strlen(thcol3)+3;
    
    cout.width(col_1_width);
    cout.fill(' ');
    cout <<left<<thcol1;
    
    
    cout.width(col_2_width);
    cout.fill(' ');
    cout<<left<<thcol2;
    
    
    cout.width(col_3_width);
    cout.fill(' ');
    cout<<left<<(thcol3);
    cout<<endl;
    
    for( map<int,int>::iterator itr= this->tcpUniqueTCPOptionsMap.begin(); itr!=this->tcpUniqueTCPOptionsMap.end(); ++itr)
    {
        cout.width(col_1_width);
        cout.fill(' ');
        cout <<left<<(*itr).first;
        cout.width(col_2_width);
        cout.fill(' ');
        cout<<left<<(*itr).second;
        cout.width(col_3_width);
        cout.fill(' ');
        cout <<setprecision(3)<<(((float)(*itr).second)/this->totalTCPPackets)*100;
        cout<<endl;
    }
    
}



void Analyzer::getICMPTypeCodeResult()
{
    
    
    
    cout<<"\n\n\n-----------------ICMP  Types and Code-----------------\n\n";
    
    const char *thcol1 = "Type";
    const char *thcol2 = "Code";
    const char *thcol3 = "Number of packets";
    const char *thcol4 = "Percentage %";
    int col_1_width = (int)strlen(thcol1)+3;
    int col_2_width = (int)strlen(thcol2)+3;
    int col_3_width = (int)strlen(thcol3)+3;
    int col_4_width = (int)strlen(thcol4)+3;
    
    cout.width(col_1_width);
    cout.fill(' ');
    cout <<left<<thcol1;
    
    
    cout.width(col_2_width);
    cout.fill(' ');
    cout<<left<<thcol2;
    
    
    cout.width(col_3_width);
    cout.fill(' ');
    cout<<left<<(thcol3);
    
    cout.width(col_4_width);
    cout.fill(' ');
    cout<<left<<(thcol4);
    
    
    cout<<endl;
    
    for( map<int,map<int,int>>::iterator itr= this->icmpTypeCodeMap.begin(); itr!=this->icmpTypeCodeMap.end(); ++itr)
    {
        
        
        map<int,int> codeCntMap = (*itr).second;
        cout.width(col_1_width);
        cout.fill(' ');
        cout <<left<<(*itr).first;
        
        for(map<int,int>::iterator innerItr = codeCntMap.begin(); innerItr!=codeCntMap.end(); ++innerItr)
        {
            
            cout.width(col_2_width);
            cout.fill(' ');
            cout<<left<<(*innerItr).first;
            
            cout.width(col_3_width);
            cout.fill(' ');
            cout<<left<<(*innerItr).second;
            
            
            cout.width(col_4_width);
            cout.fill(' ');
            cout<<setprecision(4)<<(((float)(*innerItr).second)/this->totalICMPPackets)*100;
            cout<<endl;

            
            
        }
    }
    
}


//void Analyzer::getARPSrcMACIPResult()
//{
//    
//    
//    
//    cout<<"\n\n\n-----------------ARP  Source MAC and IP address-----------------\n\n";
//    
//    const char *thcol1 = "MAC Address";
//    const char *thcol2 = "IP  Address";
//    const char *thcol3 = "Number of packets";
//    const char *thcol4 = "Percentage %";
//    int col_1_width = (int)strlen(thcol1)+10;
//    int col_2_width = (int)strlen(thcol2)+10;
//    int col_3_width = (int)strlen(thcol3)+3;
//    int col_4_width = (int)strlen(thcol4)+3;
//    
//    cout.width(col_1_width);
//    cout.fill(' ');
//    cout <<left<<thcol1;
//    
//    
//    cout.width(col_2_width);
//    cout.fill(' ');
//    cout<<left<<thcol2;
//    
//    
//    cout.width(col_3_width);
//    cout.fill(' ');
//    cout<<left<<(thcol3);
//    
//    cout.width(col_4_width);
//    cout.fill(' ');
//    cout<<left<<(thcol4);
//    
//    
//    cout<<endl;
//    
//    for( map<string,map<string,int>>::iterator itr= this->arpSrcMacIpCntMap.begin(); itr!=this->arpSrcMacIpCntMap.end(); ++itr)
//    {
//        
//        
//        map<string,int> codeCntMap = (*itr).second;
//        cout.width(col_1_width);
//        cout.fill(' ');
//        cout <<left<<(*itr).first;
//        
//        for(map<string,int>::iterator innerItr = codeCntMap.begin(); innerItr!=codeCntMap.end(); ++innerItr)
//        {
//            
//            cout.width(col_2_width);
//            cout.fill(' ');
//            cout<<left<<(*innerItr).first;
//            
//            cout.width(col_3_width);
//            cout.fill(' ');
//            cout<<left<<(*innerItr).second;
//            
//            
//            cout.width(col_4_width);
//            cout.fill(' ');
//            cout<<setprecision(4)<<(((float)(*innerItr).second)/this->totalARPPackets)*100;
//            cout<<endl;
//            
//            
//            
//        }
//    }
//    
//}



void Analyzer::getICMPSrcIPResult()
{
    cout<<"\n\n\n-----------------ICMP Source IP address-----------------\n\n";
    
    const char *thcol1 = "IP Address";
    const char *thcol2 = "Number of packets";
    const char *thcol3 = "Percentage %";
    int col_1_width = (int)strlen(thcol1)+10;
    int col_2_width = (int)strlen(thcol2)+3;
    int col_3_width = (int)strlen(thcol3)+3;
    
    cout.width(col_1_width);
    cout.fill(' ');
    cout <<left<<thcol1;
    
    
    cout.width(col_2_width);
    cout.fill(' ');
    cout<<left<<thcol2;
    
    
    cout.width(col_3_width);
    cout.fill(' ');
    cout<<left<<(thcol3);
    cout<<endl;
    
    for( map<string,int>::iterator itr= this->icmpUniqueSrcAddressMap.begin(); itr!=this->icmpUniqueSrcAddressMap.end(); ++itr)
    {
        cout.width(col_1_width);
        cout.fill(' ');
        cout <<left<<(*itr).first;
        cout.width(col_2_width);
        cout.fill(' ');
        cout<<left<<(*itr).second;
        cout.width(col_3_width);
        cout.fill(' ');
        cout <<setprecision(3)<<(((float)(*itr).second)/this->totalICMPPackets)*100;
        cout<<endl;
    }
    
    
    
}


void Analyzer::getICMPDesIPResult()
{
    cout<<"\n\n\n-----------------ICMP Destination IP address-----------------\n\n";
    
    const char *thcol1 = "IP Address";
    const char *thcol2 = "Number of packets";
    const char *thcol3 = "Percentage %";
    int col_1_width = (int)strlen(thcol1)+10;
    int col_2_width = (int)strlen(thcol2)+3;
    int col_3_width = (int)strlen(thcol3)+3;
    
    cout.width(col_1_width);
    cout.fill(' ');
    cout <<left<<thcol1;
    
    
    cout.width(col_2_width);
    cout.fill(' ');
    cout<<left<<thcol2;
    
    
    cout.width(col_3_width);
    cout.fill(' ');
    cout<<left<<(thcol3);
    cout<<endl;
    
    for( map<string,int>::iterator itr= this->icmpUniqueDesAddressMap.begin(); itr!=this->icmpUniqueDesAddressMap.end(); ++itr)
    {
        cout.width(col_1_width);
        cout.fill(' ');
        cout <<left<<(*itr).first;
        cout.width(col_2_width);
        cout.fill(' ');
        cout<<left<<(*itr).second;
        cout.width(col_3_width);
        cout.fill(' ');
        cout <<setprecision(3)<<(((float)(*itr).second)/this->totalICMPPackets)*100;
        cout<<endl;
    }
    
    
    
}



void Analyzer::analyzeIPHeader(struct ip *kHeader)
{
    
    
    srcDesIpv4 srcDest = getIpPairForIpHeader(kHeader);
    
    string srcIp = srcDest.src;
    string desIp = srcDest.des;
    
    int cnt = this->ipUniqueSrcAddrMap[srcIp];
    this->ipUniqueSrcAddrMap[srcIp] = cnt + 1;
    
    cnt = this->ipUniqueDesAddrMap[desIp];
    this->ipUniqueDesAddrMap[desIp] = cnt + 1;
    
    int ttl = (unsigned int)kHeader->ip_ttl;
    cnt = this->ipUniqueTTLMap[ttl];
    this->ipUniqueTTLMap[ttl] = cnt+1;
    
    int protoNumber = (unsigned int)kHeader->ip_p;
    cnt = this->uniqueTransportLayerProtocolsMap[protoNumber];
    this->uniqueTransportLayerProtocolsMap[protoNumber] = cnt+1;
    cout<<" ";
    //get source address
    //get destination address
}



void Analyzer::analyzeTCPHeader(struct tcphdr *kHeader)
{
    
    int srcPort = ntohs(kHeader->th_sport);
    int desPort = ntohs(kHeader->th_dport);
    string flags = getFlagCombinationForTCPHeader(kHeader);
    
    
    int cnt = this->tcpUniqueSrcPortsMap[srcPort];
    this->tcpUniqueSrcPortsMap[srcPort]=cnt+1;
    
    cnt = this->tcpUniqueDesPortsMap[desPort];
    this->tcpUniqueDesPortsMap[desPort]=cnt+1;
    
    cnt = this->tcpUniqueFlagCombinationsMap[flags];
    this->tcpUniqueFlagCombinationsMap[flags] = cnt+1;
    
}

void Analyzer::analyzeUDPHeader(struct udphdr *kHeader)
{
    int sport = ntohs(kHeader->uh_sport);
    int dport = ntohs(kHeader->uh_dport);
    
    int cnt = this->udpUniqueSrcPortsMap[sport];
    this->udpUniqueSrcPortsMap[sport] = cnt+1;
    
    cnt = this->udpUniqueDesPortsMap[dport];
    this->udpUniqueDesPortsMap[dport]=cnt+1;
    
    
}



bool Analyzer::startAnalyzing()
{
    char errBuff[PCAP_ERRBUF_SIZE];
    this->handle = pcap_open_offline((const char*)this->pcapFile.c_str(),errBuff);
    
    struct pcap_pkthdr header;
    const u_char *packet;
    int totalPackets=0;
    int minPacketSize=999999999;
    int maxPacketSize=0;
    int avgPacketSize=0;
    while ((packet = pcap_next(handle, &header))!=NULL) {
        totalPackets++;
        
        int pckSize = header.len;
        if(pckSize<minPacketSize)
            minPacketSize = pckSize;
        if(pckSize>maxPacketSize)
            maxPacketSize = pckSize;
        avgPacketSize = (avgPacketSize*(totalPackets-1) + pckSize)/totalPackets;
        
        
        struct ether_header *ethernet_header = (struct ether_header*)packet;
        this->analyzeEthernetHeader(ethernet_header);
        
        if(ntohs(ethernet_header->ether_type) == ETHERTYPE_IP)
        {
            struct ip *ip_header = (struct ip*)(packet + sizeof(struct ether_header));
            //logIpHeader(ip_header, 1, 1);
            this->analyzeIPHeader(ip_header);
            this->totalV4Packets++;
            
            
            
            if((unsigned int)ip_header->ip_p == IPPROTO_TCP )
            {
                struct tcphdr *tcp = (struct tcphdr*)(packet + 34);
                //logTCPHeader(tcp);
                
                //cout<<"\n";
                int numberOfBytesOfTCPHeader = (unsigned int)tcp->th_off*4;
                int totalOptionBytes= numberOfBytesOfTCPHeader-20;
                u_char *c = (u_char *)(packet + 54);
                set<int> allOpts;
                
                while(totalOptionBytes>1)
                {
                    u_int length;
                    u_int opt = *c;
                    allOpts.insert(opt);
                    if(opt!=1)
                        length = *(c+1);
                    else
                        length = 1;
                    // cout<<" ["<<opt<<"] ";
                    
                    c = (c+length);
                    
                    totalOptionBytes-=length;
                }
                //set options counts
                set<int>::iterator itr;
                for(itr=allOpts.begin(); itr!=allOpts.end(); itr++)
                {
                    
                    int cnt = this->tcpUniqueTCPOptionsMap[*itr];
                    this->tcpUniqueTCPOptionsMap[*itr] =cnt+1;
                }
                
                //cout<<"\n";
                this->analyzeTCPHeader(tcp);
                this->totalTCPPackets++;
            }
            else if((unsigned int)ip_header->ip_p == IPPROTO_UDP)
            {
                struct udphdr *udp = (struct udphdr*)(packet +sizeof(struct ether_addr) + sizeof(struct ip));
                this->analyzeUDPHeader(udp);
                this->totalUDPPackets++;
                //logUDPHeader(udp);
            }
            else if((unsigned int)ip_header->ip_p == IPPROTO_ICMP)
            {
                
                struct icmp *icmpHdr = (struct icmp*)(packet +34);
                int type = (unsigned int)icmpHdr->icmp_type;
                int code = (unsigned int)icmpHdr->icmp_code;
                map<int,int> icmpCodeCntMap = this->icmpTypeCodeMap[type];
                int cnt = icmpCodeCntMap[code];
                icmpCodeCntMap[code] = cnt+1;
                this->icmpTypeCodeMap[type] = icmpCodeCntMap;
                this->totalICMPPackets++;
                
                struct ip *innerIP = (struct ip*)(packet+ 8+14+20);
                //logIpHeader(innerIP, 1, 1);
                
                srcDesIpv4 srcDest = getIpPairForIpHeader(innerIP);
                
                string srcIp = srcDest.src;
                string desIp = srcDest.des;
                
                 cnt = this->icmpUniqueSrcAddressMap[srcIp];
                this->icmpUniqueSrcAddressMap[srcIp] = cnt + 1;
                
                cnt = this->icmpUniqueDesAddressMap[desIp];
                this->icmpUniqueDesAddressMap[desIp] = cnt + 1;

                
                cout<<"";
            }
        }
        
        typedef struct kArp
        {
            u_int16_t hardwareType;
            u_int16_t protocolType;
            u_char hardwareSize;
            u_char protocolSize;
            u_int16_t opCode;
            u_char srcMac[ETHER_ADDR_LEN];
            u_char srcIp[4];
            u_char desMac[ETHER_ADDR_LEN];
            u_char desIp[4];


        };
        
        
        //if header is arp
        if(ntohs(ethernet_header->ether_type) == ETHERTYPE_ARP)
        {
//            cout<<"\n Got ARP Packet";
//            cout<<" ";
            
            kArp *arpHdr = (struct kArp*)(packet+14);
//            cout<<ntohs(arpHdr->hardwareType)<<" 0x"<<hex<<ntohs(arpHdr->protocolType)<<" "<<(unsigned int)arpHdr->hardwareSize;
//            cout<<" "<<(unsigned int)arpHdr->protocolSize<<" "<<ntohs(arpHdr->opCode);

            struct ether_header srcMacAddr;
            memcpy(srcMacAddr.ether_shost, arpHdr->srcMac,ETHER_ADDR_LEN);
            string srcMACaddrStr = getEthSourceAddress(&srcMacAddr);
//            cout<<" "<<srcMACaddrStr;

            char buffer[15];
            sprintf(buffer,"%d.",(unsigned int)(arpHdr->srcIp[0]));
            sprintf(buffer,"%s%d.",buffer,(unsigned int)(arpHdr->srcIp[1]));
            sprintf(buffer,"%s%d.",buffer,(unsigned int)(arpHdr->srcIp[2]));
            sprintf(buffer,"%s%d",buffer,(unsigned int)(arpHdr->srcIp[3]));
//            cout<<" "<<buffer;
            
            
//            map<string,int> srcIpCntMap = this->arpSrcMacIpCntMap[srcMACaddrStr];
//            int cnt = srcIpCntMap[buffer];
//            srcIpCntMap[buffer] = cnt+1;
//            this->arpSrcMacIpCntMap[srcMACaddrStr] = srcIpCntMap;
            
            
            
            struct ether_header desMacAddr;
            memcpy(desMacAddr.ether_dhost, arpHdr->desMac,ETHER_ADDR_LEN);
            string desMacAddrStr = getEthDestinationAddress(&desMacAddr);
//            cout<<" "<<desMacAddrStr;

            char desIpbuffer[15];
            sprintf(desIpbuffer,"%d.",(unsigned int)(arpHdr->desIp[0]));
            sprintf(desIpbuffer,"%s%d.",desIpbuffer,(unsigned int)(arpHdr->desIp[1]));
            sprintf(desIpbuffer,"%s%d.",desIpbuffer,(unsigned int)(arpHdr->desIp[2]));
            sprintf(desIpbuffer,"%s%d",desIpbuffer,(unsigned int)(arpHdr->desIp[3]));
//            cout<<" "<<desIpbuffer;

            
            
            this->arpSrcMacAndIpMap[srcMACaddrStr] = buffer;
            this->arpSrcMacAndIpMap[desMacAddrStr] = desIpbuffer;
//            cout<<" ";
            this->totalARPPackets++;


            
        }
        
        
        
    }
    
    this->totalPackets = totalPackets;
    this->minPacketSize = minPacketSize;
    this->maxPacketSize = maxPacketSize;
    this->avgPacketSize = avgPacketSize;
    
    return (this->handle!=NULL)?true:false;
    
    
}
