//
//  Analyzer.cpp
//  Wiretap
//
//  Created by Abhineet on 10/11/12.
//  Copyright (c) 2012 Abhineet. All rights reserved.
//

#include "Analyzer.h"

#define NO_RESULT cout<<"\n[no result]\n";

Analyzer::Analyzer()
{
    //initialize
}


Analyzer::Analyzer(string kFile)
{
    cout<<"\nFile to scan: "<<kFile;
    this->pcapFile = kFile;
    
    this->totalARPPackets=0;
    this->totalTCPPackets=0;
    
    
    this->totalICMPPackets=0;
    this->totalUDPPackets=0;
    
    
    this->totalV6Packets=0;
    this->totalV4Packets=0;
    
    this->totalPackets=0;
    this->minPacketSize=0;
    this->maxPacketSize=0;
    
    this->avgPacketSize=0.0;
    this->diff=0.0;
    
    
    
    
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
    cout<<"\n Start date          : "<<this->startTime;
    cout<<"\n Duration(seconds)   : "<<this->diff;
    cout<<"\n Total Packets       : "<<this->totalPackets;
    cout<<"\n Maximum Packet Size : "<<this->maxPacketSize;
    cout<<"\n Minimum Packet Size : "<<this->minPacketSize;
    cout<<"\n Average Packet Size : "<<this->avgPacketSize;
}


void Analyzer::getUniqueNetworkLayerProtoclsResult()
{
    
    cout<<"\n\n-----------------Network Layer Protocols-----------------\n";
    
    if(this->uniqueNetworkLayerProtocolsMap.size()==0)
    {
        NO_RESULT
    }
    else
    {
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
            if((*itr).first == ETHERTYPE_IP)
                cout <<left<<"IP";
            else if((*itr).first == ETHERTYPE_ARP)
                cout <<left<<"ARP";
            else if((*itr).first <= 1536)
            {
                char buff[50];
                sprintf(buff, "*Length = %d",(*itr).first);
                cout<<left<<buff;
                
            }
            else
                cout<<left<<(*itr).first;
            
            
            cout.width(col_2_width);
            cout.fill(' ');
            cout<<left<<(*itr).second;
            cout.width(col_3_width);
            cout.fill(' ');
            cout<<(((float)(*itr).second)/this->totalPackets)*100;
            cout<<endl;
        }
        
        
    }
    
    
    
    
}


void Analyzer::getUniqueSrcIPResult()
{
    cout<<"\n\n-----------------Source IP address-----------------\n";
    
    if(this->ipUniqueSrcAddrMap.size()==0)
    {
        NO_RESULT
    }
    else
    {
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
            cout <<(((float)(*itr).second)/this->totalV4Packets)*100;
            cout<<endl;
        }
        
        
    }
    
    
    
    
}


void Analyzer::getUniqueTTLResult()
{
    cout<<"\n\n-----------------TTLs in IP Packets-----------------\n";
    
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
        cout <<(((float)(*itr).second)/this->totalV4Packets)*100;
        cout<<endl;
    }
    
    
}


void Analyzer::getUniqueDesIPResult()
{
    cout<<"\n\n-----------------Destination IP Address-----------------\n";
    
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
        cout <<(((float)(*itr).second)/this->totalV4Packets)*100;
        cout<<endl;
    }
    
    
    
}




void Analyzer::getUniqueEtherAddressResult()
{
    cout<<"\n\n-----------------Source Ethernet Address-----------------\n";
    const char *thcol1 = "MAC Address";
    const char *thcol2 = "Number of packets";
    const char *thcol3 = "Percentage %";
    int col_1_width = (int)strlen(thcol1)+15;
    int col_2_width = (int)strlen(thcol2)+3;
    int col_3_width = (int)strlen(thcol3)+3;
    
    
    if(this->ethernetUniqueSrcAddrMap.size()==0)
    {
        NO_RESULT
    }
    else
    {
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
            cout <<(((float)(*itr).second)/this->totalPackets)*100;
            cout<<endl;
        }
        
        
    }
    
    
    
    
    cout<<"\n\n--------------Destination Ethernet Address--------------\n";
    
    if(this->ethernetUniqueDesAddrMap.size()==0 )
    {
        NO_RESULT
    }
    else
    {
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
            cout <<(((float)(*itr).second)/this->totalPackets)*100;
            cout<<endl;
            
            
        }
        
        
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
    
    
    if(this->arpSrcMacAndIpMap.size()==0)
    {
        NO_RESULT
    }
    else
    {
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
    
    
    
}

void Analyzer::getUniqueTransportLayerProtocolsResult()
{
    
    
    cout<<"\n\n-----------------Transport Layer Protocols-----------------\n\n";
    
    const char *thcol1 = "Protocol Number";
    const char *thcol2 = "Number of packets";
    const char *thcol3 = "Percentage %";
    int col_1_width = (int)strlen(thcol1)+3;
    int col_2_width = (int)strlen(thcol2)+3;
    int col_3_width = (int)strlen(thcol3)+3;
    
    
    if(this->uniqueTransportLayerProtocolsMap.size()==0)
    {
        NO_RESULT
    }
    else
    {
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
            if((*itr).first == IPPROTO_TCP)
                cout <<left<<"TCP";
            else if((*itr).first == IPPROTO_UDP)
                cout <<left<<"UDP";
            else if((*itr).first == IPPROTO_ICMP)
                cout <<left<<"ICMP";
            else
                cout <<left<<(*itr).first;
            
            
            
            cout.width(col_2_width);
            cout.fill(' ');
            cout<<left<<(*itr).second;
            cout.width(col_3_width);
            cout.fill(' ');
            cout <<(((float)(*itr).second)/this->totalV4Packets)*100;
            cout<<endl;
        }
        
        
    }
    
    
}

void Analyzer::getUniqueTCPPortsResult()
{
    
    cout<<"\n=== Transport layer: TCP ===\n";
    
    cout<<"\n\n-----------------TCP Source Ports-----------------\n\n";
    const char *thcol1 = "Ports";
    const char *thcol2 = "Number of packets";
    const char *thcol3 = "Percentage %";
    int col_1_width = (int)strlen(thcol1)+15;
    int col_2_width = (int)strlen(thcol2)+3;
    int col_3_width = (int)strlen(thcol3)+3;
    
    
    if(this->tcpUniqueSrcPortsMap.size()==0)
    {
        NO_RESULT
    }
    else
    {
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
            cout <<(((float)(*itr).second)/this->totalTCPPackets)*100;
            cout<<endl;
        }
        
        
    }
    
    
    cout<<"\n\n--------------TCP Destination Port--------------\n\n";
    
    if(this->tcpUniqueDesPortsMap.size()==0)
    {
        NO_RESULT
    }
    else
    {
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
        
        
        
        for( map<int,int>::iterator itr= this->tcpUniqueDesPortsMap.begin(); itr!=this->tcpUniqueDesPortsMap.end(); ++itr)
        {
            cout.width(col_1_width);
            cout.fill(' ');
            cout <<left<<(*itr).first;
            cout.width(col_2_width);
            cout.fill(' ');
            cout<<left<<(*itr).second;
            cout.width(col_3_width);
            cout.fill(' ');
            cout <<(((float)(*itr).second)/this->totalTCPPackets)*100;
            cout<<endl;
            
            
        }
        
        
    }
    
    
    
}


void Analyzer::getTCPFlagCombinationsResult()
{
    cout<<"\n\n-----------------Flag Combinations in TCP Packets-----------------\n\n";
    
    if(this->tcpUniqueFlagCombinationsMap.size()==0)
    {
        NO_RESULT
    }
    else
    {
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
            cout <<(((float)(*itr).second)/this->totalTCPPackets)*100;
            cout<<endl;
        }
        
        
    }
    
    
    
    
    
}

void Analyzer::getUniqueUDPPortsResult()
{
    cout<<"\n\n-----------------UDP Source Ports-----------------\n\n";
    const char *thcol1 = "Ports";
    const char *thcol2 = "Number of packets";
    const char *thcol3 = "Percentage %";
    int col_1_width = (int)strlen(thcol1)+15;
    int col_2_width = (int)strlen(thcol2)+3;
    int col_3_width = (int)strlen(thcol3)+3;
    
    
    if(this->udpUniqueSrcPortsMap.size()==0)
    {
        NO_RESULT
    }
    else
    {
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
            cout <<(((float)(*itr).second)/this->totalUDPPackets)*100;
            cout<<endl;
        }
        
        
    }
    
    
    
    cout<<"\n\n--------------UDP Destination Port--------------\n\n";
    
    
    if(this->udpUniqueDesPortsMap.size()==0)
    {
        NO_RESULT
    }
    else
    {
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
            cout <<(((float)(*itr).second)/this->totalUDPPackets)*100;
            cout<<endl;
            
            
        }
        
        
    }
    
    
}


void Analyzer::getTCPOptionsResult()
{
    
    
    cout<<"\n\n-----------------TCP  Options-----------------\n\n";
    
    if(this->tcpUniqueTCPOptionsMap.size()==0)
    {
        NO_RESULT
    }
    else
    {
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
            cout <<(((float)(*itr).second)/this->totalTCPPackets)*100;
            cout<<endl;
        }
        
    }
    
    
}



void Analyzer::getICMPTypeCodeResult()
{
    
    cout<<"\n\n-----------------ICMP Types-----------------\n\n";
    const char *thcol1 = "Type";
    const char *thcol2 = "Number of packets";
    const char *thcol3 = "Percentage %";
    int col_1_width = (int)strlen(thcol1)+15;
    int col_2_width = (int)strlen(thcol2)+3;
    int col_3_width = (int)strlen(thcol3)+3;
    
    
    if(this->icmpTypeMap.size()==0)
    {
        NO_RESULT
    }
    else
    {
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
        for( map<int,int>::iterator itr= this->icmpTypeMap.begin(); itr!=this->icmpTypeMap.end(); ++itr)
        {
            cout.width(col_1_width);
            cout.fill(' ');
            cout <<left<<(*itr).first;
            cout.width(col_2_width);
            cout.fill(' ');
            cout<<left<<(*itr).second;
            cout.width(col_3_width);
            cout.fill(' ');
            cout <<(((float)(*itr).second)/this->totalICMPPackets)*100;
            cout<<endl;
        }
        
        
    }
    
    
    
    cout<<"\n\n--------------ICMP codes--------------\n\n";
    
    
    if(this->icmpCodeMap.size()==0)
    {
        NO_RESULT
    }
    else
    {
        const char *thcol1 = "Code";
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
        
        
        
        for( map<int,int>::iterator itr= this->icmpCodeMap.begin(); itr!=this->icmpCodeMap.end(); ++itr)
        {
            cout.width(col_1_width);
            cout.fill(' ');
            cout <<left<<(*itr).first;
            cout.width(col_2_width);
            cout.fill(' ');
            cout<<left<<(*itr).second;
            cout.width(col_3_width);
            cout.fill(' ');
            cout <<(((float)(*itr).second)/this->totalICMPPackets)*100;
            cout<<endl;
            
            
        }
        
        
    }
    
    
}





void Analyzer::getICMPSrcIPResult()
{
    cout<<"\n\n-----------------ICMP Source IP address-----------------\n\n";
    
    
    if(this->icmpUniqueSrcAddressMap.size()==0)
    {
        NO_RESULT;
    }else
    {
        
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
            cout<<setprecision(2)<<(((float)(*itr).second)/this->totalICMPPackets)*100;
            cout<<endl;
        }
        
    }
    
    
    
}


void Analyzer::getICMPDesIPResult()
{
    cout<<"\n\n-----------------ICMP Destination IP address-----------------\n\n";
    
    if(this->icmpUniqueDesAddressMap.size()==0)
    {
        NO_RESULT;
    }
    else{
        
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
            cout <<(((float)(*itr).second)/this->totalICMPPackets)*100;
            cout<<endl;
        }
        
        
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
    
    if(this->handle==NULL)
    {
        
        fprintf(stderr,"%s",errBuff);
        exit(1);
    }
    
    struct pcap_pkthdr header;
    const u_char *packet;
    int totalPackets=0;
    int minPacketSize=999999999;
    int maxPacketSize=0;
    double avgPacketSize=0;
    while ((packet = pcap_next(handle, &header))!=NULL) {
        totalPackets++;
        this->timestamps.insert(header.ts.tv_sec);
        
        
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
                struct udphdr *udp = (struct udphdr*)(packet + 34);
                this->analyzeUDPHeader(udp);
                this->totalUDPPackets++;
                //logUDPHeader(udp);
            }
            else if((unsigned int)ip_header->ip_p == IPPROTO_ICMP)
            {
                
                struct icmp *icmpHdr = (struct icmp*)(packet +34);
                int type = (unsigned int)icmpHdr->icmp_type;
                int code = (unsigned int)icmpHdr->icmp_code;
                //                map<int,int> icmpCodeCntMap = this->icmpTypeCodeMap[type];
                //                int cnt = icmpCodeCntMap[code];
                //                icmpCodeCntMap[code] = cnt+1;
                //                this->icmpTypeCodeMap[type] = icmpCodeCntMap;
                
                
                int cnt = this->icmpCodeMap[code];
                this->icmpCodeMap[code] = cnt+1;
                
                cnt = this->icmpTypeMap[type];
                this->icmpTypeMap[type] = cnt+1;
                
                
                this->totalICMPPackets++;
                
                struct ip *innerIP = (struct ip*)(packet+14);
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
        
        typedef struct ArpStructure
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
            
            
        }kArp;
        
        
        //if header is arp
        if(ntohs(ethernet_header->ether_type) == ETHERTYPE_ARP)
        {
            //            cout<<"\n Got ARP Packet";
            //            cout<<" ";
            
            kArp *arpHdr = ( kArp*)(packet+14);
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
            
            
            //               if(strcmp((const char *)buffer,(const char *)"129.79.247.6")==0)
            //               {
            //                   cout<<" ";
            //               }
            //
            //            if(strcmp((const char *)desIpbuffer,(const char *)"129.79.247.6")==0)
            //            {
            //                cout<<" ";
            //            }
            //
            
            
            if(!isBroadCastEtherAddress(srcMACaddrStr))
            {
                this->arpSrcMacAndIpMap[srcMACaddrStr] = buffer;
                
            }
            if(!isBroadCastEtherAddress(desMacAddrStr))
            {
                this->arpSrcMacAndIpMap[desMacAddrStr] = desIpbuffer;
                
            }
            
            this->totalARPPackets++;
            
            //            cout<<" ";
            
            
            
        }
        
        
        
    }
    
    this->totalPackets = totalPackets;
    this->minPacketSize = minPacketSize;
    this->maxPacketSize = maxPacketSize;
    this->avgPacketSize = avgPacketSize;
    
    
    
    pcap_close(this->handle);
    
    set<long>::iterator theItr;
    theItr = this->timestamps.begin();
    long start = *theItr;
    theItr = this->timestamps.end();
    --theItr;
    long end = *theItr;
    
    time_t start_Time = (time_t)(start);
    strftime(this->startTime, 20, "%Y-%m-%d %H:%M:%S", localtime(&start_Time));
    
    
    time_t end_Time = (time_t)(end);
    strftime(this->endTime, 20, "%Y-%m-%d %H:%M:%S", localtime(&end_Time));
    
    
    
    this->diff = difftime (end_Time,start_Time);
    
    
    return (this->handle!=NULL)?true:false;
    
    
}
