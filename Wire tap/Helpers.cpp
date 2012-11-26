//
//  Helpers.cpp
//  Wiretap
//
//  Created by Abhineet on 09/11/12.
//  Copyright (c) 2012 Abhineet. All rights reserved.
//

#include "Helpers.h"



srcDesIpv4 getIpPairForIpHeader(struct ip *kIpHdr)
{
    
    srcDesIpv4 ipPair;
    char src[INET_ADDRSTRLEN];
    char des[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &kIpHdr->ip_src, src, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &kIpHdr->ip_dst, des, INET_ADDRSTRLEN);
    strcpy(ipPair.src, src);
    strcpy(ipPair.des, des);
    
    return ipPair;
}

string getEthSourceAddress(struct ether_header *kHeader)
{
    
    string addr;
    struct ether_addr src_eth;
    memset(&src_eth, 0, sizeof(struct ether_addr));
    memcpy(src_eth.octet, (const char*)kHeader->ether_shost,sizeof(kHeader->ether_shost));
    char *src_link_addr;
    src_link_addr = ether_ntoa(&src_eth);
    addr = src_link_addr;
    return addr;

}

string getEthDestinationAddress(struct ether_header *kHeader)
{
    string addr;
    struct ether_addr des_eth;
    memset(&des_eth, 0, sizeof(struct ether_addr));
    memcpy(des_eth.octet, (const char*)kHeader->ether_dhost,sizeof(kHeader->ether_dhost));
    char *des_link_addr;
    des_link_addr = ether_ntoa(&des_eth);
    addr = des_link_addr;
    return addr;
}



void logIpHeader(struct ip *kIpHdr, int tabs, int nxtline)
{
    while (nxtline>0) {
        cout<<"\n";
        nxtline--;
    }
    while (tabs>0) {
        cout<<"-";
        tabs--;
    }
    
    char src[INET_ADDRSTRLEN];
    char des[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &kIpHdr->ip_src, src, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &kIpHdr->ip_dst, des, INET_ADDRSTRLEN);
    cout<<"IP  "<<" | src-> "<<src
    <<" | des-> "<<des
    <<" | total length-> "<<ntohs(kIpHdr->ip_len)
    <<" | protocol-> "<<(unsigned int)kIpHdr->ip_p
    <<" | header length-> "<<(kIpHdr->ip_hl);
}

void logEthernetHeader(struct ether_header *ehdr, int tabs, int nxtline)
{
    while (nxtline>0) {
        cout<<"\n";
        nxtline--;
    }
    while (tabs>0) {
        cout<<"-";
        tabs--;
    }
    
    struct ether_addr src_eth, des_eth;
    
    memset(&src_eth, 0, sizeof(struct ether_addr));
    memset(&des_eth, 0, sizeof(struct ether_addr));
    
    memcpy(src_eth.octet, (const char*)ehdr->ether_shost,sizeof(ehdr->ether_shost));
    memcpy(des_eth.octet, (const char*)ehdr->ether_dhost,sizeof(ehdr->ether_dhost));
    
    char *src_link_addr,*des_link_addr;
    src_link_addr = ether_ntoa(&src_eth);
    des_link_addr = ether_ntoa(&des_eth);
    
    
    cout<<"EHTERNET  | SRC -> "<<src_link_addr<<" | DES -> "<<des_link_addr<<" | TYPE -> "<<ntohs(ehdr->ether_type);


    
}


string getFlagCombinationForTCPHeader(struct tcphdr *kHeader)
{
    string flags;
    /*
     TH_FIN
     TH_SYN
     TH_RST
     TH_PUSH
     TH_ACK
     TH_URG
     TH_ECE
     TH_CWR
     */
    
    if (kHeader->th_flags & TH_FIN)
        flags.append(" TH_FIN ");
    if(kHeader->th_flags & TH_SYN)
        flags.append(" TH_SYN ");
    if(kHeader->th_flags & TH_RST)
        flags.append(" TH_RST ");
    if (kHeader->th_flags & TH_PUSH)
        flags.append(" TH_PUSH ");
    if (kHeader->th_flags & TH_ACK)
        flags.append(" TH_ACK ");
    if (kHeader->th_flags & TH_URG)
        flags.append(" TH_URG ");
    if (kHeader->th_flags & TH_ECE)
        flags.append(" TH_ECE ");
    if (kHeader->th_flags & TH_CWR)
        flags.append(" TH_CWR ");

    
    return flags;
    
}

void logTCPHeader(struct tcphdr *kHeader){
    cout<<"\nTCP  |SOURCE PORT: "<<ntohs(kHeader->th_sport)
    <<" |DESTINATION PORT: "<<ntohs(kHeader->th_dport)
    <<" |FLAGS: ";
    if (kHeader->th_flags & TH_SYN)
        putchar('S');
    if(kHeader->th_flags & TH_ACK)
        putchar('.');
    if(kHeader->th_flags & TH_FIN)
        putchar('F');
    if (kHeader->th_flags & TH_RST)
        putchar('R');
    
    
    cout<<" |ACK :"<<(unsigned int)ntohl(kHeader->th_ack)
    <<" |SEQ :"<<ntohl(kHeader->th_seq)<<endl;
    
}

void logUDPHeader(struct udphdr *header)
{
    cout<<"\nUDP |src port: "<<ntohs(header->uh_sport)<<" |des port: "<<ntohs(header->uh_dport);
}