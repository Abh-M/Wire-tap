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
    
    
    if(argc!=2)
    {
        fprintf(stderr, "Invalid number of arguments \nQuitting.....");
        exit(1);
    }
    else
    {
        
        
        //check if file is pcap file
        char name[strlen(argv[1])];
        strcpy(name, argv[1]);
        
        const char *seperator = ".";
        char *token;
        token = strtok(name,seperator);
        char *parts[10];
        
        int index =0;
        
        
        while (token != NULL)
        {
            parts[index++]=token;
            token = strtok (NULL,seperator);
            
        }
        
        //        cout<<parts[index-1];
        
        if(strcmp(parts[index-1],"pcap")==0)
        {
            
            string pathToFile("/Users/abhineet/Github/Wire tap/Wire tap/");
            string fileNmae(argv[1]);
            pathToFile.append(fileNmae);
            Analyzer *kAnalyzer = new Analyzer(pathToFile);
            cout<<setiosflags(ios::fixed | ios::showpoint | ios::left)<<setprecision(2);
            kAnalyzer->startAnalyzing();

            
            cout<<"\n\n===================== Summary =====================\n";
            
            kAnalyzer->getPacketSizeStats();
            
            
            cout<<"\n\n===================== Link layer =====================\n";

            kAnalyzer->getUniqueEtherAddressResult();
            
            cout<<"\n\n===================== Network layer =====================\n";
            
            
            kAnalyzer->getUniqueNetworkLayerProtoclsResult();
            kAnalyzer->getUniqueSrcIPResult();
            kAnalyzer->getUniqueDesIPResult();
            kAnalyzer->getUniqueTTLResult();
            kAnalyzer->getUniqueARPParticipantsResult();
            
            cout<<"\n\n===================== Transport layer =====================\n";
            
            kAnalyzer->getUniqueTransportLayerProtocolsResult();
            kAnalyzer->getUniqueTCPPortsResult();
            kAnalyzer->getTCPFlagCombinationsResult();
            kAnalyzer->getTCPOptionsResult();

            
            cout<<"\n\n===================== Transport layer: UDP =====================\n\n";

            kAnalyzer->getUniqueUDPPortsResult();
            
            cout<<"\n\n================== Transport layer: ICMP =====================\n\n";
            kAnalyzer->getICMPSrcIPResult();
            kAnalyzer->getICMPDesIPResult();
            kAnalyzer->getICMPTypeCodeResult();
            kAnalyzer->~Analyzer();
            
            
        }
        else
        {
            fprintf(stderr, "Not a pcap file \nQuitting");
            exit(2);
        }
        
        
        
        
        
    }    return 0;
}

