//
//  Globals.h
//  Wiretap
//
//  Created by Abhineet on 09/11/12.
//  Copyright (c) 2012 Abhineet. All rights reserved.
//

#ifndef Wiretap_Globals_h
#define Wiretap_Globals_h


#define START_DELIMITER "\n----------------------START-------------------------";
#define END_DELIMITER   "\n\n---------------------END--------------------------";

typedef struct srcDesIpv4
{
    char src[INET_ADDRSTRLEN];
    char des[INET_ADDRSTRLEN];
};


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

#endif
