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

typedef struct ipformatstruct
{
    char src[INET_ADDRSTRLEN];
    char des[INET_ADDRSTRLEN];
}srcDesIpv4;



#endif
