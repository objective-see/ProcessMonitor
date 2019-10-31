//
//  utilities.h
//  ProcessMonitor
//
//  Created by Patrick Wardle on 9/1/19.
//  Copyright © 2019 Objective-See. All rights reserved.
//

#ifndef utilities_h
#define utilities_h

#import <Foundation/Foundation.h>
#import <EndpointSecurity/EndpointSecurity.h>

//convert es_string_token_t to string
NSString* convertStringToken(es_string_token_t* stringToken);

#endif /* utilities_h */
