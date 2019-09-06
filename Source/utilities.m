//
//  utilities.m
//  ProcessMonitor
//
//  Created by Patrick Wardle on 9/1/19.
//  Copyright © 2019 Objective-See. All rights reserved.
//

#import "utilities.h"

//convert es_string_token_t to string
NSString* convertStringToken(es_string_token_t* stringToken)
{
    //string
    NSString* string = nil;
    
    //init to empty string
    string = [NSString string];
    
    //sanity check(s)
    if( (NULL == stringToken) ||
        (0 == stringToken->length) ||
        (NULL == stringToken->data) )
    {
        //bail
        goto bail;
    }
        
    //convert to data, then to string
    string = [NSString stringWithUTF8String:[[NSData dataWithBytes:stringToken->data length:stringToken->length] bytes]];
    
bail:
    
    return string;
    
}
