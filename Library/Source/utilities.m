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
    
    //sanity check(s)
    if( (NULL == stringToken) ||
        (NULL == stringToken->data) ||
        (stringToken->length <= 0) )
    {
        //bail
        goto bail;
    }
        
    //convert to data, then to string
    string = [[NSString alloc] initWithBytes:stringToken->data length:stringToken->length encoding:NSUTF8StringEncoding];
    
bail:
    
    return string;
}
