//
//  utilities.m
//  ProcessMonitor
//
//  Created by Patrick Wardle on 9/1/19.
//  Copyright © 2020 Objective-See. All rights reserved.
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

// parses environment string |env| and writes the key to |key| and the value to |value|
void convertEnvironmentVariableStringToKeyValue(NSString *env, NSString **key, NSString **value)
{
    NSRange firstEquals = [env rangeOfString:@"="];
    if(firstEquals.length == NSNotFound)
    {
        return;
    }
    
    @try
    {
        NSString *keySubStr = [env substringToIndex:firstEquals.location];
        if(keySubStr != nil && keySubStr.length > 0)
        {
            *key = keySubStr;
        }
        else
        {
            // key cannot be empty, fail fast
            return;
        }
        
        NSString *valueSubStr = [env substringFromIndex:firstEquals.location + 1];
        // either empty or contains value, either is fine
        *value = valueSubStr;
    }
    // should never happen but just in case
    @catch (NSException *exception)
    {
        return;
    }
}
