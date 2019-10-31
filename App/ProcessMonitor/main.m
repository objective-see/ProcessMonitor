//
//  main.m
//  ProcessMonitor
//
//  Created by Patrick Wardle on 10/17/19.
//  Copyright © 2019 Patrick Wardle. All rights reserved.
//

#import <Cocoa/Cocoa.h>
#import "ProcessMonitor.h"

/* FUNCTIONS */

//print usage
void usage(void);

//monitor
BOOL monitor(void);

//prettify JSON
NSString* prettifyJSON(NSString* output);

int main(int argc, const char * argv[]) {
    
    //return var
    int status = -1;

    @autoreleasepool {
        
        //args
        NSArray* arguments = nil;
        
        //grab args
        arguments = [[NSProcessInfo processInfo] arguments];
        
        //run via user (app)?
        // display error popup
        if(1 == getppid())
        {
            //launch app normally
            status = NSApplicationMain(argc, argv);
            
            //bail
            goto bail;
        }
        
        //handle '-h' or '-help'
        if( (YES == [arguments containsObject:@"-h"]) ||
            (YES == [arguments containsObject:@"-help"]) )
        {
            //print usage
            usage();
            
            //done
            goto bail;
        }
        
        //go!
        if(YES != monitor())
        {
            //bail
            goto bail;
        }
    
        //run loop
        // as don't want to exit
        [[NSRunLoop currentRunLoop] run];
        
    } //pool
    
bail:
        
    return status;
}

//print usage
void usage()
{
    //usage
    printf("\nPROCESS MONITOR USAGE:\n");
    printf(" -h or -help  display this usage info\n");
    printf(" -pretty      JSON output is 'pretty-printed'\n");
    printf(" -skipApple   ignore Apple (platform) processes \n\n");
    
    return;
}

//monitor
BOOL monitor()
{
    //init monitor
    ProcessMonitor* procMon = [[ProcessMonitor alloc] init];
    
    //define block
    // automatically invoked upon process events
    ProcessCallbackBlock block = ^(Process* process)
    {
        //do thingz
        // e.g. process.event has event (exec, fork, exit)
        // for now, we just print out the event and process object
        
        //ingore apple?
        if( (YES == [[[NSProcessInfo processInfo] arguments] containsObject:@"-skipApple"]) &&
            (YES == [process.signingInfo[KEY_SIGNATURE_PLATFORM_BINARY] boolValue]))
        {
            //ignore
            return;
        }
            
        //pretty print?
        if(YES == [[[NSProcessInfo processInfo] arguments] containsObject:@"-pretty"])
        {
            //make me pretty!
            printf("%s\n", prettifyJSON(process.description).UTF8String);
        }
        else
        {
            //output
            printf("%s\n", process.description.UTF8String);
        }
    };
        
    //start monitoring
    // pass in block for events
    return [procMon start:block];
}

//prettify JSON
NSString* prettifyJSON(NSString* output)
{
    //data
    NSData* data = nil;
    
    //object
    id object = nil;
    
    //pretty data
    NSData* prettyData = nil;
    
    //pretty string
    NSString* prettyString = nil;
    
    //covert to data
    data = [output dataUsingEncoding:NSUTF8StringEncoding];
    
    //convert to JSON
    // wrap since we are serializing JSON
    @try
    {
        //serialize
        object = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
        
        //covert to pretty data
        prettyData =  [NSJSONSerialization dataWithJSONObject:object options:NSJSONWritingPrettyPrinted error:nil];
    }
    //ignore exceptions (here)
    @catch(NSException *exception)
    {
        ;
    }
    
    //covert to pretty string
    if(nil != prettyData)
    {
        //convert to string
        // note, we manually unescape forward slashes
        prettyString = [[[NSString alloc] initWithData:prettyData encoding:NSUTF8StringEncoding] stringByReplacingOccurrencesOfString:@"\\/" withString:@"/"];
    }
    else
    {
        //error
        prettyString = @"{\"error\" : \"failed to convert output to JSON\"}";
    }
    
    return prettyString;
}
