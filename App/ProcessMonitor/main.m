//
//  main.m
//  ProcessMonitor
//
//  Created by Patrick Wardle on 10/17/19.
//  Copyright © 2020 Patrick Wardle. All rights reserved.
//

#import "main.h"
#import "ProcessMonitor.h"

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
        
        //process (other) args
        if(YES != processArgs(arguments))
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

//process args
BOOL processArgs(NSArray* arguments)
{
    //flag
    BOOL validArgs = YES;
    
    //index
    NSUInteger index = 0;
    
    //init 'skipApple' flag
    skipApple = [arguments containsObject:@"-skipApple"];
    
    //init 'prettyPrint' flag
    prettyPrint = [arguments containsObject:@"-pretty"];
    
    //init 'parseEnv' flag
    parseEnv = [arguments containsObject:@"-parseEnv"];
    
    //extract value for 'filterBy'
    index = [arguments indexOfObject:@"-filter"];
    if(NSNotFound != index)
    {
        //inc
        index++;
        
        //sanity check
        // make sure name comes after
        if(index >= arguments.count)
        {
            //invalid
            validArgs = NO;
            
            //bail
            goto bail;
        }
        
        //grab filter name
        filterBy = [arguments objectAtIndex:index];
    }

bail:
    
    return validArgs;
}

//print usage
void usage()
{
    //name
    NSString* name = nil;
    
    //version
    NSString* version = nil;
    
    //extract name
    name = [[[NSBundle mainBundle] infoDictionary] objectForKey:@"CFBundleName"];
    
    //extract version
    version = [[[NSBundle mainBundle] infoDictionary] objectForKey:@"CFBundleVersion"];

    //usage
    printf("\n%s (v%s) usage:\n", name.UTF8String, version.UTF8String);
    printf(" -h or -help      display this usage info\n");
    printf(" -pretty          JSON output is 'pretty-printed'\n");
    printf(" -skipApple       ignore Apple (platform) processes \n");
    printf(" -parseEnv        parse environment variable information\n");
    printf(" -filter <name>   show events matching process name\n\n");
    
    return;
}

//monitor
BOOL monitor()
{
    //(process) events of interest
    es_event_type_t events[] = {ES_EVENT_TYPE_NOTIFY_EXEC, ES_EVENT_TYPE_NOTIFY_FORK, ES_EVENT_TYPE_NOTIFY_EXIT};
    
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
        if( (YES == skipApple) &&
            (YES == process.isPlatformBinary.boolValue))
        {
            //ignore
            return;
        }
        
        //filter
        // and no match? skip
        if(0 != filterBy.length)
        {
            //check file paths & process
            if(YES != [process.path hasSuffix:filterBy])
            {
                //ignore
                return;
            }
        }
    
        //pretty print?
        if(YES == prettyPrint)
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
    // pass in events, count, and callback block for events
    return [procMon start:events count:sizeof(events)/sizeof(events[0]) csOption:csStatic parseEnv:parseEnv callback:block];
}

//prettify JSON
NSString* prettifyJSON(NSString* output)
{
    //data
    NSData* data = nil;
    
    //error
    NSError* error = nil;
    
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
        object = [NSJSONSerialization JSONObjectWithData:data options:0 error:&error];
        if(nil == object)
        {
            //bail
            goto bail;
        }
        
        //covert to pretty data
        prettyData = [NSJSONSerialization dataWithJSONObject:object options:NSJSONWritingPrettyPrinted error:&error];
        if(nil == prettyData)
        {
            //bail
            goto bail;
        }
    }
    //ignore exceptions (here)
    @catch(NSException *exception)
    {
        //bail
        goto bail;
    }
    
    //convert to string
    // note, we manually unescape forward slashes
    prettyString = [[[NSString alloc] initWithData:prettyData encoding:NSUTF8StringEncoding] stringByReplacingOccurrencesOfString:@"\\/" withString:@"/"];
   
bail:
    
    //error?
    if(nil == prettyString)
    {
        //init error
        prettyString = @"{\"error\" : \"failed to convert output to JSON\"}";
    }
    
    return prettyString;
}
