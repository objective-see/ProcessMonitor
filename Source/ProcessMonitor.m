//
//  ProcessMonitor.m
//  ProcessMonitor
//
//  Created by Patrick Wardle on 9/1/19.
//  Copyright © 2019 Objective-See. All rights reserved.
//

//  Inspired by https://gist.github.com/Omar-Ikram/8e6721d8e83a3da69b31d4c2612a68ba
//  NOTE: requires a) root b) the 'com.apple.developer.endpoint-security.client' entitlement

#import "utilities.h"
#import "ProcessMonitor.h"

#import <Foundation/Foundation.h>
#import <EndpointSecurity/EndpointSecurity.h>

//endpoint
es_client_t* endpointClient = nil;

//process events
es_event_type_t events[] = {ES_EVENT_TYPE_NOTIFY_EXEC, ES_EVENT_TYPE_NOTIFY_FORK, ES_EVENT_TYPE_NOTIFY_EXIT};

@implementation ProcessMonitor

//start monitoring
-(BOOL)start:(ProcessCallbackBlock)callback
{
    //flag
    BOOL started = NO;
    
    //result
    es_new_client_result_t result = 0;
    
    //sync
    @synchronized (self)
    {
    
    //create client
    // callback invokes (user) callback for new processes
    result = es_new_client(&endpointClient, ^(es_client_t *client, const es_message_t *message)
    {
        //new process event
        Process* process = nil;
        
        //init process obj
        process = [[Process alloc] init:(es_message_t* _Nonnull)message];
        if(nil != process)
        {
            //invoke user callback
            callback(process);
        }
    
    });
        
    //error?
    if(ES_NEW_CLIENT_RESULT_SUCCESS != result)
    {
        //err msg
        NSLog(@"ERROR: es_new_client() failed with %d", result);
        
        //bail
        goto bail;
    }
    
    //clear cache
    if(ES_CLEAR_CACHE_RESULT_SUCCESS != es_clear_cache(endpointClient))
    {
        //err msg
        NSLog(@"ERROR: es_clear_cache() failed");
        
        //bail
        goto bail;
    }
    
    //subscribe
    if(ES_RETURN_SUCCESS != es_subscribe(endpointClient, events, sizeof(events)/sizeof(events[0])))
    {
        //err msg
        NSLog(@"ERROR: es_subscribe() failed");
        
        //bail
        goto bail;
    }
        
    } //sync
    
    //happy
    started = YES;
    
bail:
    
    return started;
}

//stop
-(BOOL)stop
{
    //flag
    BOOL stopped = NO;
    
    //sync
    @synchronized (self)
    {
        
    //unsubscribe & delete
    if(NULL != endpointClient)
    {
       //unsubscribe 
       if(ES_RETURN_SUCCESS != es_unsubscribe_all(endpointClient))
       {
           //err msg
           NSLog(@"ERROR: es_unsubscribe_all() failed");
           
           //bail
           goto bail;
       }
       
       //delete client
       if(ES_RETURN_SUCCESS != es_delete_client(endpointClient))
       {
           //err msg
           NSLog(@"ERROR: es_delete_client() failed");
           
           //bail
           goto bail;
       }
       
       //unset
       endpointClient = NULL;
       
       //happy
       stopped = YES;
    }
        
    } //sync
    
bail:
    
    return stopped;
}

@end
