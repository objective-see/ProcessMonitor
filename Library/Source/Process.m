//
//  Process.m
//  ProcessMonitor
//
//  Created by Patrick Wardle on 9/1/19.
//  Copyright © 2019 Objective-See. All rights reserved.
//

#import <libproc.h>
#import <bsm/libbsm.h>
#import <sys/sysctl.h>

#import "utilities.h"
#import "ProcessMonitor.h"

/* FUNCTIONS */

//helper function
// get parent of arbitrary process
pid_t getParentID(pid_t child);

@implementation Process

@synthesize pid;
@synthesize exit;
@synthesize path;
@synthesize ppid;
@synthesize event;
@synthesize ancestors;
@synthesize arguments;
@synthesize timestamp;
@synthesize signingInfo;

//init
-(id)init:(es_message_t*)message
{
    //init super
    self = [super init];
    if(nil != self)
    {
        //process from msg
        es_process_t* process = NULL;
        
        //alloc array for args
        self.arguments = [NSMutableArray array];
        
        //alloc array for parents
        self.ancestors  = [NSMutableArray array];
        
        //alloc dictionary for signing info
        self.signingInfo = [NSMutableDictionary dictionary];
        
        //init exit
        self.exit = -1;
        
        //init user id
        self.uid = -1;
        
        //init event
        self.event = -1;
        
        //set start time
        self.timestamp = [NSDate date];
        
        //set type
        self.event = message->event_type;
        
        //event specific logic
        // set type
        // extract (relevant) process object, etc
        switch (message->event_type) {
            
            //exec
            case ES_EVENT_TYPE_NOTIFY_EXEC:
                
                //set process (target)
                process = message->event.exec.target;
                
                //extract/format args
                [self extractArgs:&message->event];
                
                break;
                
            //fork
            case ES_EVENT_TYPE_NOTIFY_FORK:
                
                //set process (child)
                process = message->event.fork.child;
                
                break;
                
            //exit
            case ES_EVENT_TYPE_NOTIFY_EXIT:
                
                //set process
                process = message->process;
                
                //set exit code
                self.exit = message->event.exit.stat;
                
                break;
            
            //default
            default:
                
                //set process
                process = message->process;
                
                break;
        }
        
        //init pid
        self.pid = audit_token_to_pid(process->audit_token);
        
        //init ppid
        self.ppid = process->ppid;
        
        //init uuid
        self.uid = audit_token_to_euid(process->audit_token);
        
        //init path
        self.path = convertStringToken(&process->executable->path);
        
        //extract/format code signing info
        [self extractSigningInfo:process];
        
        //enum ancestors
        [self enumerateAncestors];
        
    }
    
    return self;
}

//extract/format args
-(void)extractArgs:(es_events_t *)event
{
    //number of args
    uint32_t count = 0;
    
    //argument
    NSString* argument = nil;
    
    //get # of args
    count = es_exec_arg_count(&event->exec);
    if(0 == count)
    {
        //bail
        goto bail;
    }
    
    //extract all args
    for(uint32_t i = 0; i < count; i++)
    {
        //current arg
        es_string_token_t currentArg = {0};
        
        //extract current arg
        currentArg = es_exec_arg(&event->exec, i);
        
        //convert argument
        argument = convertStringToken(&currentArg);
        if(nil != argument)
        {
            //append
            [self.arguments addObject:argument];
        }
    }
    
bail:
    
    return;
}

//extract/format signing info
-(void)extractSigningInfo:(es_process_t *)process
{
    //cd hash
    NSMutableString* cdHash = nil;
    
    //signing id
    NSString* signingID = nil;
    
    //team id
    NSString* teamID = nil;
    
    //alloc string for hash
    cdHash = [NSMutableString string];
    
    //add flags
    self.signingInfo[KEY_SIGNATURE_FLAGS] = [NSNumber numberWithUnsignedInt:process->codesigning_flags];
    
    //convert/add signing id
    signingID = convertStringToken(&process->signing_id);
    if(nil != signingID)
    {
        //add
        self.signingInfo[KEY_SIGNATURE_IDENTIFIER] = signingID;
    }
    
    //convert/add team id
    teamID = convertStringToken(&process->team_id);
    if(nil != teamID)
    {
        //add
        self.signingInfo[KEY_SIGNATURE_TEAM_IDENTIFIER] = teamID;
    }
    
    //add platform binary
    self.signingInfo[KEY_SIGNATURE_PLATFORM_BINARY] = [NSNumber numberWithBool:process->is_platform_binary];
    
    //format cdhash
    for(uint32_t i = 0; i<CS_CDHASH_LEN; i++)
    {
        //append
        [cdHash appendFormat:@"%X", process->cdhash[i]];
    }
    
    //add cdhash
    self.signingInfo[KEY_SIGNATURE_CDHASH] = cdHash;
    
    return;
}

//generate list of ancestors
-(void)enumerateAncestors
{
    //current process id
    pid_t currentPID = -1;
    
    //parent pid
    pid_t parentPID = -1;
    
    //add parent
    if(-1 != self.ppid)
    {
        //add
        [self.ancestors addObject:[NSNumber numberWithInt:self.ppid]];
        
        //set current to parent
        currentPID = self.ppid;
    }
    //don't know parent
    // just start with self
    else
    {
        //start w/ self
        currentPID = self.pid;
    }
    
    //complete ancestry
    while(YES)
    {
        //get parent pid
        parentPID = getParentID(currentPID);
        if( (0 == parentPID) ||
            (-1 == parentPID) ||
            (currentPID == parentPID) )
        {
            //bail
            break;
        }
        
        //update
        currentPID = parentPID;
        
        //add
        [self.ancestors addObject:[NSNumber numberWithInt:parentPID]];
    }
    
    return;
}

//for pretty printing
// though we convert to JSON
-(NSString *)description
{
    //description
    NSMutableString* description = nil;

    //init output string
    description = [NSMutableString string];
    
    //start JSON
    [description appendString:@"{"];
    
    //add event
    [description appendString:@"\"event\":"];
    
    //add event
    switch(self.event)
    {
        //exec
        case ES_EVENT_TYPE_NOTIFY_EXEC:
            [description appendString:@"\"ES_EVENT_TYPE_NOTIFY_EXEC\","];
            break;
            
        //fork
        case ES_EVENT_TYPE_NOTIFY_FORK:
            [description appendString:@"\"ES_EVENT_TYPE_NOTIFY_FORK\","];
            break;
            
        //exit
        case ES_EVENT_TYPE_NOTIFY_EXIT:
            [description appendString:@"\"ES_EVENT_TYPE_NOTIFY_EXIT\","];
            break;
            
        default:
            break;
    }
    
    //add timestamp
    [description appendFormat:@"\"timestamp\":\"%@\",", self.timestamp];
    
    //start process
    [description appendString:@"\"process\":{"];
    
    //add pid, path, etc
    [description appendFormat: @"\"pid\":%d,\"path\":\"%@\",\"uid\":%d," ,self.pid, self.path, self.uid];
    
    //arguments
    if(0 != self.arguments.count)
    {
        //start list
        [description appendFormat:@"\"arguments\":["];
        
        //add all arguments
        for(NSString* argument in self.arguments)
        {
            //add
            [description appendFormat:@"\"%@\",", [argument stringByReplacingOccurrencesOfString:@"\"" withString:@"\\\""]];
        }
        
        //remove last ','
        if(YES == [description hasSuffix:@","])
        {
            //remove
            [description deleteCharactersInRange:NSMakeRange([description length]-1, 1)];
        }
        
        //terminate list
        [description appendString:@"],"];
    }
    //no args
    else
    {
        //add empty list
        [description appendFormat:@"\"arguments\":[],"];
    }
    
    //add ppid
    [description appendFormat: @"\"ppid\":%d," ,self.ppid];
    
    //add ancestors
    [description appendFormat:@"\"ancestors\":["];
    
    //add all arguments
    for(NSNumber* ancestor in self.ancestors)
    {
        //add
        [description appendFormat:@"%d,", ancestor.unsignedIntValue];
    }
    
    //remove last ','
    if(YES == [description hasSuffix:@","])
    {
        //remove
        [description deleteCharactersInRange:NSMakeRange([description length]-1, 1)];
    }
    
    //terminate list
    [description appendString:@"],"];
    
    //signing info
    [description appendString:@"\"signing info\":{"];
    
    //add all key/value pairs from signing info
    for(NSString* key in self.signingInfo)
    {
        //value
        id value = self.signingInfo[key];
        
        //number?
        // add as is
        if(YES == [value isKindOfClass:[NSNumber class]])
        {
            //add
            [description appendFormat:@"\"%@\":%@,", key, value];
        }
        //otherwise, escape
        else
        {
            //add
            [description appendFormat:@"\"%@\":\"%@\",", key, value];
        }
    }

    //remove last ','
    if(YES == [description hasSuffix:@","])
    {
       //remove
       [description deleteCharactersInRange:NSMakeRange([description length]-1, 1)];
    }
    
    //terminate dictionary
    [description appendString:@"}"];
    
    //exit event?
    // add exit code
    if(ES_EVENT_TYPE_NOTIFY_EXIT == self.event)
    {
        //add exit
        [description appendFormat:@",\"exit code\":%d", self.exit];
    }
    
    //terminate process
    [description appendString:@"}"];
    
    //terminate entire JSON
    [description appendString:@"}"];

    return description;
}

@end

//helper function
// get parent of arbitrary process
pid_t getParentID(pid_t child)
{
    //parent id
    pid_t parentID = -1;
    
    //kinfo_proc struct
    struct kinfo_proc processStruct = {0};
    
    //size
    size_t procBufferSize = 0;
    
    //mib
    const u_int mibLength = 4;
    
    //syscall result
    int sysctlResult = -1;
    
    //init buffer length
    procBufferSize = sizeof(processStruct);
    
    //init mib
    int mib[mibLength] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, child};
    
    //make syscall
    sysctlResult = sysctl(mib, mibLength, &processStruct, &procBufferSize, NULL, 0);
    
    //check if got ppid
    if( (noErr == sysctlResult) &&
        (0 != procBufferSize) )
    {
        //save ppid
        parentID = processStruct.kp_eproc.e_ppid;
    }
    
    return parentID;
}
