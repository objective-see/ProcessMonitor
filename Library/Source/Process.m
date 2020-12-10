//
//  Process.m
//  ProcessMonitor
//
//  Created by Patrick Wardle on 9/1/19.
//  Copyright © 2020 Objective-See. All rights reserved.
//

#import <libproc.h>
#import <bsm/libbsm.h>
#import <sys/sysctl.h>

#import "signing.h"
#import "utilities.h"
#import "ProcessMonitor.h"

//hash length
// from: cs_blobs.h
#define CS_CDHASH_LEN 20

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
// flag controls code signing options
-(id)init:(es_message_t*)message csOption:(NSUInteger)csOption
{
    //init super
    self = [super init];
    if(nil != self)
    {
        //process from msg
        es_process_t* process = NULL;
        
        //string value
        // used for various conversions
        NSString* string = nil;
        
        //alloc array for args
        self.arguments = [NSMutableArray array];
        
        //alloc array for parents
        self.ancestors = [NSMutableArray array];
        
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
    
        //add cs flags
        self.csFlags = [NSNumber numberWithUnsignedInt:process->codesigning_flags];
        
        //convert/add signing id
        if(nil != (string = convertStringToken(&process->signing_id)))
        {
            //add
            self.signingID = string;
        }
        
        //convert/add team id
        if(nil != (string = convertStringToken(&process->team_id)))
        {
            //add
            self.teamID = string;
        }
        
        //add platform binary
        self.isPlatformBinary = [NSNumber numberWithBool:process->is_platform_binary];
        
        //save cd hash
        self.cdHash = [NSData dataWithBytes:(const void *)process->cdhash length:sizeof(uint8_t)*CS_CDHASH_LEN];
               
        //when specified
        // generate full code signing info
        if(csNone != csOption)
        {
            //generate code signing info
            [self generateCSInfo:csOption];
        }
    
        //enum ancestors
        [self enumerateAncestors];
    }
    
    return self;
}

//generate code signing info
// sets 'signingInfo' iVar
-(void)generateCSInfo:(NSUInteger)csOption
{
    //generate via helper function
    self.signingInfo = generateSigningInfo(self, csOption, kSecCSDefaultFlags);
    
    return;
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
    
    //cd hash
    // requires formatting
    NSMutableString* cdHash = nil;

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
    [description appendFormat: @"\"pid\":%d,\"path\":\"%@\",\"uid\":%d,",self.pid, self.path, self.uid];
   
    //arguments
    if(0 != self.arguments.count)
    {
       //start list
       [description appendFormat:@"\"arguments\":["];
       
       //add all arguments
       for(NSString* argument in self.arguments)
       {
           //skip blank args
           if(0 == argument.length) continue;
           
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
       [description appendFormat:@"\"arguments NULL\":[1],"];
    }

    //add ppid
    [description appendFormat: @"\"ppid\":%d,", self.ppid];

    //add ancestors
    [description appendFormat:@"\"ancestors\":["];

    //add each ancestor
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

    //signing info (reported)
    [description appendString:@"\"signing info (reported)\":{"];
    
    //add cs flags, platform binary
    [description appendFormat: @"\"csFlags\":%d,\"platformBinary\":%d,", self.csFlags.intValue, self.isPlatformBinary.intValue];
    
    //add signing id
    if(0 == self.signingID.length)
    {
        //blank
        [description appendString:@"\"signingID\":\"\","];
    }
    //not blank
    else
    {
        //append
        [description appendFormat:@"\"signingID\":\"%@\",", self.signingID];
    }
    
    //add team id
    if(0 == self.teamID.length)
    {
        //blank
        [description appendString:@"\"teamID\":\"\","];
    }
    //not blank
    else
    {
        //append
        [description appendFormat:@"\"teamID\":\"%@\",", self.teamID];
    }
    
    //alloc string for cd hash
    cdHash = [NSMutableString string];
    
    //format cd hash
    [self.cdHash enumerateByteRangesUsingBlock:^(const void *bytes, NSRange byteRange, BOOL *stop)
    {
        //To print raw byte values as hex
        for (NSUInteger i = 0; i < byteRange.length; ++i) {
            [cdHash appendFormat:@"%02X", ((uint8_t*)bytes)[i]];
        }
    }];
    
    //add cs hash
    [description appendFormat:@"\"cdHash\":\"%@\"", cdHash];
    
    //terminate dictionary
    [description appendString:@"},"];

    //signing info
    [description appendString:@"\"signing info (computed)\":{"];

    //add all key/value pairs from signing info
    for(NSString* key in self.signingInfo)
    {
       //value
       id value = self.signingInfo[key];
       
       //handle `KEY_SIGNATURE_SIGNER`
       if(YES == [key isEqualToString:KEY_SIGNATURE_SIGNER])
       {
           //convert to pritable
           switch ([value intValue]) {
           
               //'None'
               case None:
                   [description appendFormat:@"\"%@\":\"%@\",", key, @"none"];
                   break;
                   
               //'Apple'
               case Apple:
                   [description appendFormat:@"\"%@\":\"%@\",", key, @"Apple"];
                   break;
               
               //'App Store'
               case AppStore:
                   [description appendFormat:@"\"%@\":\"%@\",", key, @"App Store"];
                   break;
                   
               //'Developer ID'
               case DevID:
                   [description appendFormat:@"\"%@\":\"%@\",", key, @"Developer ID"];
                   break;

               //'AdHoc'
               case AdHoc:
                  [description appendFormat:@"\"%@\":\"%@\",", key, @"AdHoc"];
                  break;
                   
               default:
                   break;
           }
       }
       
       //number?
       // add as is
       else if(YES == [value isKindOfClass:[NSNumber class]])
       {
           //add
           [description appendFormat:@"\"%@\":%@,", key, value];
       }
       //array
       else if(YES == [value isKindOfClass:[NSArray class]])
       {
           //start
           [description appendFormat:@"\"%@\":[", key];
           
           //add each item
           [value enumerateObjectsUsingBlock:^(id obj, NSUInteger index, BOOL * _Nonnull stop) {
               
               //add
               [description appendFormat:@"\"%@\"", obj];
               
               //add ','
               if(index != ((NSArray*)value).count-1)
               {
                   //add
                   [description appendString:@","];
               }
               
           }];
           
           //terminate
           [description appendString:@"],"];
       }
       //otherwise
       // just escape it
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
