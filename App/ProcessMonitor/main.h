//
//  main.h
//  ProcessMonitor
//
//  Created by Patrick Wardle on 11/10/19.
//  Copyright © 2019 Patrick Wardle. All rights reserved.
//

#ifndef main_h
#define main_h

#import <Cocoa/Cocoa.h>

/* GLOBALS */

//'skipAPple' flag
BOOL skipApple = NO;

//filter string
NSString* filterBy = nil;

//'prettyPrint' flag
BOOL prettyPrint = NO;

/* FUNCTIONS */

//process args
BOOL processArgs(NSArray* arguments);

//print usage
void usage(void);

//monitor
BOOL monitor(void);

//prettify JSON
NSString* prettifyJSON(NSString* output);

#endif /* main_h */
