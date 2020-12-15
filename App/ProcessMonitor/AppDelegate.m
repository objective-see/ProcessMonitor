//
//  AppDelegate.m
//  ProcessMonitor
//
//  Created by Patrick Wardle on 10/17/19.
//  Copyright © 2020 Patrick Wardle. All rights reserved.
//

#import "AppDelegate.h"

/* DEFINES */

//product url
#define PRODUCT_URL @"https://objective-see.com/products/utilities.html#ProcessMonitor"

@interface AppDelegate ()

@property (weak) IBOutlet NSWindow *window;
@end

@implementation AppDelegate

//center window
-(void)awakeFromNib
{
    //center
    [self.window center];
    
    return;
}

//make close button first responder
-(void)applicationDidFinishLaunching:(NSNotification *)aNotification {
    
    //first responder
    [self.window makeFirstResponder:[self.window.contentView viewWithTag:1]];
}

//exit on window close
-(BOOL)applicationShouldTerminateAfterLastWindowClosed:(NSApplication *)theApplication {
    return YES;
}

//close app
-(IBAction)close:(id)sender {
    
    //close
    // will trigger exit
    [self.window close];
}

//open product documentation
-(IBAction)moreInfo:(id)sender {
    
    //open
    [[NSWorkspace sharedWorkspace] openURL:[NSURL URLWithString:PRODUCT_URL]];
}

@end
