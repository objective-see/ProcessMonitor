//
//  AppDelegate.m
//  ProcessMonitor
//
//  Created by Patrick Wardle on 10/17/19.
//  Copyright © 2019 Patrick Wardle. All rights reserved.
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

- (void)applicationDidFinishLaunching:(NSNotification *)aNotification {
    
}

//exit on window close
- (BOOL)applicationShouldTerminateAfterLastWindowClosed:(NSApplication *)theApplication {
    return YES;
}

//open 'user guide'
- (IBAction)moreInfo:(id)sender {
    
    [[NSWorkspace sharedWorkspace] openURL:[NSURL URLWithString:PRODUCT_URL]];
}


@end
