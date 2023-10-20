//
//  File: Signing.h
//  Project: ProcessMonitor
//
//  Created by: Patrick Wardle
//  Copyright:  2017 Objective-See
//  License:    Creative Commons Attribution-NonCommercial 4.0 International License
//

#ifndef Signing_h
#define Signing_h

#import "ProcessMonitor.h"

#import <AppKit/AppKit.h>
#import <Foundation/Foundation.h>


/* FUNCTIONS */

//get the signing info of a item
// pid specified: extract dynamic code signing info
// path specified: generate static code signing info
NSMutableDictionary* generateSigningInfo(Process* process, NSUInteger options, SecCSFlags flags);

//extract signing info/check via dynamic code ref (process pid)
CFDictionaryRef dynamicCodeCheck(Process* process, SecCSFlags flags, NSMutableDictionary* signingInfo) CF_RETURNS_NOT_RETAINED;

//extact signing info/check via static code ref (process path)
CFDictionaryRef staticCodeCheck(Process* process, SecCSFlags flags, NSMutableDictionary* signingInfo) CF_RETURNS_NOT_RETAINED;

//determine who signed item
NSNumber* extractSigner(SecStaticCodeRef code, SecCSFlags flags, BOOL isDynamic);

//validate a requirement
OSStatus validateRequirement(SecStaticCodeRef code, SecRequirementRef requirement, SecCSFlags flags, BOOL isDynamic);

//extract (names) of signing auths
NSMutableArray* extractSigningAuths(NSDictionary* signingDetails);

#endif
