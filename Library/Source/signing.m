//
//  File: Signing.m
//  Project: Proc Info
//
//  Created by: Patrick Wardle
//  Copyright:  2017 Objective-See
//  License:    Creative Commons Attribution-NonCommercial 4.0 International License
//

#import "signing.h"
#import "utilities.h"

#import <Security/Security.h>
#import <SystemConfiguration/SystemConfiguration.h>

//get the signing info of a item
// pid specified: extract dynamic code signing info
// path specified: generate static code signing info
NSMutableDictionary* generateSigningInfo(Process* process, NSUInteger options, SecCSFlags flags)
{
    //status
    OSStatus status = !errSecSuccess;
    
    //info dictionary
    NSMutableDictionary* signingInfo = nil;
    
    //signing details
    CFDictionaryRef signingDetails = NULL;
    
    //signing authorities
    NSMutableArray* signingAuths = nil;
    
    //init signing status
    signingInfo = [NSMutableDictionary dictionary];
    
    //start with dynamic cs check
    signingDetails = dynamicCodeCheck(process, flags, signingInfo);
        
    //extract status
    status = [signingInfo[KEY_SIGNATURE_STATUS] intValue];
    
    //on (certain) errors
    // do static, if option is set
    if( (csStatic == options) &&
        ( (kPOSIXErrorESRCH == status)  ||
          (errSecCSNoSuchCode == status) ||
          (errSecCSStaticCodeChanged == status) ) )
    {
        //free (invalid) details
        if(NULL != signingDetails)
        {
            //free / unset
            CFRelease(signingDetails);
            signingDetails = NULL;
        }
    
        //static code sign check
        signingDetails = staticCodeCheck(process, flags, signingInfo);
    }

    //bail on any signing error(s)
    if(errSecSuccess != [signingInfo[KEY_SIGNATURE_STATUS] intValue])
    {
        //bail
        goto bail;
    }
    
    /*
    //extract code signing flags
    if(nil != [(__bridge NSDictionary*)signingDetails objectForKey:(__bridge NSString*)kSecCodeInfoFlags])
    {
        //extract/save
        signingInfo[KEY_SIGNATURE_FLAGS] = [(__bridge NSDictionary*)signingDetails objectForKey:(__bridge NSString*)kSecCodeInfoFlags];
    }
    */
    
    //extract code signing id
    if(nil != [(__bridge NSDictionary*)signingDetails objectForKey:(__bridge NSString*)kSecCodeInfoIdentifier])
    {
        //extract/save
        signingInfo[KEY_SIGNATURE_IDENTIFIER] = [(__bridge NSDictionary*)signingDetails objectForKey:(__bridge NSString*)kSecCodeInfoIdentifier];
    }
    
    //extract team signing id
    if(nil != [(__bridge NSDictionary*)signingDetails objectForKey:(__bridge NSString*)kSecCodeInfoTeamIdentifier])
    {
        //extract/save
        signingInfo[KEY_SIGNATURE_TEAM_IDENTIFIER] = [(__bridge NSDictionary*)signingDetails objectForKey:(__bridge NSString*)kSecCodeInfoTeamIdentifier];
    }
    
    //extract signing authorities
    signingAuths = extractSigningAuths((__bridge NSDictionary *)(signingDetails));
    if(0 != signingAuths.count)
    {
        //save
        signingInfo[KEY_SIGNATURE_AUTHORITIES] = signingAuths;
    }
    
bail:
    
    //free signing info
    if(NULL != signingDetails)
    {
        //free
        CFRelease(signingDetails);
        
        //unset
        signingDetails = NULL;
    }
    
    return signingInfo;
}

//extract signing info/check via dynamic code ref (process pid)
CFDictionaryRef dynamicCodeCheck(Process* process, SecCSFlags flags, NSMutableDictionary* signingInfo)
{
    //status
    OSStatus status = !errSecSuccess;
    
    //dynamic code ref
    SecCodeRef dynamicCode = NULL;
    
    //signing details
    CFDictionaryRef signingDetails = NULL;
    
    //attempt to generate dynamic code ref via pid
    // if this fails, perform static code checks via path
    status = SecCodeCopyGuestWithAttributes(NULL, (__bridge CFDictionaryRef _Nullable)(@{(__bridge NSString *)kSecGuestAttributePid : [NSNumber numberWithInt:process.pid]}), kSecCSDefaultFlags, &dynamicCode);
    if(errSecSuccess != status)
    {
        //set error
        signingInfo[KEY_SIGNATURE_STATUS] = [NSNumber numberWithInt:status];
        
        //bail
        goto bail;
    }

    //validate code
    status = SecCodeCheckValidity(dynamicCode, flags, NULL);
    if(errSecSuccess != status)
    {
        //set error
        signingInfo[KEY_SIGNATURE_STATUS] = [NSNumber numberWithInt:status];
        
        //bail
        goto bail;
    }
    
    //happily signed
    signingInfo[KEY_SIGNATURE_STATUS] = [NSNumber numberWithInt:errSecSuccess];
    
    //determine signer
    // apple, app store, dev id, adhoc, etc...
    signingInfo[KEY_SIGNATURE_SIGNER] = extractSigner(dynamicCode, flags, YES);
    
    //extract signing info
    status = SecCodeCopySigningInformation(dynamicCode, kSecCSSigningInformation, &signingDetails);
    if(errSecSuccess != status)
    {
        //bail
        goto bail;
    }
    
bail:
    
    //free dynamic code
    if(NULL != dynamicCode)
    {
        //free
        CFRelease(dynamicCode);
        
        //unset
        dynamicCode = NULL;
    }
    
    return signingDetails;
}

//extact signing info/check via static code ref (process path)
CFDictionaryRef staticCodeCheck(Process* process, SecCSFlags flags, NSMutableDictionary* signingInfo)
{
    //status
    OSStatus status = !errSecSuccess;
    
    //static code ref
    SecStaticCodeRef staticCode = NULL;
    
    //signing details
    CFDictionaryRef signingDetails = NULL;
    
    //sanity check
    if(nil == process.path)
    {
        //set error
        signingInfo[KEY_SIGNATURE_STATUS] = [NSNumber numberWithInt:kPOSIXErrorESRCH];
        
        //bail
        goto bail;
    }
    
    //create static code ref via path
    status = SecStaticCodeCreateWithPath((__bridge CFURLRef)([NSURL fileURLWithPath:process.path]), kSecCSDefaultFlags, &staticCode);
    if(errSecSuccess != status)
    {
        //set error
        signingInfo[KEY_SIGNATURE_STATUS] = [NSNumber numberWithInt:status];
        
        //bail
        goto bail;
    }
    
    //check signature
    status = SecStaticCodeCheckValidity(staticCode, flags, NULL);
    if(errSecSuccess != status)
    {
        //set error
        signingInfo[KEY_SIGNATURE_STATUS] = [NSNumber numberWithInt:status];
        
        //bail
        goto bail;
    }
    
    //happily signed
    signingInfo[KEY_SIGNATURE_STATUS] = [NSNumber numberWithInt:errSecSuccess];
    
    //determine signer
    // apple, app store, dev id, adhoc, etc...
    signingInfo[KEY_SIGNATURE_SIGNER] = extractSigner(staticCode, flags, NO);
    
    //extract signing info
    status = SecCodeCopySigningInformation(staticCode, kSecCSSigningInformation, &signingDetails);
    if(errSecSuccess != status)
    {
        //bail
        goto bail;
    }
    
bail:

    //free static code
    if(NULL != staticCode)
    {
        //free
        CFRelease(staticCode);
        
        //unset
        staticCode = NULL;
    }
    
    return signingDetails;
}

//determine who signed item
NSNumber* extractSigner(SecStaticCodeRef code, SecCSFlags flags, BOOL isDynamic)
{
    //result
    NSNumber* signer = nil;
    
    //"anchor apple"
    static SecRequirementRef isApple = nil;
    
    //"anchor apple generic"
    static SecRequirementRef isDevID = nil;
    
    //"anchor apple generic and certificate leaf [subject.CN] = \"Apple Mac OS Application Signing\""
    static SecRequirementRef isAppStore = nil;
    
    //token
    static dispatch_once_t onceToken = 0;
    
    //only once
    // init requirements
    dispatch_once(&onceToken, ^{
        
        //init apple signing requirement
        SecRequirementCreateWithString(CFSTR("anchor apple"), kSecCSDefaultFlags, &isApple);
        
        //init dev id signing requirement
        SecRequirementCreateWithString(CFSTR("anchor apple generic"), kSecCSDefaultFlags, &isDevID);
        
        //init app store signing requirement
        SecRequirementCreateWithString(CFSTR("anchor apple generic and certificate leaf [subject.CN] = \"Apple Mac OS Application Signing\""), kSecCSDefaultFlags, &isAppStore);
    });
    
    //check 1: "is apple" (proper)
    if(errSecSuccess == validateRequirement(code, isApple, flags, isDynamic))
    {
        //set signer to apple
        signer = [NSNumber numberWithInt:Apple];
    }
    
    //check 2: "is app store"
    // note: this is more specific than dev id, so do it first
    else if(errSecSuccess == validateRequirement(code, isAppStore, flags, isDynamic))
    {
        //set signer to app store
        signer = [NSNumber numberWithInt:AppStore];
    }
    
    //check 3: "is dev id"
    else if(errSecSuccess == validateRequirement(code, isDevID, flags, isDynamic))
    {
        //set signer to dev id
        signer = [NSNumber numberWithInt:DevID];
    }
    
    //otherwise
    // has to be adhoc?
    else
    {
        //set signer to ad hoc
        signer = [NSNumber numberWithInt:AdHoc];
    }
    
    return signer;
}

//validate a requirement
OSStatus validateRequirement(SecStaticCodeRef code, SecRequirementRef requirement, SecCSFlags flags, BOOL isDynamic)
{
    //result
    OSStatus result = -1;
    
    //dynamic check?
    if(YES == isDynamic)
    {
        //validate dynamically
        result = SecCodeCheckValidity((SecCodeRef)code, flags, requirement);
    }
    //static check
    else
    {
        //validate statically
        result = SecStaticCodeCheckValidity(code, flags, requirement);
    }
    
    return result;
}

//extract (names) of signing auths
NSMutableArray* extractSigningAuths(NSDictionary* signingDetails)
{
    //signing auths
    NSMutableArray* authorities = nil;
    
    //cert chain
    NSArray* certificateChain = nil;
    
    //index
    NSUInteger index = 0;
    
    //cert
    SecCertificateRef certificate = NULL;
    
    //common name on chert
    CFStringRef commonName = NULL;
    
    //init array for certificate names
    authorities = [NSMutableArray array];
    
    //get cert chain
    certificateChain = [signingDetails objectForKey:(__bridge NSString*)kSecCodeInfoCertificates];
    if(0 == certificateChain.count)
    {
        //no certs
        goto bail;
    }
    
    //extract/save name of all certs
    for(index = 0; index < certificateChain.count; index++)
    {
        //reset
        commonName = NULL;
        
        //extract cert
        certificate = (__bridge SecCertificateRef)([certificateChain objectAtIndex:index]);
        
        //get common name
        if( (errSecSuccess == SecCertificateCopyCommonName(certificate, &commonName)) &&
            (NULL != commonName) )
        {
            //save
            [authorities addObject:(__bridge id _Nonnull)(commonName)];
            
            //release
            CFRelease(commonName);
        }
    }
        
bail:
    
    return authorities;
}
