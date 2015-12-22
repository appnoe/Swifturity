//
//  ViewController.swift
//  Swifturity
//
//  Created by Klaus Rodewig on 08.12.15.
//  Copyright © 2015 Appnö UG (haftungsbeschränkt). All rights reserved.
//

import UIKit

class ViewController: UIViewController {
    @IBAction func writeFile(sender: UIButton) {
        
        // NSFileProtection
        let theFileManager = NSFileManager.defaultManager()
        let theLocalDirectories = theFileManager.URLsForDirectory(.DocumentDirectory, inDomains: .UserDomainMask)
        
        let theDocumentsPath = theLocalDirectories.first?.path
        let theFileName = "foobar.txt"
        let theFile = theDocumentsPath! + "/" + theFileName
        
        let theContentString = "foobar"
        let theContentData = theContentString.dataUsingEncoding(NSUTF8StringEncoding)
        
        let theAttributes = [NSFileProtectionKey : NSFileProtectionComplete]
        theFileManager.createFileAtPath(theFile, contents:theContentData, attributes:theAttributes)
        
        // Backup exclusion
        let theFileURL = NSURL.fileURLWithPath(theFile)
        do {
            try theFileURL.setResourceValue(true, forKey: NSURLIsExcludedFromBackupKey)
        } catch {
            print("Backup exclusion not set")
        }
        
        // encryption & decryption
        let theSecret = "Lorem Ipsum Alaaf und Helau."
        // uncomment for CommonCrypto mega fail
//        let theSecret = "AAAAAAAAA"
        let theSalt = randomDataWithLength(32)
        let theHash = generateHashFromString("foobar")
        let theKey = keyFromPassword(theHash, inSalt: theSalt)
        print(theHash)
        print(theSalt)
        print(theKey)
        let theCipherText = encryptData(theSecret.dataUsingEncoding(NSUTF8StringEncoding)!, inKey: theKey, inIV: randomDataWithLength(kCCBlockSizeAES128))
        // uncomment for CommonCrypto mega fail
//        let theCipherText = encryptData(theSecret.dataUsingEncoding(NSUTF8StringEncoding)!, inKey: theSecret.dataUsingEncoding(NSUTF8StringEncoding)!, inIV: randomDataWithLength(kCCBlockSizeAES128))
        print((theCipherText))
        let theClearData = decryptData(theCipherText!, inKey: theKey)!
        let theClearText = NSString(data: theClearData, encoding: NSUTF8StringEncoding)
        print(theClearText)
    }
    
    func generateHashFromString(inString : String) -> String {
        let theContext = UnsafeMutablePointer<CC_SHA256_CTX>.alloc(1)
        var theDigest = Array<UInt8>(count:Int(CC_SHA256_DIGEST_LENGTH), repeatedValue:0)
        CC_SHA256_Init(theContext)
        CC_SHA256_Update(theContext, inString, CC_LONG(inString.lengthOfBytesUsingEncoding(NSUTF8StringEncoding)))
        CC_SHA256_Final(&theDigest, theContext)
        theContext.dealloc(1)
        var theHash = ""
        for oneByte in theDigest {
            theHash += String(format:"%02x", oneByte)
        }
        return theHash
    }
    
    func randomDataWithLength(inLength : size_t) -> NSMutableData {
        let theData = NSMutableData(length: inLength)
        SecRandomCopyBytes(kSecRandomDefault, inLength, UnsafeMutablePointer<UInt8>(theData!.mutableBytes))
        return theData!
    }
    
    func keyFromPassword(inPassword : NSString, inSalt : NSData) -> NSData {
        let theEncryptionKey : NSMutableData = NSMutableData(length: kCCBlockSizeAES128)!
        CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2),
                                inPassword.UTF8String,
                                size_t(inPassword.length),
                                UnsafePointer<UInt8>(inSalt.bytes),
                                size_t(inSalt.length),
                                CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                                uint(20000),
                                UnsafeMutablePointer<UInt8>(theEncryptionKey.mutableBytes),
                                size_t(theEncryptionKey.length));
        return theEncryptionKey
    }
    
    func encryptData(inData : NSData, inKey : NSData, inIV : NSData) -> NSData? {
        let theCipherText : NSMutableData = NSMutableData(length: inData.length + kCCBlockSizeAES128)!
        var outLength : Int = 0
        let theOperation : CCOperation = UInt32(kCCEncrypt)
        let theAlgorithm :  CCAlgorithm = UInt32(kCCAlgorithmAES128)
        let theOptions :   CCOptions = UInt32(kCCOptionPKCS7Padding)
        let theCCResult : CCCryptorStatus = CCCrypt(theOperation,
                                                    theAlgorithm,
                                                    theOptions,
                                                    UnsafePointer<UInt8>(inKey.bytes),
                                                    size_t(inKey.length),
                                                    UnsafePointer<UInt8>(inIV.bytes),
                                                    UnsafePointer<UInt8>(inData.bytes),
                                                    size_t(inData.length),
                                                    UnsafeMutablePointer<Void>(theCipherText.mutableBytes),
                                                    size_t(theCipherText.length),
                                                    &outLength)
        if (theCCResult == 0) {
            theCipherText.length = outLength
            theCipherText.appendData(inIV)
            return theCipherText
        } else {
            return nil
        }
    }
    
    func decryptData(inData : NSData, inKey : NSData) -> NSData? {
        var outLength : Int = 0
        let theIV = inData.subdataWithRange(NSMakeRange(inData.length-kCCBlockSizeAES128, kCCBlockSizeAES128))
        let theCipherText = inData.subdataWithRange(NSMakeRange(0, inData.length-kCCBlockSizeAES128))
        let theClearText = NSMutableData(length: inData.length + kCCBlockSizeAES128)
        let theOperation : CCOperation = UInt32(kCCDecrypt)
        let theAlgorithm :  CCAlgorithm = UInt32(kCCAlgorithmAES128)
        let theOptions :   CCOptions = UInt32(kCCOptionPKCS7Padding)
        let theCCResult : CCCryptorStatus = CCCrypt(theOperation,
                                                    theAlgorithm,
                                                    theOptions,
                                                    UnsafePointer<UInt8>(inKey.bytes),
                                                    size_t(inKey.length),
                                                    UnsafePointer<UInt8>(theIV.bytes),
                                                    UnsafePointer<UInt8>(theCipherText.bytes),
                                                    size_t(theCipherText.length),
                                                    UnsafeMutablePointer<Void>(theClearText!.mutableBytes),
                                                    size_t(theClearText!.length),
                                                    &outLength)
        if(theCCResult == 0){
            theClearText?.length = outLength
            return NSData(data: theClearText!)
        } else {
            return nil
        }
    }
    
//    +(OSStatus)storeSecretInKeychain:(NSData *)inSecret
//    account:(NSString *)inAccount
//    service:(NSString *)inService
//    label:(NSString * )inLabel
//    accessGroup:(NSString *)inAccessGroup
//    protectionClass:(CFTypeRef)inProtectionClass{
//    NSMutableDictionary *theSearchDict = [NSMutableDictionary dictionary];
//    [theSearchDict setObject:(__bridge id)kSecClassGenericPassword forKey:(__bridge id)kSecClass];
//    [theSearchDict setObject:inService forKey:(__bridge id)kSecAttrService];
//    [theSearchDict setObject:inLabel forKey:(__bridge id)kSecAttrLabel];
//    [theSearchDict setObject:inAccount forKey:(__bridge id)kSecAttrAccount];
//    
//    NSMutableDictionary *theWriteDict = [NSMutableDictionary dictionary];
//    [theWriteDict setDictionary:theSearchDict];
//    CFTypeRef theProtectionClass = inProtectionClass ? inProtectionClass : kSecDefaultProtectionClass;
//    [theWriteDict setObject:(__bridge id)theProtectionClass forKey:(__bridge id)kSecAttrAccessible];
//    [theWriteDict setObject:inSecret forKey:(__bridge id)kSecValueData];
//    if(inAccessGroup != nil)
//    [theWriteDict setObject:inAccessGroup forKey:(__bridge id)kSecAttrAccessGroup];
//    
//    NSMutableDictionary *theUpdateDict = [NSMutableDictionary dictionary];
//    [theUpdateDict setObject:inSecret forKey:(__bridge id)kSecValueData];
//    
//    OSStatus theStatus;
//    
//    if((theStatus = SecItemAdd((__bridge CFDictionaryRef)theWriteDict, NULL)) == errSecDuplicateItem){
//    theStatus =  SecItemUpdate((__bridge CFDictionaryRef)theSearchDict, ((__bridge CFDictionaryRef)theUpdateDict));
//    }
//    NSLog(@"Keychain status: %ld", (long)theStatus);
//    return theStatus;
//    }
//    
//    +(NSData *)secretFromKeychainForAccount:(NSString *)inAccount
//    service:(NSString *)inService
//    withLabel:(NSString * )inLabel{
//    if(inAccount != nil){
//    NSMutableDictionary *theQueryDict = [NSMutableDictionary dictionary];
//    [theQueryDict setObject:(__bridge NSString *)kSecClassGenericPassword forKey:(__bridge NSString *)kSecClass];
//    [theQueryDict setObject:inAccount forKey:(__bridge id)kSecAttrAccount];
//    [theQueryDict setObject:inLabel forKey:(__bridge id)kSecAttrLabel];
//    [theQueryDict setObject:inService forKey:(__bridge id)kSecAttrService];
//    [theQueryDict setObject:(id)kCFBooleanTrue forKey:(__bridge_transfer id)kSecReturnData];
//    
//    CFDataRef thePWData = nil;
//    OSStatus theStatus = SecItemCopyMatching((__bridge CFDictionaryRef)theQueryDict, (CFTypeRef*)&thePWData);
//    NSLog(@"Keychain status: %ld", (long)theStatus);
//    if(theStatus == errSecSuccess){
//    NSData *result = (__bridge_transfer NSData*)thePWData;
//    return result;
//    } else {
//    return nil;
//    }
//    } else {
//    return nil;
//    }
//    }

    
}

