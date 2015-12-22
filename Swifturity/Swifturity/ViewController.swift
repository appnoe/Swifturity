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
        let thePassword = "foobar"
        let theSecret = "Lorem Ipsum Alaaf und Helau."
        // uncomment for CommonCrypto mega fail
//        let theSecret = "AAAAAAAAA"
        let theSalt = randomDataWithLength(32)
        let theHash = generateHashFromString(thePassword)
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
        
        storeSecretInKeychain(thePassword.dataUsingEncoding(NSUTF8StringEncoding)!, inAccount: "MyAccount", inLabel: "MyLabel", inService: "MyService")
        let theRestoredSecret = secretFromKeychain("MyAccount")!
        print(NSString(data: theRestoredSecret, encoding: NSUTF8StringEncoding))
        
        
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
    
    func storeSecretInKeychain(inSecret : NSData, inAccount : NSString, inLabel : NSString, inService : NSString) -> OSStatus {
        
        //errSecSuccess                = 0       No error.
        //errSecUnimplemented          = -4      Function or operation not implemented.
        //errSecParam                  = -50     One or more parameters passed to a function where not valid.
        //errSecAllocate               = -108    Failed to allocate memory.
        //errSecNotAvailable           = -25291  No keychain is available. You may need to restart your computer.
        //errSecDuplicateItem          = -25299  The specified item already exists in the keychain.
        //errSecItemNotFound           = -25300  The specified item could not be found in the keychain.
        //errSecInteractionNotAllowed  = -25308  User interaction is not allowed.
        //errSecDecode                 = -26275  Unable to decode the provided data.
        //errSecAuthFailed             = -25293  The user name or passphrase you entered is not correct.
        
        let theQueryDict = [
            kSecClass as String             : kSecClassGenericPassword as String,
            kSecAttrAccount as String       : inAccount
        ]
    
        let theWriteDict = [
            kSecClass as String             : kSecClassGenericPassword as String,
            kSecAttrAccount as String       : inAccount,
            kSecValueData as String         : inSecret,
            kSecAttrService as String       : inService,
            kSecAttrLabel as String         : inLabel,
            kSecAttrAccessible as String    : kSecAttrAccessibleWhenUnlocked
        ]
        
        let theUpdateDict = [
            kSecValueData as String         : inSecret
        ]

        var theStatus = SecItemAdd(theWriteDict as CFDictionaryRef, nil)

        if(theStatus == errSecDuplicateItem ){
            print(("Duplicate found. Updating …"))
            theStatus = SecItemUpdate(theQueryDict as CFDictionaryRef, theUpdateDict as CFDictionaryRef)
        }

        return theStatus
    }
    
    func secretFromKeychain(inAccount : NSString) -> NSData? {
        let theQueryDict = [
            kSecClass as String             : kSecClassGenericPassword as String,
            kSecAttrAccount as String       : inAccount,
            kSecReturnData as String        : kCFBooleanTrue,
            kSecMatchLimit as String        : kSecMatchLimitOne
        ]
        
        var theSecret : AnyObject?
        let theStatus = withUnsafeMutablePointer(&theSecret) { SecItemCopyMatching(theQueryDict, UnsafeMutablePointer($0)) }
        
        if theStatus == errSecSuccess {
            if let data = theSecret as! NSData? {
                return data
            }
        }
        return nil
    }
    
}

