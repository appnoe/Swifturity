//
//  ViewController.swift
//  Swifturity
//
//  Created by Klaus Rodewig on 08.12.15.
//  Copyright © 2015 Appnö UG (haftungsbeschränkt). All rights reserved.
//

import UIKit

class ViewController: UIViewController, URLSessionDelegate {
    @IBOutlet weak var urlTextField: UITextField!
    @IBAction func writeFile(_ sender: UIButton) {
        
        // NSFileProtection
        let theFileManager = FileManager.default
        let theLocalDirectories = theFileManager.urls(for: .documentDirectory, in: .userDomainMask)
        
        guard let theDocumentsPath = theLocalDirectories.first else { fatalError() }
        let theFileURL = theDocumentsPath.appendingPathComponent("foobar.txt")
        
        let theContentString = "foobar"
        let theContentData = theContentString.data(using: String.Encoding.utf8)
        
        let theAttributes : [String : Any] = [FileAttributeKey.protectionKey.rawValue : FileProtectionType.complete]
        let theFilePath = theFileURL.path
        theFileManager.createFile(atPath: theFilePath, contents:theContentData, attributes:theAttributes)
        
        // Backup exclusion
        do {
            try (theFileURL as NSURL).setResourceValue(true, forKey: URLResourceKey.isExcludedFromBackupKey)
        } catch {
            print("Error: \(error)")
            print("Backup exclusion not set")
        }
        
        // encryption & decryption
        let thePassword = "foobar"
        let theSecret = "Lorem Ipsum Alaaf und Helau."
        // uncomment for CommonCrypto mega fail
//        let theSecret = "AAAAAAAAA"
        let theSalt = randomDataWithLength(32)
        let theHash = generateHashFromString(thePassword)
        let theKey = keyFromPassword(theHash as NSString, inSalt: theSalt as Data)
        print(theHash)
        print(theSalt)
        print(theKey)
        guard let theSecretData = theSecret.data(using: String.Encoding.utf8) else { fatalError() }
        guard let theCipherText = encryptData(theSecretData, inKey: theKey, inIV: randomDataWithLength(kCCBlockSizeAES128) as Data) else { fatalError() }        // uncomment for CommonCrypto mega fail
//        let theCipherText = encryptData(theSecret.dataUsingEncoding(NSUTF8StringEncoding)!, inKey: theSecret.dataUsingEncoding(NSUTF8StringEncoding)!, inIV: randomDataWithLength(kCCBlockSizeAES128))
        print((theCipherText))
        let theClearData = decryptData(theCipherText, inKey: theKey)!
        let theClearText = NSString(data: theClearData, encoding: String.Encoding.utf8.rawValue)
        print(theClearText as Any)
        
        guard let passswordData = thePassword.data(using: String.Encoding.utf8) else { fatalError() }
        _ = storeSecretInKeychain(passswordData, inAccount: "MyAccount", inLabel: "MyLabel", inService: "MyService")
        let theRestoredSecret = secretFromKeychain("MyAccount")!
        print(NSString(data: theRestoredSecret, encoding: String.Encoding.utf8.rawValue) as Any)
        
        
    }
    
    func generateHashFromString(_ inString : String) -> String {
        let theContext = UnsafeMutablePointer<CC_SHA256_CTX>.allocate(capacity: 1)
        var theDigest = Array<UInt8>(repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        CC_SHA256_Init(theContext)
        CC_SHA256_Update(theContext, inString, CC_LONG(inString.lengthOfBytes(using: String.Encoding.utf8)))
        CC_SHA256_Final(&theDigest, theContext)
        theContext.deallocate(capacity: 1)
        var theHash = ""
        for oneByte in theDigest {
            theHash += String(format:"%02x", oneByte)
        }
        return theHash
    }
    
    func randomDataWithLength(_ inLength : size_t) -> NSMutableData {
        guard let theData = NSMutableData(length: inLength) else { fatalError() }
        SecRandomCopyBytes(kSecRandomDefault, inLength, UnsafeMutablePointer<UInt8>(theData.mutableBytes))
        return theData
    }
    
    func keyFromPassword(_ inPassword : NSString, inSalt : Data) -> Data {
        let theEncryptionKey : NSMutableData = NSMutableData(length: kCCBlockSizeAES128)!
        let theStartTime = Date.timeIntervalSinceReferenceDate
        CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2),
                                inPassword.utf8String,
                                size_t(inPassword.length),
                                (inSalt as NSData).bytes.bindMemory(to: UInt8.self, capacity: inSalt.count),
                                size_t(inSalt.count),
                                CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                                uint(30000),
                                UnsafeMutablePointer<UInt8>(theEncryptionKey.mutableBytes),
                                size_t(theEncryptionKey.length));
        let theStopTime = Date.timeIntervalSinceReferenceDate - theStartTime
        print(theStopTime)
        return theEncryptionKey as Data
    }
    
    func encryptData(_ inData : Data, inKey : Data, inIV : Data) -> Data? {
        let theCipherText : NSMutableData = NSMutableData(length: inData.count + kCCBlockSizeAES128)!
        var outLength : Int = 0
        let theOperation : CCOperation = UInt32(kCCEncrypt)
        let theAlgorithm :  CCAlgorithm = UInt32(kCCAlgorithmAES128)
        let theOptions :   CCOptions = UInt32(kCCOptionPKCS7Padding)
        let theCCResult : CCCryptorStatus = CCCrypt(theOperation,
                                                    theAlgorithm,
                                                    theOptions,
                                                    (inKey as NSData).bytes.bindMemory(to: UInt8.self, capacity: inKey.count),
                                                    size_t(inKey.count),
                                                    (inIV as NSData).bytes.bindMemory(to: UInt8.self, capacity: inIV.count),
                                                    (inData as NSData).bytes.bindMemory(to: UInt8.self, capacity: inData.count),
                                                    size_t(inData.count),
                                                    theCipherText.mutableBytes,
                                                    size_t(theCipherText.length),
                                                    &outLength)
        if (theCCResult == 0) {
            theCipherText.length = outLength
            theCipherText.append(inIV)
            return theCipherText as Data
        } else {
            return nil
        }
    }
    
    func decryptData(_ inData : Data, inKey : Data) -> Data? {
        var outLength : Int = 0
        let theIV = inData.subdata(in: NSMakeRange(inData.count-kCCBlockSizeAES128, kCCBlockSizeAES128))
        let theCipherText = inData.subdata(in: NSMakeRange(0, inData.count-kCCBlockSizeAES128))
        guard let theClearText = NSMutableData(length: inData.count + kCCBlockSizeAES128) else { return nil }
        let theOperation : CCOperation = UInt32(kCCDecrypt)
        let theAlgorithm :  CCAlgorithm = UInt32(kCCAlgorithmAES128)
        let theOptions :   CCOptions = UInt32(kCCOptionPKCS7Padding)
        let theCCResult : CCCryptorStatus = CCCrypt(theOperation,
                                                    theAlgorithm,
                                                    theOptions,
                                                    (inKey as NSData).bytes.bindMemory(to: UInt8.self, capacity: inKey.count),
                                                    size_t(inKey.count),
                                                    (theIV as NSData).bytes.bindMemory(to: UInt8.self, capacity: theIV.count),
                                                    (theCipherText as NSData).bytes.bindMemory(to: UInt8.self, capacity: theCipherText.count),
                                                    size_t(theCipherText.count),
                                                    theClearText.mutableBytes,
                                                    size_t(theClearText.length),
                                                    &outLength)
        if(theCCResult == 0){
            theClearText.length = outLength
            return (NSData(data: theClearText as Data) as Data)
        } else {
            return nil
        }
    }
    
    func storeSecretInKeychain(_ inSecret : Data, inAccount : NSString, inLabel : NSString, inService : NSString) -> OSStatus {
        
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
        ] as [String : Any]
    
        let theWriteDict = [
            kSecClass as String             : kSecClassGenericPassword as String,
            kSecAttrAccount as String       : inAccount,
            kSecValueData as String         : inSecret,
            kSecAttrService as String       : inService,
            kSecAttrLabel as String         : inLabel,
            kSecAttrAccessible as String    : kSecAttrAccessibleWhenUnlocked
        ] as [String : Any]
        
        let theUpdateDict = [
            kSecValueData as String         : inSecret
        ]

        var theStatus = SecItemAdd(theWriteDict as CFDictionary, nil)

        if(theStatus == errSecDuplicateItem ){
            print(("Duplicate found. Updating …"))
            theStatus = SecItemUpdate(theQueryDict as CFDictionary, theUpdateDict as CFDictionary)
        }

        return theStatus
    }
    
    func secretFromKeychain(_ inAccount : NSString) -> Data? {
        let theQueryDict = [
            kSecClass as String             : kSecClassGenericPassword as String,
            kSecAttrAccount as String       : inAccount,
            kSecReturnData as String        : kCFBooleanTrue,
            kSecMatchLimit as String        : kSecMatchLimitOne
        ] as [String : Any]
        
        var theSecret : AnyObject?
        let theStatus = withUnsafeMutablePointer(to: &theSecret) { SecItemCopyMatching(theQueryDict as CFDictionary, UnsafeMutablePointer($0)) }
        
        if theStatus == errSecSuccess {
            if let data = theSecret as! Data? {
                return data
            }
        }
        return nil
    }

    func session() -> Foundation.URLSession {
        let theSessionConfiguration = URLSessionConfiguration.default
        theSessionConfiguration.protocolClasses?.insert(KMRURLProtocol.self, at: 0)
//        return NSURLSession(configuration: theSessionConfiguration)
        return Foundation.URLSession( configuration: theSessionConfiguration,
                                  delegate: self,
                             delegateQueue: nil)
    }
    
    @IBAction func requestURL(_ sender: UIButton) {
        guard let urlString = urlTextField.text else { fatalError() }
        let theURL = URL(string: urlString)
        let theURLRequest = URLRequest(url: theURL!)
        let theSession = session()
        let task = theSession.dataTask(with: theURLRequest, completionHandler: {(data, response, error) in
//        print(response)
        });
        task.resume()
        
        
        let task2 = Foundation.URLSession.shared.dataTask(with: URLRequest(url: URL(string: "https://www.google.de")!), completionHandler: { (data, response, error) -> Void in
        }) 
        
        task2.resume()
    }
    
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        if (challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust) {
            repeat {
                if let theServerTrust = challenge.protectionSpace.serverTrust {
                    var theResult = SecTrustResultType.invalid
                    if(errSecSuccess == SecTrustEvaluate(theServerTrust, &theResult)) {

                        for index in 0..<SecTrustGetCertificateCount(theServerTrust) {
                            if let theServerCertificate = SecTrustGetCertificateAtIndex(theServerTrust, index) {
                                let theServerCertificateData = SecCertificateCopyData(theServerCertificate) as CFData
                                let theData = CFDataGetBytePtr(theServerCertificateData);
                                let theSize = CFDataGetLength(theServerCertificateData);
                                let theServerCert = Data(bytes: UnsafePointer<UInt8>(theData!), count: theSize)
                                let theLocalCert = Bundle.main.path(forResource: "wikipedia", ofType: "der")
                                if let file = theLocalCert {
                                    if let theLocalCert = try? Data(contentsOf: URL(fileURLWithPath: file)) {
                                        if theServerCert == theLocalCert {
                                            completionHandler(Foundation.URLSession.AuthChallengeDisposition.useCredential, URLCredential(trust:theServerTrust))
                                            print("Certificate valid!")
                                            return
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            } while(false)
        }
        completionHandler(Foundation.URLSession.AuthChallengeDisposition.cancelAuthenticationChallenge, nil)
        print("Certificate invalid!")
    }
}

