//
//  KMRURLProtocol.swift
//  Swifturity
//
//  Created by Klaus Rodewig on 14.02.16.
//  Copyright © 2016 Appnö UG (haftungsbeschränkt). All rights reserved.
//

import UIKit

class KMRURLProtocol: URLProtocol {
    
    override class func canInit(with request: URLRequest) -> Bool {
        print("Requesting URL: \(request.url!.absoluteString)")
        return false
    }
}
