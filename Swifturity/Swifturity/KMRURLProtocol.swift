//
//  KMRURLProtocol.swift
//  Swifturity
//
//  Created by Klaus Rodewig on 14.02.16.
//  Copyright © 2016 Appnö UG (haftungsbeschränkt). All rights reserved.
//

import UIKit

class KMRURLProtocol: NSURLProtocol {
    func canInitWithRequest(inRequest: NSURLRequest) -> Bool {
        print("Requesting: \(inRequest.URL?.absoluteString)")
        return false
    }
}
