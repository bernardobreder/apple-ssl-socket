//
//  SSLConfig.swift
//  codegenv
//
//  Created by Bernardo Breder on 11/11/16.
//
//

import Foundation

open class SSLSocketConfig {
    
    public let certFile: String?
    
    public let password: String?
    
    public let selfSigned: Bool
    
    public let certificateFilePath: String?
    
    public let keyFilePath: String?
    
    public let certificateChainFilePath: String?
    
    public init(certFile: String, password: String, selfSigned: Bool, certificateFilePath: String?, keyFilePath: String?, certificateChainFilePath: String? = nil) {
        self.certFile = certFile
        self.password = password
        self.selfSigned = selfSigned
        self.certificateFilePath = certificateFilePath
        self.keyFilePath = keyFilePath
        self.certificateChainFilePath = certificateChainFilePath
    }
    
}
