//
//  SSLSocket.swift
//  server
//
//  Created by Bernardo Breder on 04/12/16.
//  Copyright © 2016 Breder Company. All rights reserved.
//

import Foundation

public enum SSLSocketError: Error {
    case noDataFound
    case accept(String)
    case handshake
    case context(String)
    case send
    case receive
}
