//
//  SSLSocket.swift
//  server
//
//  Created by Bernardo Breder on 03/12/16.
//  Copyright © 2016 Breder Company. All rights reserved.
//

import Foundation

#if os(macOS)
    
#if SWIFT_PACKAGE
    import StdSocket
#endif
    
    public struct SSLSocketServer {
        
        let config: SSLSocketConfig
        
    }
    
    public struct SSLSocketClient {
        
        let fd: Int32
        
        let socketPtr: UnsafeMutablePointer<Int32>
        
        let context: SSLContext
        
    }
    
    open class SSLSocket {
        
        public class func initialize() {
        }
        
        public class func create(config: SSLSocketConfig) throws -> SSLSocketServer {
            return SSLSocketServer(config: config)
        }
        
        public class func accept(_ sd: SSLSocketServer, fd: Int32) throws -> SSLSocketClient {
            let context: SSLContext = try SSLSocket.createContext(config: sd.config)
            let socketPtr = UnsafeMutablePointer<Int32>.allocate(capacity: 1)
            socketPtr.pointee = fd
            guard SSLSetConnection(context, socketPtr) == errSecSuccess else { throw SSLSocketError.accept("Can not assign connection") }
            var status: OSStatus; repeat { status = SSLHandshake(context) } while status == errSSLWouldBlock
            guard status == errSecSuccess else { throw SSLSocketError.handshake }
            return SSLSocketClient(fd: fd, socketPtr: socketPtr, context: context)
        }
        
        public class func close(server: SSLSocketServer) {
        }
        
        public class func receive(_ client: SSLSocketClient, count: Int) throws -> Data {
            var buffer: UnsafeMutablePointer<UInt8> = UnsafeMutablePointer<UInt8>.allocate(capacity: count)
            defer { buffer.deinitialize() }
            var readed: Int = 0
            SSLRead(client.context, buffer, count, &readed)
            guard readed >= 0 else { throw SSLSocketError.noDataFound }
            var data: Data = Data.init(capacity: readed)
            data.append(buffer, count: readed)
            return data
        }
        
        public class func send(_ client: SSLSocketClient, data: Data) throws {
            try data.withUnsafeBytes({ (pointee: UnsafePointer<Int>) throws -> Void in
                var processed = 0
                SSLWrite(client.context, pointee, data.count, &processed)
                guard processed == data.count else { throw SSLSocketError.send }
            })
        }
        
        public class func close(client: SSLSocketClient) {
            SSLClose(client.context)
            client.socketPtr.deallocate(capacity: 1)
        }
        
        fileprivate class func createContext(config: SSLSocketConfig) throws -> SSLContext {
            guard let certFile = config.certFile else { throw SSLSocketError.context("Certificate File not assigned") }
            let cipherSuite = "14,13,2B,2F,2C,30,9E,9F,23,27,09,28,13,24,0A,14,67,33,6B,39,08,12,16,9C,9D,3C,3D,2F,35,0A"
            guard let context = SSLCreateContext(kCFAllocatorDefault, .serverSide, SSLConnectionType.streamType) else { throw SSLSocketError.context("Can not create a context") }
            guard SSLSetIOFuncs(context, readCallback, writeCallback) == errSecSuccess else { throw SSLSocketError.context("Can not assign read and write callback") }
            guard let p12Data = NSData(contentsOfFile: certFile) else { throw SSLSocketError.context("To use Certificate P12, not found: \(certFile)") }
            let key: NSString = kSecImportExportPassphrase as NSString
            let options: NSDictionary = [key: config.password as AnyObject]
            var items: CFArray? = nil
            guard SecPKCS12Import(p12Data, options, &items) == errSecSuccess else { throw SSLSocketError.context("Can not import PKCS12") }
            let dictionary: AnyObject = (items! as [AnyObject] as NSArray).object(at: 0) as AnyObject
            guard let secIdentity = dictionary.value(forKey: "identity") else { throw SSLSocketError.context("Can not get the identity") }
            var certs = [secIdentity]
            guard let ccerts: Array<SecCertificate> = dictionary.value(forKey: kSecImportItemCertChain as String) as? Array<SecCertificate> else { throw SSLSocketError.context("Can not get certificate imported") }
            for i in 1 ..< ccerts.count {
                certs += [ccerts[i] as AnyObject]
            }
            guard SSLSetCertificate(context, certs as CFArray) == errSecSuccess else { throw SSLSocketError.context("Can not set the certificate") }
            let cipherlist = cipherSuite.components(separatedBy: ",")
            let eSize = cipherlist.count * MemoryLayout<SSLCipherSuite>.size
            let eCipherSuites: UnsafeMutablePointer<SSLCipherSuite> = UnsafeMutablePointer.allocate(capacity: eSize)
            for i in 0..<cipherlist.count {
                eCipherSuites.advanced(by: i).pointee = SSLCipherSuite(cipherlist[i], radix: 16)!
            }
            guard SSLSetEnabledCiphers(context, eCipherSuites, cipherlist.count) == errSecSuccess else { throw SSLSocketError.context("Can not enable cipher") }
            return context
        }
        
    }
    
    private func readCallback(connection: SSLConnectionRef, data: UnsafeMutableRawPointer, dataLength: UnsafeMutablePointer<Int>) -> OSStatus {
        let socketfd = connection.assumingMemoryBound(to: Int32.self).pointee
        let bytesRequested = dataLength.pointee
        let bytesRead = read(socketfd, data, bytesRequested)
        if bytesRead > 0 {
            dataLength.initialize(to: bytesRead)
            if bytesRequested > bytesRead {
                return OSStatus(errSSLWouldBlock)
            } else {
                return noErr
            }
        } else if bytesRead == 0 {
            dataLength.initialize(to: 0)
            return OSStatus(errSSLClosedGraceful)
        } else {
            dataLength.initialize(to: 0)
            switch errno {
            case ENOENT:
                return OSStatus(errSSLClosedGraceful)
            case EAGAIN:
                return OSStatus(errSSLWouldBlock)
            case ECONNRESET:
                return OSStatus(errSSLClosedAbort)
            default:
                return OSStatus(errSecIO)
            }
        }
    }
    
    private func writeCallback(connection: SSLConnectionRef, data: UnsafeRawPointer, dataLength: UnsafeMutablePointer<Int>) -> OSStatus {
        let socketfd = connection.assumingMemoryBound(to: Int32.self).pointee
        let bytesToWrite = dataLength.pointee
        let bytesWritten = write(socketfd, data, bytesToWrite)
        if bytesWritten > 0 {
            dataLength.initialize(to: bytesWritten)
            if bytesToWrite > bytesWritten {
                return Int32(errSSLWouldBlock)
            } else {
                return noErr
            }
        } else if bytesWritten == 0 {
            dataLength.initialize(to: 0)
            return OSStatus(errSSLClosedGraceful)
        } else {
            dataLength.initialize(to: 0)
            if errno == EAGAIN {
                return OSStatus(errSSLWouldBlock)
            } else {
                return OSStatus(errSecIO)
            }
        }
    }
    
#endif
