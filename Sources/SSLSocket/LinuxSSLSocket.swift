//
//  LinuxSSLSocket.swift
//  server
//
//  Created by Bernardo Breder on 03/12/16.
//  Copyright © 2016 Breder Company. All rights reserved.
//

import Foundation

#if os(Linux)
    
#if SWIFT_PACKAGE
    import StdSocket
    import OpenSSL
#endif
    
    public struct SSLSocketServer {
        
        let config: SSLSocketConfig
        
        let context: UnsafeMutablePointer<SSL_CTX>
        
    }
    
    public struct SSLSocketClient {
        
        let fd: Int32
        
        let ssl: UnsafeMutablePointer<SSL>
        
    }
    
    open class SSLSocket {
        
        static var method: UnsafePointer<SSL_METHOD>?
        
        public class func initialize() {
            if SSLSocket.method == nil {
                SSL_library_init()
                SSL_load_error_strings()
                OPENSSL_config(nil)
                OPENSSL_add_all_algorithms_conf()
                SSLSocket.method = SSLv23_server_method()
            }
        }
        
        public class func create(config: SSLSocketConfig) throws -> SSLSocketServer {
            let context = try SSLSocket.createContext(config: config)
            return SSLSocketServer(config: config, context: context)
        }
        
        public class func accept(_ sd: SSLSocketServer, fd: Int32) throws -> SSLSocketClient {
            guard let ssl = SSL_new(sd.context) else { throw SSLSocketError.context("Can not create a client context") }
            if SSL_set_fd(ssl, fd) == 1 {
                if SSL_accept(ssl) == 1 {
                    return SSLSocketClient(fd: fd, ssl: ssl)
                }
            }
            SSL_shutdown(ssl)
            SSL_free(ssl)
            throw SSLSocketError.context("Can not assign client socket with ssl context")
        }
        
        public class func close(server: SSLSocketServer) {
            SSL_CTX_free(server.context)
        }
        
        public class func receive(_ client: SSLSocketClient, count: Int) throws -> Data {
            var buffer: UnsafeMutablePointer<UInt8> = UnsafeMutablePointer<UInt8>.allocate(capacity: count)
            defer { buffer.deinitialize() }
            let readed = Int(SSL_read(client.ssl, buffer, Int32(count)))
            guard readed >= 0 else { throw SSLSocketError.receive }
            var data: Data = Data(capacity: readed)
            data.append(buffer, count: readed)
            return data
        }
        
        public class func send(_ client: SSLSocketClient, data: Data) throws {
            guard data.withUnsafeBytes({ (pointee: UnsafePointer<Int>) -> Int in
                return Int(SSL_write(client.ssl, pointee, Int32(data.count)))
            }) == data.count else { throw SSLSocketError.send }
        }
        
        public class func close(client: SSLSocketClient) {
            SSL_shutdown(client.ssl)
            SSL_free(client.ssl)
        }
        
        fileprivate class func createContext(config: SSLSocketConfig) throws -> UnsafeMutablePointer<SSL_CTX> {
            let cipherSuite = "ALL:!ADH:!EXPORT56:RC4+RSA:+HIGH:+MEDIUM:+LOW:+SSLv2:+EXP:+eNULL"
            guard let context = SSL_CTX_new(SSLSocket.method) else { throw SSLSocketError.context("Can not create a context") }
            SSL_CTX_set_cipher_list(context, cipherSuite)
            if config.selfSigned { SSL_CTX_set_verify(context, SSL_VERIFY_NONE, nil) }
            SSL_CTX_set_verify_depth(context, 2)
            if let certFilePath = config.certificateFilePath {
                guard let _ = NSData(contentsOfFile: certFilePath) else { throw SSLSocketError.context("To use Certificate File, not found: \(certFilePath)") }
                guard SSL_CTX_use_certificate_file(context, certFilePath, SSL_FILETYPE_PEM) > 0 else { throw SSLSocketError.context("Can not use the Certificate File: \(certFilePath)") }
            }
            if let keyFilePath = config.keyFilePath {
                guard let _ = NSData(contentsOfFile: keyFilePath) else { throw SSLSocketError.context("To use Private Key File, not found: \(keyFilePath)") }
                guard SSL_CTX_use_PrivateKey_file(context, keyFilePath, SSL_FILETYPE_PEM) > 0 else { throw SSLSocketError.context("Can not use the Private Key File: \(keyFilePath)") }
                guard SSL_CTX_check_private_key(context) > 0 else { throw SSLSocketError.context("Can not use the Private Key File: \(keyFilePath)") }
            }
            if let chainFilePath = config.certificateChainFilePath {
                guard let _ = NSData(contentsOfFile: chainFilePath) else { throw SSLSocketError.context("To use Certificate Chain File, not found: \(chainFilePath)") }
                guard SSL_CTX_use_certificate_chain_file(context, chainFilePath) > 0 else { throw SSLSocketError.context("Can not use the Certificate Chain File: \(chainFilePath)") }
            }
            return context
        }
        
    }
    
#endif
