//
//  Package.swift
//  SSLSocket
//
//

import PackageDescription

let package = Package(
	name: "SSLSocket",
	targets: [
		Target(name: "SSLSocket", dependencies: ["StdSocket"]),
		Target(name: "StdSocket", dependencies: []),
	]
)

#if os(Linux)
	package.dependencies.append(.Package(url: "git@codegenv.com:OpenSSL.git", majorVersion: 1))
#endif
