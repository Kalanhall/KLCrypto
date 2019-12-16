//
//  NSString+KLCrypto.m
//  KLCrypto
//
//  Created by Kalan on 19/3/12.
//  Copyright (c) 2019年 Kalan. All rights reserved.
//

#import "NSString+KLCrypto.h"
#import "NSData+KLCrypto.h"

@implementation NSString (KLHex)

- (NSString * _Nullable)kl_encodeToHexString {
	return [[self dataUsingEncoding:NSUTF8StringEncoding] kl_encodeToHexString];
}

- (NSString * _Nullable)kl_decodeFromHexString {
	return [[NSString alloc] initWithData:[[self dataUsingEncoding:NSUTF8StringEncoding] kl_decodeFromHexData] encoding:NSUTF8StringEncoding];
}
@end

@implementation NSString (KLMDSHAHexString)

- (NSString * _Nullable)kl_MD2HexString {
    return [[self dataUsingEncoding:NSUTF8StringEncoding] kl_MD2HexString];
}

- (NSString * _Nullable)kl_MD4HexString {
    return [[self dataUsingEncoding:NSUTF8StringEncoding] kl_MD4HexString];
}

- (NSString * _Nullable)kl_MD5HexString {
    return [[self dataUsingEncoding:NSUTF8StringEncoding] kl_MD5HexString];
}

- (NSString * _Nullable)kl_SHA1HexString {
    return [[self dataUsingEncoding:NSUTF8StringEncoding] kl_SHA1HexString];
}

- (NSString * _Nullable)kl_SHA224HexString {
    return [[self dataUsingEncoding:NSUTF8StringEncoding] kl_SHA224HexString];
}

- (NSString * _Nullable)kl_SHA256HexString {
    return [[self dataUsingEncoding:NSUTF8StringEncoding] kl_SHA256HexString];
}

- (NSString * _Nullable)kl_SHA384HexString {
    return [[self dataUsingEncoding:NSUTF8StringEncoding] kl_SHA384HexString];
}

- (NSString * _Nullable)kl_SHA512HexString {
    return [[self dataUsingEncoding:NSUTF8StringEncoding] kl_SHA512HexString];
}

@end
