//
//  NSString+KLCrypto.h
//  KLCrypto
//
//  Created by Kalan on 19/3/12.
//  Copyright (c) 2019年 Kalan. All rights reserved.
//

#import <UIKit/UIKit.h>
/**
 *  对字符串进行十六进制编解码，使用小写字母。Using lower case.
 */
@interface NSString (KLHex)
/**
 *  获取NSString对应的十六进制字符串
 *
 *  @return 十六进制字符串
 */
- (NSString * _Nullable)kl_encodeToHexString;
/**
 *  对调用`- (NSString *)kl_encodeToHexString`得到的字符串进行还原
 *
 *  @return 还原后的NSString
 */
- (NSString * _Nullable)kl_decodeFromHexString;
@end

@interface NSString (KLMDSHAHexString)
/**
 *  Message Digest 2 hex string
 *
 *  @return md2 hex string
 */
- (NSString * _Nullable)kl_MD2HexString;
/**
 *  Message Digest 4 hex string
 *
 *  @return md4 hex string
 */
- (NSString * _Nullable)kl_MD4HexString;
/**
 *  Message Digest 5 hex string
 *
 *  @return md5 hex string
 */
- (NSString * _Nullable)kl_MD5HexString;
/**
 *  Secure Hash Algorithm 1 hex string
 *
 *  @return sha1 hex string
 */
- (NSString * _Nullable)kl_SHA1HexString;
/**
 *  Secure Hash Algorithm 224 hex string
 *
 *  @return sha224 hex string
 */
- (NSString * _Nullable)kl_SHA224HexString;
/**
 *  Secure Hash Algorithm 256 hex string
 *
 *  @return sha256 hex string
 */
- (NSString * _Nullable)kl_SHA256HexString;
/**
 *  Secure Hash Algorithm 384 hex string
 *
 *  @return sha384 hex string
 */
- (NSString * _Nullable)kl_SHA384HexString;
/**
 *  Secure Hash Algorithm 512 hex string
 *
 *  @return sha512 hex string
 */
- (NSString * _Nullable)kl_SHA512HexString;
@end
