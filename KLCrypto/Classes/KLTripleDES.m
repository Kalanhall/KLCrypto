//
//  KLTripleDES.m
//  KLCrypto
//
//  Created by Kalan on 19/3/12.
//  Copyright (c) 2019年 Kalan. All rights reserved.
//

#import "KLTripleDES.h"
#import "NSData+KLCrypto.h"

@implementation KLTripleDES

static KLTripleDES *sharedKLTripleDES = nil;

+ (nonnull instancetype)sharedKLTripleDES {
	static dispatch_once_t onceToken;
	dispatch_once(&onceToken, ^{
		sharedKLTripleDES = [[super allocWithZone:NULL] init];
		[sharedKLTripleDES updateKey];
		[sharedKLTripleDES updateIV];
	});
	return sharedKLTripleDES;
}

+ (id)allocWithZone:(struct _NSZone *)zone {
	return [KLTripleDES sharedKLTripleDES];
}

- (void)updateKey {
	_key = [NSData kl_generateSymmetricKeyForAlgorithm:kCCAlgorithm3DES keySize:kCCKeySize3DES];;
}

- (void)updateIV {
	_iv = [NSData kl_generateIVForAlgorithm:kCCAlgorithm3DES];
}

- (NSData * _Nullable)tripleDESEncrypt:(NSData * _Nonnull)plainData {
	return [self _doCipher:plainData operation:kCCEncrypt];
}

- (NSData * _Nullable)tripleDESDecrypt:(NSData * _Nonnull)cipherData {
	return [self _doCipher:cipherData operation:kCCDecrypt];
}

- (NSData * _Nullable)doCipher:(NSData * _Nonnull)data
                           key:(NSData * _Nonnull)key
                            iv:(NSData * _Nullable)iv
                     operation:(CCOperation)operation {
	_key = key;
	if (iv) {
		_iv = iv;
	} else {
		unsigned char bytes[kCCBlockSize3DES] = {'\0'};
		_iv = [NSData dataWithBytes:bytes length:kCCBlockSize3DES];
	}
	return [self _doCipher:data operation:operation];
}

#pragma mark - Private Methods
- (NSData * _Nullable)_doCipher:(NSData * _Nonnull)data
                      operation:(CCOperation)operation {
	return [self _doCipher:data operation:operation isPKCS7Padding:YES];
}

- (NSData * _Nullable)_doCipher:(NSData * _Nonnull)data
                      operation:(CCOperation)operation
                 isPKCS7Padding:(BOOL)isPKCS7Padding {
	return [data kl_doBlockCipherWithAlgorithm:kCCAlgorithm3DES
                                           key:self.key
                                            iv:self.iv
                                     operation:operation
                                isPKCS7Padding:isPKCS7Padding];
}
@end
