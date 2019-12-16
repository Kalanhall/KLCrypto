//
//  KLAES.m
//  KLCrypto
//
//  Created by Kalan on 19/3/12.
//  Copyright (c) 2019年 Kalan. All rights reserved.
//

#import "KLAES.h"
#import "NSData+KLCrypto.h"

@implementation KLAES

static KLAES *sharedKLAES = nil;

+ (nonnull instancetype)sharedKLAES {
	static dispatch_once_t onceToken;
	dispatch_once(&onceToken, ^{
		sharedKLAES = [[super allocWithZone:NULL] init];
		[sharedKLAES updateKeyWithKeySize:kCCKeySizeAES256];
		[sharedKLAES updateIV];
	});
	return sharedKLAES;
}

+ (id)allocWithZone:(struct _NSZone *)zone {
	return [KLAES sharedKLAES];
}

- (void)updateKeyWithKeySize:(unsigned int)keySize {
	NSParameterAssert(keySize == kCCKeySizeAES128 ||
					  keySize == kCCKeySizeAES192 ||
					  keySize == kCCKeySizeAES256);
	_key = [NSData kl_generateSymmetricKeyForAlgorithm:kCCAlgorithmAES keySize:keySize];
}

- (void)updateIV {
	_iv = [NSData kl_generateIVForAlgorithm:kCCAlgorithmAES];
}

- (NSData * _Nullable)AES128Encrypt:(NSData * _Nonnull)plainData {
	if (self.key.length != kCCKeySizeAES128) {
		[self updateKeyWithKeySize:kCCKeySizeAES128];
	}
	return [self _doCipher:plainData
                 operation:kCCEncrypt];
}

- (NSData * _Nullable)AES128Decrypt:(NSData * _Nonnull)cipherData {
	return [self _doCipher:cipherData
                 operation:kCCDecrypt];
}

- (NSData * _Nullable)AES192Encrypt:(NSData * _Nonnull)plainData {
	if (self.key.length != kCCKeySizeAES192) {
		[self updateKeyWithKeySize:kCCKeySizeAES192];
	}
	return [self _doCipher:plainData
                 operation:kCCEncrypt];
}
- (NSData * _Nullable)AES192Decrypt:(NSData * _Nonnull)cipherData {
	return [self _doCipher:cipherData
                 operation:kCCDecrypt];
}
- (NSData * _Nullable)AES256Encrypt:(NSData * _Nonnull)plainData {
	if (self.key.length != kCCKeySizeAES256) {
		[self updateKeyWithKeySize:kCCKeySizeAES256];
	}
	return [self _doCipher:plainData
                 operation:kCCEncrypt];
}
- (NSData * _Nullable)AES256Decrypt:(NSData * _Nonnull)cipherData {
	return [self _doCipher:cipherData
                 operation:kCCDecrypt];
}

- (NSData * _Nullable)doCipher:(NSData * _Nonnull)data
                           key:(NSData * _Nonnull)key
                            iv:(NSData * _Nullable)iv
                     operation:(CCOperation)operation {
	_key = key;
	if (iv) {
		_iv = iv;
	} else {
		unsigned char bytes[kCCBlockSizeAES128] = {'\0'};
		_iv = [NSData dataWithBytes:bytes length:kCCBlockSizeAES128];
	}
	return [self _doCipher:data
                 operation:operation];
}

#pragma mark - Private Methods
- (NSData *)_doCipher:(NSData *)data
            operation:(CCOperation)operation {
	return [self _doCipher:data
                 operation:operation
            isPKCS7Padding:YES];
}
- (NSData *)_doCipher:(NSData *)data
            operation:(CCOperation)operation
       isPKCS7Padding:(BOOL)isPKCS7Padding {
	return [data kl_doBlockCipherWithAlgorithm:kCCAlgorithmAES
                                           key:self.key
                                            iv:self.iv
                                     operation:operation
                                isPKCS7Padding:isPKCS7Padding];
}
@end
