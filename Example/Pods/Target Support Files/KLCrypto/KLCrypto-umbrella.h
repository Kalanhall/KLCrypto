#ifdef __OBJC__
#import <UIKit/UIKit.h>
#else
#ifndef FOUNDATION_EXPORT
#if defined(__cplusplus)
#define FOUNDATION_EXPORT extern "C"
#else
#define FOUNDATION_EXPORT extern
#endif
#endif
#endif

#import "KLAES.h"
#import "KLRSA.h"
#import "KLTripleDES.h"
#import "NSData+KLCrypto.h"
#import "NSString+KLCrypto.h"

FOUNDATION_EXPORT double KLCryptoVersionNumber;
FOUNDATION_EXPORT const unsigned char KLCryptoVersionString[];

