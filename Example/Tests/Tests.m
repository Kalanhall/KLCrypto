//
//  KLCryptoTests.m
//  KLCryptoTests
//
//  Created by Kalanhall@163.com on 12/16/2019.
//  Copyright (c) 2019 Kalanhall@163.com. All rights reserved.
//

@import XCTest;
@import KLCrypto;

#define kText @"加密文本加密文本加密文本加密文本加密文本加密文本加密文本加密文本加密文本加密文本加密文本加密文本"
#define kBase64PublicKey @"MIID5DCCAsygAwIBAgIBATALBgkqhkiG9w0BAQswdzEUMBIGA1UEAwwLRGFuaWF0\
ZUNlcnQxEDAOBgNVBAoMB0RhbmlhdGUxDzANBgNVBAgMBuS4iua1tzELMAkGA1UE\
BhMCQ04xDzANBgNVBAcMBuS4iua1tzEeMBwGCSqGSIb3DQEJARYPZGFuaWF0ZUAx\
MjYuY29tMB4XDTE1MDUxODA0MDUzN1oXDTI1MDUxNTA0MDUzN1owdzEUMBIGA1UE\
AwwLRGFuaWF0ZUNlcnQxEDAOBgNVBAoMB0RhbmlhdGUxDzANBgNVBAgMBuS4iua1\
tzELMAkGA1UEBhMCQ04xDzANBgNVBAcMBuS4iua1tzEeMBwGCSqGSIb3DQEJARYP\
ZGFuaWF0ZUAxMjYuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA\
rmkRfH8qROmgDaKdhNVP/hD58Nb+w7l/yM4mbYY6XUcGnFEI44lcNem/m6qUVR+T\
2xMqeOYHdJ7SogufHNphnZsi1hljVYOoS/ZZaotTBOvio+nQE41CTNSo3h8pinNh\
Lus1vv35aXkGA4SW0ZwRc8/CrJo4ZPtkO92K+T+yIfC+57Ct12PHu1Z3q2SjFKds\
GWC5xcfBDdUcnZMONky0mTI0vJSNllAtiDqsVAtM8X7z/3vAbbGV16stg2RUAR3c\
TBEHAoG/BuW2cNEWO8F6cn0sXyAqOcYaNQGBgVxJKrICYdcZ2MX1GHbU0W7FK25D\
Xz1+d/JAWFyVO0zNHcbZCQIDAQABo30wezAPBgNVHQ8BAf8EBQMDB/+AMEwGA1Ud\
JQEB/wRCMEAGCCsGAQUFBwMEBggrBgEFBQcDAgYIKwYBBQUHAwEGCCsGAQUFBwMD\
BgcrBgEFAgMEBgcrBgEFAgMFBgRVHSUAMBoGA1UdEQQTMBGBD2RhbmlhdGVAMTI2\
LmNvbTANBgkqhkiG9w0BAQsFAAOCAQEAhHcLDksfL6JrDPS6NuP/dIkZkU0efDGh\
MvensDjebys4OHTZ+JRUB/WrGQG9z4NULQCyUu2U19O6J//TJPnHznRwHJFuUsmz\
yrSAyRUsBv90L4g+phzQWCl3ECTwft+n/L73CJLNC+HZPZsMJSr41meOv7I7RXGY\
IgqwaDQYsl5tB7BUmVqVIHoCzndhvpTF84UJyMlOCDeaZFY85Jjfokjnz9AFDaiF\
AnWUvec39pTE48Lpw6Hv0AEoKIj9LUM9WFqX33qv6ZNcOhYnFIlXcmD2EH2fuojn\
AykJuj5Zp2mz4r8uf6yBhORuG3mIXZzUIeH1WlTDOYoxNXJxbUHjWg=="

@interface Tests : XCTestCase

@property (nonatomic, copy) NSData *plainData;

@end

@implementation Tests

- (void)setUp
{
    [super setUp];
    // Put setup code here. This method is called before the invocation of each test method in the class.
    
    self.plainData = [kText dataUsingEncoding:NSUTF8StringEncoding];
    NSUInteger length = self.plainData.length;
    NSLog(@"plainText length - %lu", (unsigned long)kText.length);
    NSLog(@"plainData length - %lu", (unsigned long)length);
    NSLog(@"长度%@DES分组大小", length >= kCCBlockSizeDES ? @"不小于" : @"小于");
    NSLog(@"长度%@3DES分组大小", length >= kCCBlockSize3DES ? @"不小于" : @"小于");
    NSLog(@"长度%@AES分组大小", length >= kCCBlockSizeAES128 ? @"不小于" : @"小于");
}

- (void)tearDown
{
    // Put teardown code here. This method is called after the invocation of each test method in the class.
    [super tearDown];
}

- (void)testSecurePRNG {
    u_int32_t rndLen = arc4random_uniform(2018) + 1;
    NSData *randomData = [NSData kl_generateSecureRandomData:rndLen];
    NSString *rndStr = [randomData kl_encodeToHexString];
    NSLog(@"random - %@", rndStr);
    XCTAssertNotNil(randomData, @"Secure PRNG: 安全伪随机数为空");
}

- (void)testDES {
    CCAlgorithm alg = kCCAlgorithmDES;
    NSData *key = [NSData kl_generateSymmetricKeyForAlgorithm:alg];
    NSData *iv = nil;
    if (arc4random_uniform(2) == 0) {
        iv = [NSData kl_generateIVForAlgorithm:alg];
    }
    NSLog(@"iv - %@", [iv kl_encodeToHexString]);
    BOOL isPKCS7Padding = (arc4random_uniform(2) == 0);
    BOOL isECB = (arc4random_uniform(2) == 0);
    NSLog(@"DES isPKCS7Padding - %@ isECB - %@", isPKCS7Padding ? @"YES" : @"NO", isECB ? @"YES" : @"NO");
    NSData *cipherData = [self.plainData kl_doBlockCipherWithAlgorithm:alg key:key iv:iv operation:kCCEncrypt isPKCS7Padding:isPKCS7Padding isECB:isECB];
    NSData *plainData_ = [cipherData kl_doBlockCipherWithAlgorithm:alg key:key iv:iv operation:kCCDecrypt isPKCS7Padding:isPKCS7Padding isECB:isECB];
    NSString *text = [[NSString alloc] initWithData:plainData_ encoding:NSUTF8StringEncoding];
    unichar uc = [text characterAtIndex:text.length - 1];
    NSLog(@"%x", uc);
    NSLog(@"text - <<< %@ >>>", text);
    XCTAssert([kText isEqualToString:[text stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]]], @"DES: 原始数据与解密出来的数据不一致");
}

- (void)testCAST {
    CCAlgorithm alg = kCCAlgorithmCAST;
    NSData *key = [NSData kl_generateSymmetricKeyForAlgorithm:alg];
    NSData *iv = nil;
    if (arc4random_uniform(2)) {
        iv = [NSData kl_generateIVForAlgorithm:alg];
    }
    NSLog(@"iv - %@", [iv kl_encodeToHexString]);
    BOOL isPKCS7Padding = (arc4random_uniform(2));
    BOOL isECB = (arc4random_uniform(2));
    NSLog(@"CAST isPKCS7Padding - %@ isECB - %@", isPKCS7Padding ? @"YES" : @"NO", isECB ? @"YES" : @"NO");
    NSData *cipherData = [self.plainData kl_doBlockCipherWithAlgorithm:alg key:key iv:iv operation:kCCEncrypt isPKCS7Padding:isPKCS7Padding isECB:isECB];
    NSData *plainData_ = [cipherData kl_doBlockCipherWithAlgorithm:alg key:key iv:iv operation:kCCDecrypt isPKCS7Padding:isPKCS7Padding isECB:isECB];
    NSString *text = [[NSString alloc] initWithData:plainData_ encoding:NSUTF8StringEncoding];
    NSLog(@"text - |%@|", text);
    XCTAssert([kText isEqualToString:text], @"CAST: 原始数据与解密出来的数据不一致");
}

- (void)testRC2 {
    CCAlgorithm alg = kCCAlgorithmRC2;
    NSData *key = [NSData kl_generateSymmetricKeyForAlgorithm:alg];
    NSData *iv = nil;
    if (arc4random_uniform(2)) {
        iv = [NSData kl_generateIVForAlgorithm:alg];
    }
    NSLog(@"iv - %@", [iv kl_encodeToHexString]);
    BOOL isPKCS7Padding = (arc4random_uniform(2));
    BOOL isECB = (arc4random_uniform(2));
    NSLog(@"RC2 isPKCS7Padding - %@ isECB - %@", isPKCS7Padding ? @"YES" : @"NO", isECB ? @"YES" : @"NO");
    NSData *cipherData = [self.plainData kl_doBlockCipherWithAlgorithm:alg key:key iv:iv operation:kCCEncrypt isPKCS7Padding:isPKCS7Padding isECB:isECB];
    NSData *plainData_ = [cipherData kl_doBlockCipherWithAlgorithm:alg key:key iv:iv operation:kCCDecrypt isPKCS7Padding:isPKCS7Padding isECB:isECB];
    NSString *text = [[NSString alloc] initWithData:plainData_ encoding:NSUTF8StringEncoding];
    NSLog(@"text - |%@|", text);
    XCTAssert([kText isEqualToString:text], @"RC2: 原始数据与解密出来的数据不一致");
}

- (void)testBlowfish {
    CCAlgorithm alg = kCCAlgorithmBlowfish;
    NSData *key = [NSData kl_generateSymmetricKeyForAlgorithm:alg];
    NSData *iv = nil;
    if (arc4random_uniform(2)) {
        iv = [NSData kl_generateIVForAlgorithm:alg];
    }
    NSLog(@"iv - %@", [iv kl_encodeToHexString]);
    BOOL isPKCS7Padding = (arc4random_uniform(2));
    BOOL isECB = (arc4random_uniform(2));
    NSLog(@"Blowfish isPKCS7Padding - %@ isECB - %@", isPKCS7Padding ? @"YES" : @"NO", isECB ? @"YES" : @"NO");
    NSData *cipherData = [self.plainData kl_doBlockCipherWithAlgorithm:alg key:key iv:iv operation:kCCEncrypt isPKCS7Padding:isPKCS7Padding isECB:isECB];
    NSData *plainData_ = [cipherData kl_doBlockCipherWithAlgorithm:alg key:key iv:iv operation:kCCDecrypt isPKCS7Padding:isPKCS7Padding isECB:isECB];
    NSString *text = [[NSString alloc] initWithData:plainData_ encoding:NSUTF8StringEncoding];
    NSLog(@"text - |%@|", text);
    XCTAssert([kText isEqualToString:text], @"Blowfish: 原始数据与解密出来的数据不一致");
}

- (void)test3DES {
    KLTripleDES *tripleDES = [KLTripleDES sharedKLTripleDES];
    NSData *cipherData = [tripleDES tripleDESEncrypt:self.plainData];
    NSData *plainData_ = [tripleDES tripleDESDecrypt:cipherData];
    NSString *text = [[NSString alloc] initWithData:plainData_ encoding:NSUTF8StringEncoding];
    XCTAssert([kText isEqualToString:text], @"3DES: 原始数据与解密出来的数据不一致");
    
    // IV is NULL
    NSData *key = [NSData kl_generateSymmetricKeyForAlgorithm:kCCAlgorithm3DES];
    cipherData = [tripleDES doCipher:self.plainData key:key iv:nil operation:kCCEncrypt];
    plainData_ = [tripleDES doCipher:cipherData key:key iv:nil operation:kCCDecrypt];
    text = [[NSString alloc] initWithData:plainData_ encoding:NSUTF8StringEncoding];
    NSLog(@"text - |%@|", text);
    XCTAssert([kText isEqualToString:text], @"AES: 原始数据与解密出来的数据不一致");
}
/**
 *  AES
 */
- (void)testAES {
    KLAES *aes = [KLAES sharedKLAES];
    [aes updateKeyWithKeySize:kCCKeySizeAES256];
    [aes updateIV];
    NSLog(@"AES key - %@", [aes.key kl_encodeToHexString]);
    NSLog(@"AES  iv - %@", [aes.iv kl_encodeToHexString]);
    NSData *cipherData = [aes AES256Encrypt:self.plainData];
    NSData *plainData_ = [aes AES256Decrypt:cipherData];
    NSString *text = [[NSString alloc] initWithData:plainData_ encoding:NSUTF8StringEncoding];
    NSLog(@"text - |%@|", text);
    XCTAssert([kText isEqualToString:text], @"AES: 原始数据与解密出来的数据不一致");
    
    // IV is NULL
    NSData *key = [NSData kl_generateSymmetricKeyForAlgorithm:kCCAlgorithmAES];
    cipherData = [aes doCipher:self.plainData key:key iv:nil operation:kCCEncrypt];
    plainData_ = [aes doCipher:cipherData key:key iv:nil operation:kCCDecrypt];
    text = [[NSString alloc] initWithData:plainData_ encoding:NSUTF8StringEncoding];
    NSLog(@"text - |%@|", text);
    XCTAssert([kText isEqualToString:text], @"AES: 原始数据与解密出来的数据不一致");
}
/**
 *  RSA
 */
- (void)testRSA {
    KLRSA *rsa = [KLRSA sharedKLRSA];
    NSString *path = [[NSBundle bundleForClass:[self class]] pathForResource:@"KalanCert" ofType:@"p12"];
    XCTAssert(path, @"未能找到p12文件");
    // p12文件的密码为111111
    BOOL success = [rsa keysFromPersonalInformationExchangeFile:path password:@"111111"];
    XCTAssertTrue(success, @"未能成功获取RSA公私钥");
    NSLog(@"rsa private key - %@", rsa.privateKey);
    NSLog(@"rsa public  key - %@", rsa.publicKey);
    size_t privateBlockSize = SecKeyGetBlockSize(rsa.privateKey);
    size_t publicBlockSize = SecKeyGetBlockSize(rsa.publicKey);
    NSLog(@"分组大小: %zd %zd", privateBlockSize, publicBlockSize);
    NSData *cipherData = [rsa encryptDataWithPublicKey:self.plainData];
    NSData *plainData_ = [rsa decryptDataWithPrivateKey:cipherData];
    NSString *text = [[NSString alloc] initWithData:plainData_ encoding:NSUTF8StringEncoding];
    NSLog(@"text - |%@|", text);
    XCTAssert([kText isEqualToString:text], @"RSA: 原始数据与解密出来的数据不一致");
}

- (void)testLoadPublicKeyFromCert {
    KLRSA *rsa = [KLRSA sharedKLRSA];
    SecKeyRef publicKeyOld = rsa.publicKey;
    NSLog(@"before - %@", publicKeyOld);
    NSString *path = [[NSBundle bundleForClass:[self class]] pathForResource:@"KalanCert" ofType:@"cer"];
    if ([rsa publicKeyFromDERData:[NSData dataWithContentsOfFile:path]]) {
        NSLog(@"after - %@", rsa.publicKey);
    }
    XCTAssert(YES);
}

- (void)testLoadPublicKeyFromBase64CertData {
    NSData *certData = [NSData kl_base64DecodedDataWithString:kBase64PublicKey];
    KLRSA *rsa = [KLRSA sharedKLRSA];
    SecKeyRef publicKeyOld = rsa.publicKey;
    NSLog(@"before - %@", publicKeyOld);
    if ([rsa publicKeyFromDERData:certData]) {
        NSLog(@"after - %@", rsa.publicKey);
    }
    XCTAssert(YES);
}

/**
 *  数字签名
 */
- (void)testDigitalSignature {
    KLRSA *rsa = [KLRSA sharedKLRSA];
    // 自iOS 5.0起，不再支持kSecPaddingPKCS1MD2、kSecPaddingPKCS1MD5
    NSArray *paddings = @[
                          //                          @(kSecPaddingPKCS1MD2),/* Unsupported as of iOS 5.0 */
                          //                          @(kSecPaddingPKCS1MD5),/* Unsupported as of iOS 5.0 */
                          @(kSecPaddingPKCS1SHA1),
                          @(kSecPaddingPKCS1SHA224),
                          @(kSecPaddingPKCS1SHA256),
                          @(kSecPaddingPKCS1SHA384),
                          @(kSecPaddingPKCS1SHA512),
                          ];
    uint32_t idx = arc4random_uniform((uint32_t)paddings.count);
    NSNumber *padding = paddings[idx];
    rsa.padding = padding.unsignedIntValue;
    NSLog(@"padding - %x", rsa.padding);
    NSLog(@"rsa private key - %@", rsa.privateKey);
    NSLog(@"rsa public  key - %@", rsa.publicKey);
    NSData *sigData = [rsa signDataWithPrivateKey:self.plainData];
    XCTAssert(sigData != nil, @"签名失败");
    BOOL success = [rsa verifyDataWithPublicKey:self.plainData digitalSignature:sigData];
    XCTAssert(success, @"验签失败");
}

- (void)testHex {
    NSData *hex = [self.plainData kl_encodeToHexData];
    NSData *plainData_ = [hex kl_decodeFromHexData];
    NSString *text = [[NSString alloc] initWithData:plainData_ encoding:NSUTF8StringEncoding];
    XCTAssert([kText isEqualToString:text], @"Hex: 原始数据与解码后的数据不一致");
    
    NSString *hexStr = [kText kl_encodeToHexString];
    NSString *originText = [hexStr kl_decodeFromHexString];
    XCTAssert([kText isEqualToString:originText], @"Hex: 原始数据与解码后的数据不一致");
    
    // 命令`md5 -s "中华人民共和国"`，MD5 ("中华人民共和国") = 025fceab9418be86066b60a71bc71485
    NSString *s = @"中华人民共和国";
    NSString *md5_1= [[[s dataUsingEncoding:NSUTF8StringEncoding] kl_MD5] kl_encodeToHexString];
    NSString *md5_2 = [s kl_MD5HexString];
    NSLog(@"md5_1 - %@", md5_1);
    NSLog(@"md5_2 - %@", md5_2);
    XCTAssert([@"025fceab9418be86066b60a71bc71485" isEqualToString:md5_1], @"MD5结果不一致");
    XCTAssert([@"025fceab9418be86066b60a71bc71485" isEqualToString:md5_2], @"MD5结果不一致");
}

- (void)testBase64 {
    NSData *base64 = [self.plainData kl_base64EncodedData];
    NSData *plainData_ = [base64 kl_base64DecodedData];
    NSString *text = [[NSString alloc] initWithData:plainData_ encoding:NSUTF8StringEncoding];
    XCTAssert([kText isEqualToString:text], @"Base64: 原始数据与解码后的数据不一致");
}

- (void)testMD {
    NSString *md2 = [self.plainData kl_MD2HexString];
    NSString *md4 = [self.plainData kl_MD4HexString];
    // 可在命令行中使用md5命令，查看结果是否一致。例如，md5 -s "中华人民共和国"
    NSString *md5 = [self.plainData kl_MD5HexString];
    
    NSLog(@"md2 - %@", md2);
    NSLog(@"md4 - %@", md4);
    NSLog(@"md5 - %@", md5);
    // 命令`md5 -s "中华人民共和国"`，MD5 ("中华人民共和国") = 025fceab9418be86066b60a71bc71485
    NSString *s = @"中华人民共和国";
    md5 = [s kl_MD5HexString];
    NSLog(@"md5 - %@", md5);
    XCTAssert([@"025fceab9418be86066b60a71bc71485" isEqualToString:md5], @"MD5结果不一致");
}

- (void)testSHA {
    // 可在命令行中使用shasum命令，查看结果是否一致
    NSString *sha1 = [self.plainData kl_SHA1HexString];
    NSString *sha224 = [self.plainData kl_SHA224HexString];
    NSString *sha256 = [self.plainData kl_SHA256HexString];
    NSString *sha384 = [self.plainData kl_SHA384HexString];
    NSString *sha512 = [self.plainData kl_SHA512HexString];
    
    // `shasum KalanCert.cer`，结果为126686d12b27eca887acee5c55934f512e848144
    // `shasum -a 224 KalanCert.cer`，结果为f11fd42226f3ee1bb6fe42ecd54c7b4406a62998172019fad9b2af8b
    // `shasum -a 256 KalanCert.cer`，结果为2f9deb3bc80e4618e81b050c3108bd9a3bb39fd1dfa9f3bc08e4c1807a248088
    // `shasum -a 384 KalanCert.cer`，结果为4b04f4d607271041576f4b8b841fe69a4fbc33a07597a20a03ed3451775852ccd980cb67b41c814f98fd2839f945581f
    // `shasum -a 512 KalanCert.cer`，结果为df25e73786485a911b54d0c1fda229ca4b229ab51b40af8cb3e9be95ebf85844a88a8590fa8bbcf9b47a166d305379cf5d3de0b4321f63c0960f41d6957eda3e
    NSString *path = [[NSBundle bundleForClass:[self class]] pathForResource:@"KalanCert" ofType:@"cer"];
    XCTAssert(path, @"未能找到证书文件");
    NSData *data = [NSData dataWithContentsOfFile:path];
    sha1 = [data kl_SHA1HexString];
    sha224 = [data kl_SHA224HexString];
    sha256 = [data kl_SHA256HexString];
    sha384 = [data kl_SHA384HexString];
    sha512 = [data kl_SHA512HexString];
    XCTAssert([@"126686d12b27eca887acee5c55934f512e848144" isEqualToString:sha1], @"SHA1结果不一致");
    XCTAssert([@"f11fd42226f3ee1bb6fe42ecd54c7b4406a62998172019fad9b2af8b" isEqualToString:sha224], @"SHA224结果不一致");
    XCTAssert([@"2f9deb3bc80e4618e81b050c3108bd9a3bb39fd1dfa9f3bc08e4c1807a248088" isEqualToString:sha256], @"SHA256结果不一致");
    XCTAssert([@"4b04f4d607271041576f4b8b841fe69a4fbc33a07597a20a03ed3451775852ccd980cb67b41c814f98fd2839f945581f" isEqualToString:sha384], @"SHA384结果不一致");
    XCTAssert([@"df25e73786485a911b54d0c1fda229ca4b229ab51b40af8cb3e9be95ebf85844a88a8590fa8bbcf9b47a166d305379cf5d3de0b4321f63c0960f41d6957eda3e" isEqualToString:sha512], @"SHA512结果不一致");
}

- (void)testHMAC {
    CCHmacAlgorithm alg = kCCHmacAlgMD5;
    NSData *key = [NSData kl_generateHmacKeyForAlgorithm:alg];
    NSData *hmac = [self.plainData kl_HmacWithAlgorithm:alg key:key];
    NSString *hmacHex = [hmac kl_encodeToHexString];
    NSLog(@"hmac md5 - %@", hmacHex);
    
    alg = kCCHmacAlgSHA1;
    key = [NSData kl_generateHmacKeyForAlgorithm:alg];
    hmac = [self.plainData kl_HmacWithAlgorithm:alg key:key];
    hmacHex = [hmac kl_encodeToHexString];
    NSLog(@"hmac sha1 - %@", hmacHex);
    
    alg = kCCHmacAlgSHA224;
    key = [NSData kl_generateHmacKeyForAlgorithm:alg];
    hmac = [self.plainData kl_HmacWithAlgorithm:alg key:key];
    hmacHex = [hmac kl_encodeToHexString];
    NSLog(@"hmac sha224 - %@", hmacHex);
    
    alg = kCCHmacAlgSHA256;
    key = [NSData kl_generateHmacKeyForAlgorithm:alg];
    hmac = [self.plainData kl_HmacWithAlgorithm:alg key:key];
    hmacHex = [hmac kl_encodeToHexString];
    NSLog(@"hmac sha256 - %@", hmacHex);
    
    alg = kCCHmacAlgSHA384;
    key = [NSData kl_generateHmacKeyForAlgorithm:alg];
    hmac = [self.plainData kl_HmacWithAlgorithm:alg key:key];
    hmacHex = [hmac kl_encodeToHexString];
    NSLog(@"hmac sha384 - %@", hmacHex);
    
    alg = kCCHmacAlgSHA512;
    key = [NSData kl_generateHmacKeyForAlgorithm:alg];
    hmac = [self.plainData kl_HmacWithAlgorithm:alg key:key];
    hmacHex = [hmac kl_encodeToHexString];
    NSLog(@"hmac sha512 - %@", hmacHex);
    // 可用长度更长的密钥
    key = [NSData kl_generateSecureRandomData:CC_SHA512_DIGEST_LENGTH << 1];
    hmac = [self.plainData kl_HmacWithAlgorithm:alg key:key];
    hmacHex = [hmac kl_encodeToHexString];
    NSLog(@"hmac sha512 - %@", hmacHex);
    // 可用长度更短的密钥
    key = [NSData kl_generateSecureRandomData:arc4random_uniform(10) + 1];
    hmac = [self.plainData kl_HmacWithAlgorithm:alg key:key];
    hmacHex = [hmac kl_encodeToHexString];
    NSLog(@"hmac sha512 - %@", hmacHex);
}


@end

