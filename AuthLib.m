#import <Foundation/Foundation.h>
#import <Foundation/Foundation.h>
#import <Security/Security.h>

// ========== 配置区 ==========
#define VALID_SECONDS 604800 // 7天 = 7*24*3600秒
// 验证码：123456
#define VERIFY_HASH @"8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92"
// 弹窗文字自定义
#define ALERT_TITLE @"使用授权"
#define ALERT_MSG @"请输入验证码，解锁一周使用权限"
#define PLACEHOLDER @"请输入验证码"
// ============================

BOOL authPassed = NO;
NSTimeInterval expireTimestamp = 0;
UIAlertController *alertVC = nil;
BOOL alertShowing = NO;

// Keychain 读写
BOOL keychainSave(NSString *key, NSString *value) {
    NSDictionary *query = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrAccount: key,
        (__bridge id)kSecValueData: [value dataUsingEncoding:NSUTF8StringEncoding],
        (__bridge id)kSecAttrAccessible: (__bridge id)kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    };
    SecItemDelete((__bridge CFDictionaryRef)query);
    OSStatus ret = SecItemAdd((__bridge CFDictionaryRef)query, NULL);
    return ret == errSecSuccess;
}

NSString* keychainRead(NSString *key) {
    NSDictionary *query = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrAccount: key,
        (__bridge id)kSecReturnData: (__bridge id)kCFBooleanTrue,
        (__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitOne,
        (__bridge id)kSecAttrAccessible: (__bridge id)kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    };
    CFDataRef dataRef = NULL;
    OSStatus ret = SecItemCopyMatching((__bridge CFDictionaryRef)query, (CFTypeRef *)&dataRef);
    if(ret != errSecSuccess) return nil;
    NSData *data = (__bridge_transfer NSData *)dataRef;
    return [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
}

// SHA256哈希
NSString* sha256(NSString *input) {
    NSData *data = [input dataUsingEncoding:NSUTF8StringEncoding];
    uint8_t hash[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(data.bytes, (CC_LONG)data.length, hash);
    NSMutableString *res = [NSMutableString string];
    for(int i=0;i<CC_SHA256_DIGEST_LENGTH;i++){
        [res appendFormat:@"%02x",hash[i]];
    }
    return res;
}

// 弹窗
void showAuthAlert() {
    if(alertShowing) return;
    alertShowing = YES;
    UIViewController *topVC = [UIApplication sharedApplication].keyWindow.rootViewController;
    while(topVC.presentedViewController) topVC = topVC.presentedViewController;
    
    alertVC = [UIAlertController alertControllerWithTitle:ALERT_TITLE message:ALERT_MSG preferredStyle:UIAlertControllerStyleAlert];
    [alertVC addTextFieldWithConfigurationHandler:^(UITextField *tf) {
        tf.placeholder = PLACEHOLDER;
        tf.secureTextEntry = YES;
    }];
    UIAlertAction *confirm = [UIAlertAction actionWithTitle:@"确认" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
        NSString *inputCode = alertVC.textFields.firstObject.text;
        NSString *inputHash = sha256(inputCode);
        if([inputHash isEqualToString:VERIFY_HASH]){
            NSTimeInterval now = [[NSDate date] timeIntervalSince1970];
            expireTimestamp = now + VALID_SECONDS;
            keychainSave(@"authExpire", [NSString stringWithFormat:@"%.0f",expireTimestamp]);
            authPassed = YES;
            NSLog(@"✅验证成功，有效期7天");
        }else{
            NSLog(@"❌验证码错误");
        }
        alertShowing = NO;
    }];
    UIAlertAction *cancel = [UIAlertAction actionWithTitle:@"关闭" style:UIAlertActionStyleCancel handler:^(UIAlertAction *action) {
        alertShowing = NO;
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 3 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
            showAuthAlert();
        });
    }];
    [alertVC addAction:confirm];
    [alertVC addAction:cancel];
    [topVC presentViewController:alertVC animated:YES completion:nil];
}

// 校验授权
void checkAuthStatus() {
    NSString *savedExpireStr = keychainRead(@"authExpire");
    NSTimeInterval now = [[NSDate date] timeIntervalSince1970];
    if(savedExpireStr){
        expireTimestamp = [savedExpireStr doubleValue];
        if(now < expireTimestamp){
            authPassed = YES;
            NSLog(@"✅授权有效");
            return;
        }
    }
    authPassed = NO;
    dispatch_async(dispatch_get_main_queue(), ^{
        showAuthAlert();
    });
}

// 动态库入口（APP启动自动执行）
__attribute__((constructor)) void libEntry() {
    @autoreleasepool {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 1.2 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
            checkAuthStatus();
        });
    }
}