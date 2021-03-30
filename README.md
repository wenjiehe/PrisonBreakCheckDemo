# PrisonBreakCheckDemo
越狱与非越狱的安全防护

##  动态调试

1. sysctl

> sysctl ( system control ) 是由 <sys/sysctl.h> 提供的一个函数 , 它有很多作用 , 其中一个是可以监测当前进程有没有被附加 . 但是因为其特性 , 只是监测当前时刻应用有没有被附加 . 因此正向开发中我们往往结合定时器一起使用 , 或者 定时 / 定期 / 在特定时期 去使用 .

示例代码
```Objective-C
#import "ViewController.h"
#import <sys/sysctl.h>
@interface ViewController ()
@end

@implementation ViewController
BOOL isDebug(){
    int name[4];             //里面放字节码。查询的信息
    name[0] = CTL_KERN;      //内核查询
    name[1] = KERN_PROC;     //查询进程
    name[2] = KERN_PROC_PID; //传递的参数是进程的ID
    name[3] = getpid();      //获取当前进程ID
    
    struct kinfo_proc info;  //接受查询结果的结构体
    size_t info_size = sizeof(info);  //结构体大小
    if(sysctl(name, 4, &info, &info_size, 0, 0)){
        NSLog(@"查询失败");
        return NO;
    }
    /**
    查询结果看info.kp_proc.p_flag 的第12位。如果为1，表示调试状态。
    (info.kp_proc.p_flag & P_TRACED) 就是0x800, 即可获取第12位
    */
    return ((info.kp_proc.p_flag & P_TRACED) != 0);
}

static dispatch_source_t timer;
void debugCheck(){
    timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, dispatch_get_global_queue(0, 0));
    dispatch_source_set_timer(timer, DISPATCH_TIME_NOW, 1.0 * NSEC_PER_SEC, 0.0 * NSEC_PER_SEC);
    dispatch_source_set_event_handler(timer, ^{
        if (isDebug()) {//在这里写你检测到调试要做的操作
            NSLog(@"调试状态!");
        }else{
            NSLog(@"正常！");
        }
    });
    dispatch_resume(timer);
}

- (void)viewDidLoad {
    [super viewDidLoad];
    debugCheck();
}
```

2. 监测环境变量
```Objective-C
- (void)environmentObj
{
    //越狱检测
    char * dlname = getenv("DYLD_INSERT_LIBRARIES");
    if (dlname) {
        NSLog(@"越狱手机，关闭部分功能");
    }else{
        NSLog(@"正常手机！");
    }
}
```

3. image list
```Objective-C
//引入动态库监测，使用白名单监测自己工程当前引入三方库，查找是否有未知库注入
- (void)dynamicCheck
{
    //注意: 由于程序本身 mach-o 这里也能监测出来 , 而且是第一个 , 因此 , 循环应该从 1 开始 , 也就是剔除本身 mach-o .
    //而且该方式同样可以监测越狱环境 DYLD_INSERT_LIBRARIES 动态注入的插件 .
    //此方法可以有效地检测到 Cycript 越狱与非越狱的调试 .
    /*
        如果有以下库，说明这个用户在越狱环境中
        /Library/Frameworks/CydiaSubstrate.framework/Libraries/SubstrateLoader.dylib
        /Library/MobileSubstrate/DynamicLibraries/RHRevealLoader.dylib
        /Library/Frameworks/CydiaSubstrate.framework/CydiaSubstrate
     */
    uint32_t count = _dyld_image_count();
    for (int i = 0; i < count; i++) {
        const char *imageName = _dyld_get_image_name(i);
        printf("%s\n", imageName);
    }
}
```

4. 防止重签名
```Objective-C
- (BOOL)bundleidCheck
{
    BOOL isReloadSign = NO;
    NSString *bundleID = [[NSBundle mainBundle] bundleIdentifier];
    if ([bundleID isEqualToString:@"com.hewenjie.allFunctions"]) { //Bundle ID检测，重签名工程是需要修改包名的
        isReloadSign = YES;
    }
    return isReloadSign;
}
```

5. 隐藏常量字符串
```Objective-C
#define ENCRYPT_KEY 0xAC

//隐藏常量字符串:把一些加密的key或者常量使用方法来代替，采用这样的方式，这些字符不会进入字符常量区，编译器直接换算成异或结果
static NSString *encryptKey(){
    unsigned char key[] = {
        (ENCRYPT_KEY ^ 'c'),
        (ENCRYPT_KEY ^ 'h'),
        (ENCRYPT_KEY ^ 'e'),
        (ENCRYPT_KEY ^ 'c'),
        (ENCRYPT_KEY ^ 'k'),
        (ENCRYPT_KEY ^ 'd'),
        (ENCRYPT_KEY ^ 'e'),
        (ENCRYPT_KEY ^ 'm'),
        (ENCRYPT_KEY ^ 'o'),
        (ENCRYPT_KEY ^ 'k'),
        (ENCRYPT_KEY ^ 'e'),
        (ENCRYPT_KEY ^ 'y'),
        (ENCRYPT_KEY ^ '\0'),
    };
    unsigned char *p = key;
    while (((*p) ^= ENCRYPT_KEY) != '\0') {
        p++;
    }
    
    return [NSString stringWithUTF8String:(const char *)key];
}
```

## 参考资料

1. [逆向-应用安全攻防（越狱与非越狱）](https://juejin.cn/post/6844904143979560974)
2. [ASCII码在线转换计算器](https://www.mokuge.com/tool/asciito16/)
