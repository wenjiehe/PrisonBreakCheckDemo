//
//  ViewController.m
//  PrisonBreakCheckDemo
//
//  Created by 贺文杰 on 2021/3/29.
//

#import "ViewController.h"
#import <sys/sysctl.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>


@interface ViewController ()

@end

@implementation ViewController

//根据sysctl来判断有没有被破解
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
    // Do any additional setup after loading the view.
    debugCheck();
    
    NSLog(@"encryptKey = %@", encryptKey());
}

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

- (BOOL)bundleidCheck
{
    BOOL isReloadSign = NO;
    NSString *bundleID = [[NSBundle mainBundle] bundleIdentifier];
    if ([bundleID isEqualToString:@"com.hewenjie.allFunctions"]) { //Bundle ID检测，重签名工程是需要修改包名的
        isReloadSign = YES;
    }
    return isReloadSign;
}

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


#pragma mark -- 越狱环境检测
//#if __LP64__
//#define LC_SEGMENT_COMMAND        LC_SEGMENT_64
//#define LC_SEGMENT_COMMAND_WRONG LC_SEGMENT
//#define LC_ENCRYPT_COMMAND        LC_ENCRYPTION_INFO
//#define macho_segment_command    segment_command_64
//#define macho_section            section_64
//#define macho_header            mach_header_64
//#else
//#define macho_header            mach_header
//#define LC_SEGMENT_COMMAND        LC_SEGMENT
//#define LC_SEGMENT_COMMAND_WRONG LC_SEGMENT_64
//#define LC_ENCRYPT_COMMAND        LC_ENCRYPTION_INFO_64
//#define macho_segment_command    segment_command
//#define macho_section            section
//#endif


//+ (void)load{
//    //imagelist 里第0个是我们自己的可执行文件
//    const struct mach_header * header = _dyld_get_image_header(0);
//
//    if (hasRestrictedSegment(header)) {
//        NSLog(@"没问题!");
//    }else{
//        NSLog(@"检测到!!");
//        // 退出程序  ,  可以上报 or 记录 ..
//        #ifdef __arm64__
//            asm volatile(
//                         "mov x0,#0\n"
//                         "mov x16,#1\n"
//                         "svc #0x80\n"
//                         );
//        #endif
//        #ifdef __arm__//32位下
//            asm volatile(
//                         "mov r0,#0\n"
//                         "mov r16,#1\n"
//                         "svc #80\n"
//                         );
//        #endif
//    }
//}
//
//static bool hasRestrictedSegment(const struct macho_header* mh)
//{
//    const uint32_t cmd_count = mh->ncmds;
//    const struct load_command* const cmds = (struct load_command*)(((char*)mh)+sizeof(struct macho_header));
//    const struct load_command* cmd = cmds;
//    for (uint32_t i = 0; i < cmd_count; ++i) {
//        switch (cmd->cmd) {
//            case LC_SEGMENT_COMMAND:
//            {
//                const struct macho_segment_command* seg = (struct macho_segment_command*)cmd;
//
//                if (strcmp(seg->segname, "__RESTRICT") == 0) {
//                    const struct macho_section* const sectionsStart = (struct macho_section*)((char*)seg + sizeof(struct macho_segment_command));
//                    const struct macho_section* const sectionsEnd = &sectionsStart[seg->nsects];
//                    for (const struct macho_section* sect=sectionsStart; sect < sectionsEnd; ++sect) {
//                        if (strcmp(sect->sectname, "__restrict") == 0)
//                            return true;
//                    }
//                }
//            }
//                break;
//        }
//        cmd = (const struct load_command*)(((char*)cmd)+cmd->cmdsize);
//    }
//
//    return false;
//}

//监测环境变量
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

@end
