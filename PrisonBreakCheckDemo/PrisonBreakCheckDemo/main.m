//
//  main.m
//  PrisonBreakCheckDemo
//
//  Created by 贺文杰 on 2021/3/29.
//

#import <UIKit/UIKit.h>
#import "AppDelegate.h"
#import <dlfcn.h>
#import <sys/types.h>
#import <sys/syscall.h>

//反调试
#if DEBUG
#else
typedef int (*ptrace_ptr_t)(int _request, pid_t _pid, caddr_t _addr, int _data);
#if !defined(PT_DENY_ATTACH)
#define PT_DENY_ATTACH 31
#endif

void anti_gdb_debug() {
    void *handle = dlopen(0, RTLD_GLOBAL | RTLD_NOW);
    ptrace_ptr_t ptrace_ptr = dlsym(handle, "ptrace");
    /**
     arg1: ptrace要做的事情: PT_DENY_ATTACH 表示要控制的是当前进程不允许被附加
     arg2: 要操作进程的PID , 0就代表自己
     arg3: 地址 取决于第一个参数要做的处理不同传递不同
     arg4: 数据 取决于第一个参数要做的处理不同传递不同
     */
    ptrace_ptr(PT_DENY_ATTACH, 0, 0, 0);
    dlclose(handle);
}

#endif

int main(int argc, char * argv[]) {
    // __arm64__   64位
    // __arm__  32位
    
    //svc #80\n   是指调用exit
    //26对应的是SYS_ptrace
#if DEBUG
#else
    //使用汇编直接调起ptrace
#ifdef __arm64__
    asm volatile (
                  "mov x0, #31\n"
                  "mov x1, #0\n"
                  "mov x2, #0\n"
                  "mov x12, #26\n"
                  "svc #0x80\n"
                  );
    NSLog(@"Bypassed syscall() ASM");
#endif
    
    //使用汇编调用syscall调起ptrace
#ifdef __arm64__
    asm volatile (
                  "mov x0, #26\n"
                  "mov x1, #31\n"
                  "mov x2, #0\n"
                  "mov x3, #0\n"
                  "mov x16, #0\n"
                  "svc #0x80\n"
                  );
    NSLog(@"Bypassed syscall() ASM64");
#endif

     anti_gdb_debug();
#endif
    
    NSString * appDelegateClassName;
    @autoreleasepool {
        // Setup code that might create autoreleased objects goes here.
        appDelegateClassName = NSStringFromClass([AppDelegate class]);
    }
    return UIApplicationMain(argc, argv, nil, appDelegateClassName);
}
