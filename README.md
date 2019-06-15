[TOC]

# 概述

这是一个完整的InlineHook的使用模块，直接将jni目录clone下来，使用ndk-build编译即可



# 使用

## 共享库

1. clone该demo

2. 修改ModifyIBored函数里GetModuleBaseAddr的参数，选择需要hook的so模块

3. 找到需要hook的指令地址，计算偏移(指令的内存地址-指令所在模块的基址)，然后写入

   ```uint32_t uiHookAddr = (uint32_t)pModuleBaseAddr + 偏移;```中的偏移

4. 完善替换函数EvilHookStubFunctionForIBored，执行自己需要的操作

5. ndk-build编译出共享库so文件

6. 在代码中使用`System.loadLibrary`加载共享库，加载的时候就会调用用hook函数

   `void ModifyIBored() __attribute__((constructor));`

7. (可选)使用ptrace注入共享库到指令进程中

 

# 模块

* hook文件夹：这个文件夹里存放hook功能源码
* interface文件夹：使用hook功能的地方，可以自行修改InlineHook.cpp中的ModifyIBored函数来hook指定模块的指定指令，也可以按照上面结构自己写



## HookArm

InlineHook.c文件中的函数。

针对32位ARM指令进行hook



## HookThumb

InlineHook.c文件中的函数。

针对Thumb-2指令集进行hook



# 不足

这个项目是比较简单的demo，并不涉及指令修复等内容