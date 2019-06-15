#include "InlineHook.h"

/**
 *  通用函数：获取so模块加载进内存的基地址，通过查看/proc/$pid/maps文件
 *  
 *  @param  pid             模块所在进程pid，如果访问自身进程，可填小余0的值，如-1
 *  @param  pszModuleName   模块名字
 *  @return void*           模块的基地址，错误返回0 
 */
void * GetModuleBaseAddr(pid_t pid, char* pszModuleName)
{
    FILE *pFileMaps = NULL;
    unsigned long ulBaseValue = 0;
    char szMapFilePath[256] = {0};
    char szFileLineBuffer[1024] = {0};

    /* 判断是否为自身maps文件*/
    if(pid < 0)
    {
        snprintf(szMapFilePath, sizeof(szMapFilePath), "/proc/self/maps");
    }
    else
    {
        snprintf(szMapFilePath, sizeof(szMapFilePath), "/proc/%d/maps", pid);
    }
	
	pFileMaps = fopen(szMapFilePath, "r");
	if (NULL == pFileMaps)
	{
		return (void *)ulBaseValue;
	}
    /* 循环遍历maps文件，找到对应模块名，截取字符串中的基地址*/
    while (fgets(szFileLineBuffer, sizeof(szFileLineBuffer), pFileMaps) != NULL)
    {
        if(strstr(szFileLineBuffer, pszModuleName))
        {
            char *pszModuleAddress = strtok(szFileLineBuffer, "-");
            ulBaseValue = strtoul(pszModuleAddress, NULL, 16);
            
            if (ulBaseValue == 0x8000)
            {
                ulBaseValue = 0;
            }
            break;
        }
    }

    return ulBaseValue;
}

/**
 * 通用函数，修改页属性，让内存块内的代码可执行
 *
 * @param   pAddress    需要修改属性起始地址
 * @param   size        需要修改页属性的长度
 * @return  bool        是否修改成功
 */
bool ChangePageProperty(void *pAddress, size_t size)
{
    bool bRet = false;
    
    while(1)
    {
        if(pAddress == NULL)
        {
            LOGI("change page property error.");
            break;
        }

        unsigned long ulPageSize = sysconf(_SC_PAGESIZE);
        int iProtect = PROT_READ | PROT_WRITE | PROT_EXEC;
        /*页对齐，以4096的倍数为起始位置*/
        unsigned long ulNewPageStartAddress = (unsigned long)(pAddress) & ~(ulPageSize - 1);
        /* 计算至少需要多少内存页(0x1000byte)可以包含size大小*/
        long lPageCount = (size / ulPageSize) + 1;
        int iRet = mprotect((const void *)(ulNewPageStartAddress), lPageCount*ulPageSize , iProtect);

        if (iRet == -1)
        {
            LOGI("mprotect error:%s", strerror(errno));
            break;
        }

        bRet = true;
		break;
    }

    return bRet;
}

/**
 *  ARM32：初始化hook点信息，保存原指令的opcode
 *  
 *  @param  pstInlineHook   保存hook点信息的结构体
 *  @return bool            是否初始化成功
 */
bool InitArmHookInfo(ARM_INLINE_HOOK_INFO* pstInlineHook)
{
    bool bRet = false;

    while(1)
    {
        if(pstInlineHook == NULL)
        {
            LOGI("arm pstInlineHook is null");
            break;
        }

        memcpy(pstInlineHook->szbyBackupOpcodes, pstInlineHook->pHookAddr, 8);
		bRet = true;
		break;
    }

    return bRet;
}

/**
 *  ARM32：构造桩函数
 *
 *  @param  pstInlineHook   保存hook点信息的结构体
 *  @return bool            是否构造成功
 */ 
bool BuildArmStub(ARM_INLINE_HOOK_INFO* pstInlineHook)
{
    bool bRet = false;

    while(1)
    {
        if(pstInlineHook == NULL)
        {
            LOGI("arm pstInlineHook is null");
            break;
        }
        
        /* 需要在shellcode中定义的四个全局变量。*/
        void *p_shellcode_start_s = &_shellcode_start_s;
        void *p_shellcode_end_s = &_shellcode_end_s;
        void *p_hookstub_function_addr_s = &_hookstub_function_addr_s;
        void *p_old_function_addr_s = &_old_function_addr_s;
        /* 申请一块内存，放入桩函数的shellcode*/
        size_t sShellCodeLength = p_shellcode_end_s - p_shellcode_start_s;
        void *pNewShellCode = malloc(sShellCodeLength);
        
        if(pNewShellCode == NULL)
        {
            LOGI("arm shellcode malloc fail.");
            break;
        }
        memcpy(pNewShellCode, p_shellcode_start_s, sShellCodeLength);
        if(ChangePageProperty(pNewShellCode, sShellCodeLength) == false)
        {
            LOGI("change shell code page property fail.");
            break;
        }

        /* ppHookStubFunctionAddr的值是一个变量值的地址。这个变量值是shellcode中用户自定义函数地址(在新申请的空间中)*/
        void **ppHookStubFunctionAddr = pNewShellCode + (p_hookstub_function_addr_s - p_shellcode_start_s);
        *ppHookStubFunctionAddr = pstInlineHook->onCallBack;
        /* 桩函数地址*/
        pstInlineHook->pStubShellCodeAddr = pNewShellCode;
        /* _old_function_addr_s变量的地址，这个变量值就是原指令函数的函数指针值*/
        pstInlineHook->ppOldFuncAddr  = pNewShellCode + (p_old_function_addr_s - p_shellcode_start_s);
		
        bRet = true;
        break;
    }

    return bRet;
}

/**
 *  ARM32：构造跳转指令。
 *
 *  @param  pCurAddress      当前地址，要构造跳转指令的位置
 *  @param  pJumpAddress     目的地址，要从当前位置跳过去的地址
 *  @return bool             跳转指令是否构造成功
 */ 
bool BuildArmJumpCode(void *pCurAddress , void *pJumpAddress)
{
    bool bRet = false;

    while(1)
    {
        if(pCurAddress == NULL || pJumpAddress == NULL)
        {
            LOGI("arm jump address null.");
            break;
        }

        /* LDR PC, [PC, #-4]的机器码是0xE51FF004 */
        BYTE szLdrPCOpcodes[8] = {0x04, 0xF0, 0x1F, 0xE5};
        memcpy(szLdrPCOpcodes + 4, &pJumpAddress, 4);
        memcpy(pCurAddress, szLdrPCOpcodes, 8);
        /* 刷新缓存中的指令，防止缓存中指令未进行修改引起的错误*/
        cacheflush(*((uint32_t*)pCurAddress), 8, 0);

        bRet = true;
        break;
    }

    return bRet;
}

/**
 *  ARM：构造原指令函数。申请一块内存，写入原指令和跳转指令
 *      * 执行原指令
 *      * 跳转到原始指令流程中，即原指令的下一条指令处
 *  出了上面两个功能我们还需要将shellcode中的原指令函数地址进行填充，补全桩函数中原指令函数地址
 *
 *  @param  pstInlineHook   hook点相关信息的结构体
 *  @return bool            原指令函数是否构造成功
 */ 
bool BuildArmOldFunction(ARM_INLINE_HOOK_INFO* pstInlineHook)
{
    bool bRet = false;
    
    while(1)
    {
        if(pstInlineHook == NULL)
        {
            LOGI("build old function , arm pstInlineHook is null");
            break;
        }

        /* 8字节原指令，8字节原指令的下一条指令*/
        void * pNewEntryForOldFunction = malloc(16);
        if(pNewEntryForOldFunction == NULL)
        {
            LOGI("arm new entry for old function malloc fail.");
            break;
        }

        if(ChangePageProperty(pNewEntryForOldFunction, 16) == false)
        {
            LOGI("arm change new entry page property fail.");
            break;
        }

        /* 拷贝原指令到内存块中*/
        memcpy(pNewEntryForOldFunction, pstInlineHook->szbyBackupOpcodes, 8);
        /* 拷贝跳转指令到内存块中*/
        if(BuildArmJumpCode(pNewEntryForOldFunction + 8, pstInlineHook->pHookAddr + 8) == false)
        {
            LOGI("arm build jump opcodes for new entry fail.");
            break;
        }

        /* 填充shellcode里stub的回调地址*/
        *(pstInlineHook->ppOldFuncAddr) = pNewEntryForOldFunction;

        bRet = true;
        break;
    }

    return bRet;
}

/**
 *  ARM：覆盖HOOK点的指令，跳转到桩函数的位置
 *
 *  @param  pstInlineHook   inlinehook信息
 *  @return bool            原地跳转指令是否构造成功
 */
bool RebuildArmHookTarget(ARM_INLINE_HOOK_INFO* pstInlineHook)
{
    bool bRet = false;

    while(1)
    {
        if(pstInlineHook == NULL)
        {
            LOGI("arm cover old instructions, pstInlineHook is null");
            break;
        }

        /* 修改原位置的页属性，保证可写*/
        if(ChangePageProperty(pstInlineHook->pHookAddr, 8) == false)
        {
            LOGI("arm change page property error.");
            break;
        }

        /* 覆盖原指令为跳转指令*/
        if(BuildArmJumpCode(pstInlineHook->pHookAddr, pstInlineHook->pStubShellCodeAddr) == false)
        {
            LOGI("arm build jump opcodes for new entry fail.");
            break;
        }

        bRet = true;
        break;
    }

    return bRet;
}

/**
 *  ARM：恢复原指令，删除hook点
 *
 *  @param  pstInlineHook   inlinehook信息
 *  @return bool            删除hook点是否成功
 */
bool RestroeArmHookTarget(ARM_INLINE_HOOK_INFO* pstInlineHook)
{	
    bool bRet = false;

    while(1)
    {
        if(pstInlineHook == NULL)
        {
            LOGI("arm cover old instructions, pstInlineHook is null");
            break;
        }

        /* 修改原位置的页属性，保证可写*/
        if(ChangePageProperty(pstInlineHook->pHookAddr, 8) == false)
        {
            LOGI("arm change page property error.");
            break;
        }
		
		if(InitArmHookInfo(pstInlineHook) == false)
		{
			LOGI("arm pstInlineHook is null.");
			break;
		}
        /* 恢复原指令*/
		memcpy(pstInlineHook->pHookAddr, pstInlineHook->szbyBackupOpcodes, 8);
		cacheflush(*((uint32_t*)pstInlineHook->pHookAddr), 8, 0);
		
        bRet = true;
        break;
    }

    return bRet;
}

/**
 *  ARM：对外提供Hook函数的调用接口。
 *
 *  @param  pstInlineHook   inlinehook信息
 *  @return bool            是否hook成功
 */ 
bool HookArm(ARM_INLINE_HOOK_INFO* pstInlineHook)
{
    bool bRet = false;
    
    while(1)
    {
        if(pstInlineHook == NULL)
        {
            LOGI("arm pstInlineHook is null.");
            break;
        }

        /* 初始化hook点的信息，将原指令地址处的指令内容存放到hook点结构体中*/
        if(InitArmHookInfo(pstInlineHook) == false)
        {
            LOGI("Init Arm HookInfo fail.");
            break;
        }

        /* 1. 构造桩函数*/
        if(BuildArmStub(pstInlineHook) == false)
        {
            LOGI("Arm BuildStub fail.");
            break;
        }
        LOGI("ARM BuildStub completed.");

        /* 2. 构造原指令函数，执行被覆盖指令并跳转回原始指令流程*/
        if(BuildArmOldFunction(pstInlineHook) == false)
        {
            LOGI("BuildArmOldFunction fail.");
            break;
        }
        LOGI("BuildArmOldFunction completed.");
        
        /* 3. 改写原指令为跳转指令，跳转到桩函数处*/
        if(RebuildArmHookTarget(pstInlineHook) == false)
        {
            LOGI("RebuildHookAddress fail.");
            break;
        }
        LOGI("RebuildArmHookAddress completed.");

        bRet = true;
        break;
    }

    return bRet;
}

/**
 *  Thumb-2：初始化Hook点信息，根据用户指定位置，将该处的指令存进hook点结构体中
 *
 *  @param  pstInlineHook   hook点信息的结构体
 *  @return bool            是否初始化成功
 */ 
bool InitThumbHookInfo(THUMB_INLINE_HOOK_INFO* pstInlineHook)
{
    bool bRet = false;
    char caddr[10] = {0};
    unsigned long addr = 0;

    while(1)
    {
        if(pstInlineHook == NULL)
        {
            LOGI("Thumb init THUMB_INLINE_HOOK_INFO failed.");
            break;
        }
        /* 计算需要覆盖的opcode长度*/
        sprintf(caddr, "%p", pstInlineHook->pHookAddr);
        addr = strtoul(caddr, 0, 16);
        if(SET_BIT0(addr) % 4 != 0)
        {
            pstInlineHook->thumb2OpcodeLen = 10;
        }
        else
        {
            pstInlineHook->thumb2OpcodeLen = 8;
        }

        memcpy(pstInlineHook->szbyBackupOpcodes, pstInlineHook->pHookAddr, pstInlineHook->thumb2OpcodeLen);
        bRet = true;
        break;
    }

    return bRet;
}

/**
 *  Thumb-2：构造桩函数
 *
 *  @param  pstInlineHook   hook点信息的结构体
 *  @return bool            是否构造成功
 */ 
bool BuildThumbStub(THUMB_INLINE_HOOK_INFO* pstInlineHook)
{
    bool bRet = false;

    while(1)
    {
        if(pstInlineHook == NULL)
        {
            LOGI("Thumb pstInlineHook is null");
            break;
        }

        void *p_shellcode_start_s_thumb = &_shellcode_start_s_thumb;
        void *p_shellcode_end_s_thumb = &_shellcode_end_s_thumb;
        void *p_hookstub_function_addr_s_thumb = &_hookstub_function_addr_s_thumb;
        void *p_old_function_addr_s_thumb = &_old_function_addr_s_thumb;
        /* 申请一块内存，放入桩函数的shellcode*/
        size_t sShellCodeLength = p_shellcode_end_s_thumb - p_shellcode_start_s_thumb;
        void *pNewShellCode = malloc(sShellCodeLength);

        if(pNewShellCode == NULL)
        {
            LOGI("Thumb shellcode malloc fail.");
            break;
        }
        memcpy(pNewShellCode, p_shellcode_start_s_thumb, sShellCodeLength);

        if(ChangePageProperty(pNewShellCode, sShellCodeLength) == false)
        {
            LOGI("Thumb change shell code page property fail.");
            break;
        }

        /* 用户自定义函数地址*/
        void **ppHookStubFunctionAddr = pNewShellCode + (p_hookstub_function_addr_s_thumb - p_shellcode_start_s_thumb);
        *ppHookStubFunctionAddr = pstInlineHook->onCallBack;
        /* 桩函数地址*/
        pstInlineHook->pStubShellCodeAddr = pNewShellCode;
        /* 保留地址：原指令函数指针的存放地址*/
        pstInlineHook->ppOldFuncAddr  = pNewShellCode + (p_old_function_addr_s_thumb - p_shellcode_start_s_thumb);

        bRet = true;
        break;
    }

    return bRet;
}

/**
 *  Thumb-2：构造Thumb指令集的函数跳转
 *
 *  @param  pCurAddress      当前地址，要构造跳转指令的位置
 *  @param  pJumpAddress     目的地址，要从当前位置跳过去的地址
 *  @return bool             跳转指令是否构造成功
 */ 
bool BuildThumbJumpCode(void *pCurAddress , void *pJumpAddress)
{
    bool bRet = false;
	char caddr[10] = {0};
    unsigned long addr = 0;

    while(1)
    {
        if(pCurAddress == NULL || pJumpAddress == NULL)
        {
            LOGI("Thumb jump address null.");
            break;
        }
        
		sprintf(caddr, "%p", pCurAddress);
        addr = strtoul(caddr, 0, 16);
        /* 如果原指令地址不能被4整除就用NOP填充1条thumb16指令的长度，让跳转指令被4整除*/
        /* LDR PC, [PC, #0]的thumb指令是0xF000F8DF*/
        if(SET_BIT0(addr) % 4 != 0)
        {
            BYTE szLdrPCOpcodes[10] = {0x00, 0xBF, 0xDF, 0xF8, 0x00, 0xF0};
            memcpy(szLdrPCOpcodes + 6, &pJumpAddress, 4);
            memcpy(pCurAddress, szLdrPCOpcodes, 10);
            cacheflush(*((uint32_t*)pCurAddress), 10, 0);
        }
        else
        {
            BYTE szLdrPCOpcodes[8] = {0xDF, 0xF8, 0x00, 0xF0};
            memcpy(szLdrPCOpcodes + 4, &pJumpAddress, 4);
            memcpy(pCurAddress, szLdrPCOpcodes, 8);
            cacheflush(*((uint32_t*)pCurAddress), 8, 0);
        }

        bRet = true;
        break;
    }

    return bRet;
}

/**
 *  Thumb-2：构造原指令函数
 *
 *  @param  pstInlineHook   hook点相关信息的结构体
 *  @return bool            原指令函数是否构造成功
 */
bool BuildThumbOldFunction(THUMB_INLINE_HOOK_INFO* pstInlineHook)
{
    bool bRet = false;

    while(1)
    {
        if(pstInlineHook == NULL)
        {
            LOGI("build old function , thumb pstInlineHook is null");
            break;
        }

        /* 申请空间将原指令拷进去并赋可执行权限*/
        void * pNewEntryForOldFunction = malloc(20);
        if(pNewEntryForOldFunction == NULL)
        {
            LOGI("Thumb new entry for old function malloc fail.");
            break;
        }

        if(ChangePageProperty(pNewEntryForOldFunction, 20) == false)
        {
            LOGI("thumb change new entry page property fail.");
            break;
        }
        
        memcpy(pNewEntryForOldFunction, pstInlineHook->szbyBackupOpcodes, pstInlineHook->thumb2OpcodeLen);
        if(BuildThumbJumpCode(pNewEntryForOldFunction + pstInlineHook->thumb2OpcodeLen, pstInlineHook->pHookAddr + pstInlineHook->thumb2OpcodeLen+1) == false)
        {
            LOGI("Thumb build jump opcodes for new entry fail.");
            break;
        }

        *(pstInlineHook->ppOldFuncAddr) = pNewEntryForOldFunction;

        bRet = true;
        break;
    }

    return bRet;
}

/**
 *  Thumb：覆盖原指令
 *
 *  @param  pstInlineHook   inlinehook信息
 *  @return bool            原地跳转指令是否构造成功
 */
bool RebuildThumbHookTarget(THUMB_INLINE_HOOK_INFO* pstInlineHook)
{
    bool bRet = false;

    while(1)
    {
        if(pstInlineHook == NULL)
        {
            LOGI("Thumb cover old instructions, pstInlineHook is null");
            break;
        }

        if(ChangePageProperty(pstInlineHook->pHookAddr, pstInlineHook->thumb2OpcodeLen) == false)
        {
            LOGI("Thumb change page property error.");
            break;
        }

        if(BuildThumbJumpCode(pstInlineHook->pHookAddr, pstInlineHook->pStubShellCodeAddr) == false)
        {
            LOGI("Thumb build jump opcodes for new entry fail.");
            break;
        }

        bRet = true;
        break;
    }
    
    return bRet;
}

/**
 *  Thumb：删除hook点，恢复原指令
 *
 *  @param  pstInlineHook   inlinehook信息
 *  @return bool            删除hook点是否成功
 */
bool RestroeThumbHookTarget(THUMB_INLINE_HOOK_INFO* pstInlineHook)
{
    bool bRet = false;

    while(1)
    {
        if(pstInlineHook == NULL)
        {
            LOGI("Thumb cover old instructions, pstInlineHook is null");
            break;
        }

        if(ChangePageProperty(pstInlineHook->pHookAddr, pstInlineHook->thumb2OpcodeLen) == false)
        {
            LOGI("Thumb change page property error.");
            break;
        }
		
		memcpy(pstInlineHook->pHookAddr, pstInlineHook->szbyBackupOpcodes, pstInlineHook->thumb2OpcodeLen);
		cacheflush(*((uint32_t*)pstInlineHook->pHookAddr), pstInlineHook->thumb2OpcodeLen, 0);
		
        bRet = true;
        break;
    }
    
    return bRet;
}

/**
 *  Thumb：对外提供hook的入口函数
 *
 *  @param  pstInlineHook   inlinehook信息
 *  @return bool            是否hook成功
 */
bool HookThumb(THUMB_INLINE_HOOK_INFO* pstInlineHook)
{
    bool bRet = false;

    while(1)
    {
        if(pstInlineHook == NULL)
        {
            LOGI("Thumb pstInlineHook is null.");
            break;
        }

        if(InitThumbHookInfo(pstInlineHook) == false)
        {
            LOGI("Init Thumb HookInfo fail.");
            break;
        }
		LOGI("ARM InitThumbHookInfo completed.");

        if(BuildThumbStub(pstInlineHook) == false)
        {
            LOGI("Thumb BuildStub fail.");
            break;
        }
        LOGI("ARM BuildStub completed.");

        if(BuildThumbOldFunction(pstInlineHook) == false)
        {
            LOGI("BuildThumbOldFunction fail.");
            break;
        }
        LOGI("BuildThumbOldFunction completed.");
        
        if(RebuildThumbHookTarget(pstInlineHook) == false)
        {
            LOGI("RebuildHookAddress fail.");
            break;
        }
        LOGI("RebuildThumbHookAddress completed.");
		
        bRet = true;
        break;
    }

    return bRet;
}
