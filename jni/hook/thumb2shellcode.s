.global _shellcode_start_s_thumb
.global _shellcode_end_s_thumb
.global _hookstub_function_addr_s_thumb
.global _old_function_addr_s_thumb

.data
_shellcode_start_s_thumb:
    push    {r0, r1, r2, r3} 
    mrs     r0, cpsr
    str     r0, [sp, #0xC]
    str     r14, [sp, #8]
    add     r14, sp, #0x10
    str     r14, [sp, #4]
    pop     {r0}
    push    {r0-r12} 
    mov     r0, sp
    ldr     r3, _hookstub_function_addr_s_thumb
    blx     r3  
    ldr     r3, _old_function_addr_s_thumb
    bic     r3, r3, #1
    add     r3, r3, #0x1
    str     r3, _old_function_addr_s_thumb
    ldr     r0, [sp, #0x3C]
    ldmfd   sp!, {r0-r12}  
    ldr     r14, [sp, #4]
    ldr     sp, [r13]
    ldr     pc, _old_function_addr_s_thumb

_hookstub_function_addr_s_thumb:
.word 0xffffffff

_old_function_addr_s_thumb:
.word 0xffffffff

_shellcode_end_s_thumb:

.end

