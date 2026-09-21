    .text
    .p2align 4
    .globl sl_kernel32_rtl_capture_context
    .type sl_kernel32_rtl_capture_context, @function
sl_kernel32_rtl_capture_context:
    /* RCX is both the Windows argument and its captured caller value. */
    movq %rax, 0x78(%rcx)
    movq %rcx, 0x80(%rcx)
    movq %rdx, 0x88(%rcx)
    movq %rbx, 0x90(%rcx)
    leaq 8(%rsp), %rax
    movq %rax, 0x98(%rcx)
    movq %rbp, 0xa0(%rcx)
    movq %rsi, 0xa8(%rcx)
    movq %rdi, 0xb0(%rcx)
    movq %r8, 0xb8(%rcx)
    movq %r9, 0xc0(%rcx)
    movq %r10, 0xc8(%rcx)
    movq %r11, 0xd0(%rcx)
    movq %r12, 0xd8(%rcx)
    movq %r13, 0xe0(%rcx)
    movq %r14, 0xe8(%rcx)
    movq %r15, 0xf0(%rcx)
    movq (%rsp), %rax
    movq %rax, 0xf8(%rcx)

    fxsave64 0x100(%rcx)
    stmxcsr 0x34(%rcx)
    pushfq
    popq %rax
    movl %eax, 0x44(%rcx)

    movw %cs, %ax
    movw %ax, 0x38(%rcx)
    movw %ds, %ax
    movw %ax, 0x3a(%rcx)
    movw %es, %ax
    movw %ax, 0x3c(%rcx)
    movw %fs, %ax
    movw %ax, 0x3e(%rcx)
    movw %gs, %ax
    movw %ax, 0x40(%rcx)
    movw %ss, %ax
    movw %ax, 0x42(%rcx)
    movl $0x0010000f, 0x30(%rcx)

    xorq %rax, %rax
    movq %rax, 0x00(%rcx)
    movq %rax, 0x08(%rcx)
    movq %rax, 0x10(%rcx)
    movq %rax, 0x18(%rcx)
    movq %rax, 0x20(%rcx)
    movq %rax, 0x28(%rcx)
    movq %rax, 0x48(%rcx)
    movq %rax, 0x50(%rcx)
    movq %rax, 0x58(%rcx)
    movq %rax, 0x60(%rcx)
    movq %rax, 0x68(%rcx)
    movq %rax, 0x70(%rcx)

    /* Vector/debug tail is not captured by FXSAVE and is reported as zero. */
    pushq %rdi
    leaq 0x300(%rcx), %rdi
    movl $58, %ecx
    rep stosq
    popq %rdi
    ret
    .size sl_kernel32_rtl_capture_context, .-sl_kernel32_rtl_capture_context

    .p2align 4
    .globl sl_kernel32_raise_exception
    .type sl_kernel32_raise_exception, @function
sl_kernel32_raise_exception:
    /* Save Windows register arguments in their caller-provided home area. */
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)

    /* Shadow space, fifth argument, volatile snapshots, and aligned CONTEXT. */
    subq $0x548, %rsp
    movq %rax, 0x28(%rsp)
    movq %r10, 0x30(%rsp)
    movq %r11, 0x38(%rsp)
    leaq 0x50(%rsp), %rcx
    call sl_kernel32_rtl_capture_context

    leaq 0x548(%rsp), %r11
    movq (%r11), %rax
    movq %rax, 0x148(%rsp) /* CONTEXT.Rip */
    leaq 8(%r11), %rax
    movq %rax, 0xe8(%rsp)  /* CONTEXT.Rsp */
    movq 8(%r11), %rax
    movq %rax, 0xd0(%rsp)  /* CONTEXT.Rcx */
    movq 16(%r11), %rax
    movq %rax, 0xd8(%rsp)  /* CONTEXT.Rdx */
    movq 24(%r11), %rax
    movq %rax, 0x108(%rsp) /* CONTEXT.R8 */
    movq 32(%r11), %rax
    movq %rax, 0x110(%rsp) /* CONTEXT.R9 */
    movq 0x28(%rsp), %rax
    movq %rax, 0xc8(%rsp)  /* CONTEXT.Rax */
    movq 0x30(%rsp), %rax
    movq %rax, 0x118(%rsp) /* CONTEXT.R10 */
    movq 0x38(%rsp), %rax
    movq %rax, 0x120(%rsp) /* CONTEXT.R11 */

    movq 0x550(%rsp), %rcx
    movq 0x558(%rsp), %rdx
    movq 0x560(%rsp), %r8
    movq 0x568(%rsp), %r9
    leaq 0x50(%rsp), %rax
    movq %rax, 0x20(%rsp)
    call sl_kernel32_raise_exception_dispatch
    addq $0x548, %rsp
    ret
    .size sl_kernel32_raise_exception, .-sl_kernel32_raise_exception

    .p2align 4
    .globl sl_kernel32_rtl_unwind_ex
    .type sl_kernel32_rtl_unwind_ex, @function
sl_kernel32_rtl_unwind_ex:
    /* Preserve all six Windows arguments before capturing the guest caller. */
    movq %rcx, 0x08(%rsp)
    movq %rdx, 0x10(%rsp)
    movq %r8, 0x18(%rsp)
    movq %r9, 0x20(%rsp)
    subq $0x58, %rsp
    movq %rax, 0x30(%rsp)
    movq %r10, 0x38(%rsp)
    movq %r11, 0x40(%rsp)

    leaq 0x58(%rsp), %r11
    movq 0x28(%r11), %rcx
    testq %rcx, %rcx
    je .Lrtl_unwind_dispatch
    call sl_kernel32_rtl_capture_context

    leaq 0x58(%rsp), %r11
    movq 0x28(%r11), %rax
    movq 0x00(%r11), %rdx
    movq %rdx, 0xf8(%rax) /* CONTEXT.Rip */
    leaq 0x08(%r11), %rdx
    movq %rdx, 0x98(%rax) /* CONTEXT.Rsp */
    movq 0x08(%r11), %rdx
    movq %rdx, 0x80(%rax) /* CONTEXT.Rcx */
    movq 0x10(%r11), %rdx
    movq %rdx, 0x88(%rax) /* CONTEXT.Rdx */
    movq 0x18(%r11), %rdx
    movq %rdx, 0xb8(%rax) /* CONTEXT.R8 */
    movq 0x20(%r11), %rdx
    movq %rdx, 0xc0(%rax) /* CONTEXT.R9 */
    movq 0x30(%rsp), %rdx
    movq %rdx, 0x78(%rax) /* CONTEXT.Rax */
    movq 0x38(%rsp), %rdx
    movq %rdx, 0xc8(%rax) /* CONTEXT.R10 */
    movq 0x40(%rsp), %rdx
    movq %rdx, 0xd0(%rax) /* CONTEXT.R11 */

.Lrtl_unwind_dispatch:
    leaq 0x58(%rsp), %r10
    movq 0x08(%r10), %rcx
    movq 0x10(%r10), %rdx
    movq 0x18(%r10), %r8
    movq 0x20(%r10), %r9
    movq 0x28(%r10), %rax
    movq %rax, 0x20(%rsp)
    movq 0x30(%r10), %rax
    movq %rax, 0x28(%rsp)
    call sl_kernel32_rtl_unwind_ex_dispatch
    ud2
    .size sl_kernel32_rtl_unwind_ex, .-sl_kernel32_rtl_unwind_ex

    .p2align 4
    .globl sl_win64_restore_context
    .type sl_win64_restore_context, @function
sl_win64_restore_context:
    movq %rcx, %r11
    fxrstor64 0x100(%r11)
    /* CONTEXT.MxCsr is authoritative when a filter edits continuation state. */
    ldmxcsr 0x34(%r11)
    movl 0x44(%r11), %eax
    pushq %rax
    popfq

    movq 0x78(%r11), %rax
    movq 0x80(%r11), %rcx
    movq 0x88(%r11), %rdx
    movq 0x90(%r11), %rbx
    movq 0xa0(%r11), %rbp
    movq 0xa8(%r11), %rsi
    movq 0xb0(%r11), %rdi
    movq 0xb8(%r11), %r8
    movq 0xc0(%r11), %r9
    movq 0xc8(%r11), %r10
    movq 0xd8(%r11), %r12
    movq 0xe0(%r11), %r13
    movq 0xe8(%r11), %r14
    movq 0xf0(%r11), %r15
    movq 0x98(%r11), %rsp
    pushq 0xf8(%r11)
    movq 0xd0(%r11), %r11
    ret
    .size sl_win64_restore_context, .-sl_win64_restore_context

    .section .note.GNU-stack,"",@progbits
