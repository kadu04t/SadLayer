    .text
    .p2align 4
    .globl sl_test_capture_context_probe
    .type sl_test_capture_context_probe, @function
sl_test_capture_context_probe:
    pushq %rbx
    pushq %rbp
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15
    subq $72, %rsp

    /* Preserve SysV arguments beyond the Windows shadow space. */
    movq %rdi, 32(%rsp)
    movq %rsi, 40(%rsp)
    leaq .Lcapture_return(%rip), %rax
    movq %rax, 0(%rsi)
    movq %rsp, 8(%rsi)

    movabsq $0x1111111122222222, %rbx
    movabsq $0x3333333344444444, %rbp
    movabsq $0x5555555566666666, %rsi
    movabsq $0x7777777788888888, %rdi
    movabsq $0x99999999aaaaaaaa, %r12
    movabsq $0xbbbbbbbbcccccccc, %r13
    movabsq $0xddddddddeeeeeeee, %r14
    movabsq $0xf0f0f0f00f0f0f0f, %r15
    movabsq $0x123456789abcdef0, %rdx
    movabsq $0x23456789abcdef01, %r8
    movabsq $0x3456789abcdef012, %r9
    movdqa .Lxmm6_value(%rip), %xmm6
    movq 32(%rsp), %rcx
    movabsq $0x456789abcdef0123, %rax
    call sl_kernel32_rtl_capture_context
.Lcapture_return:
    movq 40(%rsp), %rax
    movq %rbx, 16(%rax)
    movq %rbp, 24(%rax)
    movq %rsi, 32(%rax)
    movq %rdi, 40(%rax)
    movq %r12, 48(%rax)
    movq %r13, 56(%rax)
    movq %r14, 64(%rax)
    movq %r15, 72(%rax)
    movdqu %xmm6, 80(%rax)

    addq $72, %rsp
    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %rbp
    popq %rbx
    ret
    .size sl_test_capture_context_probe, .-sl_test_capture_context_probe

    .section .rodata
    .p2align 4
.Lxmm6_value:
    .quad 0x0123456789abcdef
    .quad 0xfedcba9876543210

    .section .note.GNU-stack,"",@progbits
