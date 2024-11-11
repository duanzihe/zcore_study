.equ STACK_MAX, 4096 * 16
.equ STACK_MAX_HARTS, 8

	.section .text.entry
	.globl _start
_start:
	#关中断,打扫干净屋子再请客，防止系统启动时的初始化过程被中断请求干扰。
	#csrw 是 RISC-V 指令集中的一条 CSR (Control and Status Register) 访问指令，用于将一个通用寄存器的值写入到一个控制状态寄存器（CSR）中。
	csrw sie, zero #清空 sie 寄存器，sie 是 Supervisor Interrupt Enable 寄存器，用于控制超级模式下的中断使能。将其置零可以关闭所有中断。
	csrw sip, zero #清空 sip 寄存器，sip 是 Supervisor Interrupt Pending 寄存器，用于查看哪些中断正在挂起。将其置零表示将挂起的中断标记清除。

	#关闭mmu，将 satp 寄存器清零，相当于关闭虚拟内存系统（MMU）。这意味着 CPU 会直接访问物理内存，而不是通过页表进行地址转换。
	#这是因为 在启动的早期阶段，虚拟内存还没有设置好，内核首先在物理地址空间下工作，稍后会设置页表并打开虚拟内存。
	csrw satp, zero  #satp 寄存器是 RISC-V 架构中用于 Supervisor Address Translation and Protection 的寄存器，它控制着虚拟内存系统的启用和页表基地址。

	#检查BSS节是否清零 ，BSS 的全称是 Block Started by Symbol。它是内存中专门用于存储未初始化的全局变量的区域。
	#清零 BSS 段是为了避免潜在的内存问题，确保所有未初始化的全局变量和静态变量都从零开始；
	#如果BSS没清空，那全局变量在定义时如果被恰好分配到没清空的地方，就会在未初始化的时候有一个初始值
	la t0, sbss #la 是 "load address" 的缩写。这个指令将符号 sbss 的地址加载到寄存器 t0 中。sbss 是 BSS 段开始的位置（符号名称），即 BSS 段的起始地址。
	la t1, ebss #将符号 ebss 的地址加载到寄存器 t1 中。ebss 是 BSS 段结束的位置（符号名称），即 BSS 段的结束地址。
	bgeu t0, t1, primary_hart  #如果 sbss（BSS 段的开始地址）已经不小于 ebss（BSS 段的结束地址），说明 BSS 段为空或者已经被处理完毕，这时直接跳转到 primary_hart，跳过 BSS 段的清零操作。
# 如果BSS没清空，就在这里清空，全部置零
clear_bss_loop:
	# sd: store double word (64 bits)
	sd zero, (t0)
	addi t0, t0, 8
	bltu t0, t1, clear_bss_loop
	
primary_hart:
	call init_vm  # 调用 init_vm 函数，初始化虚拟内存
	#函数符号的“链接地址”固定地在操作系统的虚拟内存的某个位置，而引导程序会固定的把操作系统内核放在物理内存的某个位置,
	#因此偏移量是固定的，“链接地址”+“偏移量”=primary_rust_main的物理地址。
	
	la t0, primary_rust_main # 加载 primary_rust_main 函数的“链接地址”到寄存器 t0
	la t1, PHY_MEM_OFS # 加载 PHY_MEM_OFS “偏移地址”的地址到寄存器 t1
	ld t1, (t1)  # 从 PHY_MEM_OFS 地址处取内容，加载偏移量到寄存器 t1
	add t0, t0, t1 #将链接地址加上偏移量后，t0 中存储的就是 primary_rust_main 在物理内存中的地址
	jr t0 #jr 是 "jump register" 的缩写，表示跳转到寄存器 t0 中存储的地址开始执行，这里就是跳转到primary_rust_main

.globl secondary_hart_start
secondary_hart_start:
	csrw sie, zero
	csrw sip, zero
	call init_vm
	la t0, secondary_rust_main
	la t1, PHY_MEM_OFS
	ld t1, (t1)
	add t0, t0, t1
	jr t0

init_vm:
	#获取页表的物理地址
	la t0, boot_page_table_sv39

	#右移12位，变为satp的PPN
	srli t0, t0, 12

	#satp的MODE设为Sv39
	li t1, 8 << 60

	#写satp
	or t0, t0, t1

	#刷新TLB
	sfence.vma

	csrw satp, t0

	#此时在虚拟内存空间，设置sp为虚拟地址
	li t0, STACK_MAX
	mul t0, t0, a0

	la t1, boot_stack_top
	la t2, PHY_MEM_OFS
	ld t2, (t2)
	add sp, t1, t2

	#计算多个核的sp偏移
	sub sp, sp, t0
	ret

	.section .data
	.align 12 #12位对齐
boot_page_table_sv39:
	#1G的一个大页: 0x00000000_00000000 --> 0x00000000
	#1G的一个大页: 0x00000000_80000000 --> 0x80000000
	#1G的一个大页: 0xffffffe0_00000000 --> 0x00000000
	#1G的一个大页: 0xffffffe0_80000000 --> 0x80000000

	.quad (0 << 10) | 0xef
	.zero 8
	.quad (0x80000 << 10) | 0xef

	.zero 8 * 381
	.quad (0 << 10) | 0xef
	.zero 8
	.quad (0x80000 << 10) | 0xef
	.zero 8 * 125

	.section .bss.stack
	.align 12
	.global boot_stack
boot_stack:
	.space STACK_MAX * STACK_MAX_HARTS
	.global boot_stack_top
boot_stack_top:
