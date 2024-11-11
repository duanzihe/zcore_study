ENTRY(_start)
BASE_ADDRESS = 0xffff000040080000;

SECTIONS
{
    . = BASE_ADDRESS;
    skernel = .;

    .text ALIGN(4K): {  #Z修改！添加l align4k
        stext = .;
        *(.text.entry)
        *(.text .text.*)
        . = ALIGN(4K);
        etext = .;
    }

    .rodata ALIGN(4K): { #Z修改！添加l align4k
        srodata = .;
        *(.rodata .rodata.*)
        *(.srodata .srodata.*)
    #    . = ALIGN(4K);  #z修改！不能这么早结束rodata段，后面的kcounter需要存在这里
    #    erodata = .;     #z修改！不能在这里做结束标记， 因为后面还有kcounter
    }
#Z修改！这里需要添加kcounter的符号
  .kcounter.desc ALIGN(4K):
  {
    PROVIDE_HIDDEN(kcounters_desc_vmo_start = .);
    KEEP(*(.kcounter.desc.header))
    QUAD(kcounters_desc_end - kcounters_desc_start);
    ASSERT(. - kcounters_desc_vmo_start == 24, "wrong size of the kcounter descriptor VMO header");

    PROVIDE_HIDDEN(kcounters_desc_start = .);
    KEEP(*(SORT_BY_NAME(.kcounter.desc.*)))
    PROVIDE_HIDDEN(kcounters_desc_end = .);
   erodata = .;  # Z修改！在这里定义 erodata，确保它指向真正的 rodata 段末尾
  } :rodata
#Z修改完毕！

    .data ALIGN(4K): { #Z修改！添加l align4k
        sdata = .;
        *(.data .data.*)
        *(.sdata .sdata.*)
        . = ALIGN(4K);  
        edata = .;
    }

    .bss ALIGN(4K): {  
        boot_stack = .;
        *(.bss.stack)
        . = ALIGN(4K);
        boot_stack_top = .;

        sbss = .;
        #Z修改！添加l align4k
        #Z修改！这里需要添加kcounter的符号
        PROVIDE_HIDDEN(kcounters_arena_start = .);
        KEEP(*(SORT_BY_NAME(.bss.kcounter.*)))
        PROVIDE_HIDDEN(kcounters_arena_end = .);
        ASSERT(kcounters_arena_end - kcounters_arena_start == (kcounters_desc_end - kcounters_desc_start) * 8 / 64,
              "kcounters_arena size mismatch");
        #Z修改完毕！

        *(.bss .bss.*)
        *(.sbss .sbss.*)
        . = ALIGN(4K);
        ebss = .;
    }

    ekernel = .;

    /DISCARD/ : {
        *(.eh_frame) *(.eh_frame_hdr)
    }
}