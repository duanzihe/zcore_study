//! Define dynamic memory allocation.

use crate::platform::phys_to_virt_offset;
use alloc::alloc::handle_alloc_error;
use core::{
    alloc::{GlobalAlloc, Layout},
    num::NonZeroUsize,
    ops::Range,
    ptr::NonNull,
};
use customizable_buddy::{BuddyAllocator, LinkedListBuddy, UsizeBuddy};
use kernel_hal::PhysAddr;
use lock::Mutex;

/// 堆分配器。
///
/// 27 + 6 + 3 = 36 -> 64 GiB
struct LockedHeap(Mutex<BuddyAllocator<27, UsizeBuddy, LinkedListBuddy>>);

#[global_allocator]
//初始化了一个可以管理最多 64 GiB 空间的堆分配器
static HEAP: LockedHeap = LockedHeap(Mutex::new(BuddyAllocator::new()));

/// 单页地址位数。
const PAGE_BITS: usize = 12;

/// 为启动准备的初始内存。
///
/// 经测试，不同硬件的需求：
///
/// | machine         | memory
/// | --------------- | -
/// | qemu,virt SMP 1 |  16 KiB
/// | qemu,virt SMP 4 |  32 KiB
/// | allwinner,nezha | 256 KiB
static mut MEMORY: [u8; 2 * 1024 * 1024] = [0u8; 2 * 1024 * 1024];  //这个 MEMORY 作为一个全局的内存块，会被分配器管理，用于在程序启动时提供一小块堆内存，供动态内存分配使用。

unsafe impl GlobalAlloc for LockedHeap {
    #[inline]
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if let Ok((ptr, _)) = self.0.lock().allocate_layout(layout) {
            ptr.as_ptr()
        } else {
            handle_alloc_error(layout)
        }
    }

    #[inline]
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        self.0
            .lock()
            .deallocate_layout(NonNull::new(ptr).unwrap(), layout)
    }
}

/// 初始化一个堆分配器，并将预定义的 MEMORY 内存块注册到堆分配器中，供操作系统在启动时进行动态内存管理
/// 可以理解为memory是分配器管理动态内存块们的“元数据”
pub fn init() {
    unsafe {
        log::info!("MEMORY = {:#?}", MEMORY.as_ptr_range()); //使用 log 库输出调试信息，将 MEMORY 中保存的内存区域的指针范围打印出来
        let mut heap = HEAP.0.lock();
        let ptr = NonNull::new(MEMORY.as_mut_ptr()).unwrap();
        heap.init(core::mem::size_of::<usize>().trailing_zeros() as _, ptr);
        heap.transfer(ptr, MEMORY.len());
    }
}

/// 将一些内存区域注册到分配器。
/// 通过遍历传入的物理内存区域列表，将每一个有效的内存区域转换为虚拟地址后，注册到一个内存分配器中，以便之后可以分配和管理这些内存区域。
/// 内存读写是基于分配器分配的内存块，但是要从虚拟地址空间找到物理地址空间对应的内存块就需要查页表
pub fn insert_regions(regions: &[Range<PhysAddr>]) {
    let mut heap = HEAP.0.lock();
    let offset = phys_to_virt_offset();
    regions
        .iter()
        .filter(|region| !region.is_empty())
        .for_each(|region| unsafe {
            heap.transfer(
                NonNull::new_unchecked((region.start + offset) as *mut u8),
                region.len(),
            );
        });
}

pub fn frame_alloc(frame_count: usize, align_log2: usize) -> Option<PhysAddr> {
    let (ptr, size) = HEAP
        .0
        .lock()
        .allocate::<u8>(align_log2 << PAGE_BITS, unsafe {
            NonZeroUsize::new_unchecked(frame_count << PAGE_BITS)
        })
        .ok()?;
    assert_eq!(size, frame_count << PAGE_BITS);
    Some(ptr.as_ptr() as PhysAddr - phys_to_virt_offset())
}

pub fn frame_dealloc(target: PhysAddr) {
    HEAP.0.lock().deallocate(
        unsafe { NonNull::new_unchecked((target + phys_to_virt_offset()) as *mut u8) },
        1 << PAGE_BITS,
    );
}
