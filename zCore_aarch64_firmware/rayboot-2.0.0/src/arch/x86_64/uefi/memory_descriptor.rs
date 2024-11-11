use crate::arch::x86_64::legacy_memory_region::LegacyMemoryRegion;
use crate::boot_info::MemoryRegionKind;
use uefi::table::boot::{MemoryDescriptor, MemoryType};
use x86_64::PhysAddr;

const PAGE_SIZE: u64 = 4096;

// UEFI内存描述符
impl<'a> LegacyMemoryRegion for MemoryDescriptor {
    fn start(&self) -> PhysAddr {
        PhysAddr::new(self.phys_start)
    }

    fn len(&self) -> u64 {
        self.page_count * PAGE_SIZE
    }

    fn kind(&self) -> MemoryRegionKind {
        match self.ty {
            MemoryType::CONVENTIONAL => MemoryRegionKind::Usable,
            other => MemoryRegionKind::UnknownUefi(other.0),
        }
    }
}
