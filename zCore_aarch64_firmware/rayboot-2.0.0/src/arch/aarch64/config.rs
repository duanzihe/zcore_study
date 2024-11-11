use acpi::{AcpiHandler, PhysicalMapping};
use core::ptr::NonNull;

pub const KERNEL_LOCATION: &'static str = "os";
pub const ARM64_PAGE_SIZE_BITS: usize = 12;

#[derive(Debug)]
pub struct KernelHeader {
    pub pk_size: usize,
    pub sign_size: usize,
}

#[derive(Clone)]
pub struct IdentityMapped;
impl AcpiHandler for IdentityMapped {
    unsafe fn map_physical_region<T>(
        &self,
        physical_address: usize,
        size: usize,
    ) -> PhysicalMapping<Self, T> {
        PhysicalMapping::new(
            physical_address,
            NonNull::new(physical_address as *mut _).unwrap(),
            size,
            size,
            Self,
        )
    }

    fn unmap_physical_region<T>(_region: &PhysicalMapping<Self, T>) {}
}
