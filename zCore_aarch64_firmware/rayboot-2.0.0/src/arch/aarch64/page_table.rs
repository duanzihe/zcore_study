use bitflags::*;

bitflags! {
    pub struct MemFlags: usize {
        const READ          = 1 << 0;
        const WRITE         = 1 << 1;
        const EXECUTE       = 1 << 2;
        const USER          = 1 << 3;
        const DEVICE        = 1 << 4;
    }
}

bitflags! {
    /// Memory attribute fields in the VMSAv8-64 translation table format descriptors.
    pub struct DescriptorAttr: u64 {
        // Attribute fields in stage 1 VMSAv8-64 Block and Page descriptors:

        /// Whether the descriptor is valid.
        const VALID =       1 << 0;
        /// The descriptor gives the address of the next level of translation table or 4KB page.
        /// (not a 2M, 1G block)
        const NON_BLOCK =   1 << 1;
        /// Memory attributes index field.
        const ATTR_INDX =   0b111 << 2;
        /// Non-secure bit. For memory accesses from Secure state, specifies whether the output
        /// address is in Secure or Non-secure memory.
        const NS =          1 << 5;
        /// Access permission: accessable at EL0.
        const AP_EL0 =      1 << 6;
        /// Access permission: read-only.
        const AP_RO =       1 << 7;
        /// Shareability: Inner Shareable (otherwise Outer Shareable).
        const INNER =       1 << 8;
        /// Shareability: Inner or Outer Shareable (otherwise Non-shareable).
        const SHAREABLE =   1 << 9;
        /// The Access flag.
        const AF =          1 << 10;
        /// The not global bit.
        const NG =          1 << 11;
        /// Indicates that 16 adjacent translation table entries point to contiguous memory regions.
        const CONTIGUOUS =  1 <<  52;
        /// The Privileged execute-never field.
        const PXN =         1 <<  53;
        /// The Execute-never or Unprivileged execute-never field.
        const UXN =         1 <<  54;

        // Next-level attributes in stage 1 VMSAv8-64 Table descriptors:

        /// PXN limit for subsequent levels of lookup.
        const PXN_TABLE =           1 << 59;
        /// XN limit for subsequent levels of lookup.
        const XN_TABLE =            1 << 60;
        /// Access permissions limit for subsequent levels of lookup: access at EL0 not permitted.
        const AP_NO_EL0_TABLE =     1 << 61;
        /// Access permissions limit for subsequent levels of lookup: write access not permitted.
        const AP_NO_WRITE_TABLE =   1 << 62;
        /// For memory accesses from Secure state, specifies the Security state for subsequent
        /// levels of lookup.
        const NS_TABLE =            1 << 63;
    }
}

#[repr(u64)]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum MemType {
    Device = 0,
    Normal = 1,
}

impl DescriptorAttr {
    const ATTR_INDEX_MASK: u64 = 0b111_00;

    const fn from_mem_type(mem_type: MemType) -> Self {
        let mut bits = (mem_type as u64) << 2;
        if matches!(mem_type, MemType::Normal) {
            bits |= Self::INNER.bits() | Self::SHAREABLE.bits();
        }
        Self::from_bits_truncate(bits)
    }

    fn mem_type(&self) -> MemType {
        let idx = (self.bits() & Self::ATTR_INDEX_MASK) >> 2;
        match idx {
            0 => MemType::Device,
            1 => MemType::Normal,
            _ => panic!("Invalid memory attribute index"),
        }
    }
}

impl From<DescriptorAttr> for MemFlags {
    // 根据内存标识构建ARM内存标识位
    fn from(attr: DescriptorAttr) -> Self {
        let mut flags = Self::empty();
        if attr.contains(DescriptorAttr::VALID) {
            flags |= Self::READ;
        }
        if !attr.contains(DescriptorAttr::AP_RO) {
            flags |= Self::WRITE;
        }
        if attr.contains(DescriptorAttr::AP_EL0) {
            flags |= Self::USER;
            if !attr.contains(DescriptorAttr::UXN) {
                flags |= Self::EXECUTE;
            }
        } else if !attr.intersects(DescriptorAttr::PXN) {
            flags |= Self::EXECUTE;
        }
        if attr.mem_type() == MemType::Device {
            flags |= Self::DEVICE;
        }
        flags
    }
}

impl From<MemFlags> for DescriptorAttr {
    fn from(flags: MemFlags) -> Self {
        let mut attr = if flags.contains(MemFlags::DEVICE) {
            Self::from_mem_type(MemType::Device)
        } else {
            Self::from_mem_type(MemType::Normal)
        };
        if flags.contains(MemFlags::READ) {
            attr |= Self::VALID;
        }
        if !flags.contains(MemFlags::WRITE) {
            attr |= Self::AP_RO;
        }
        if flags.contains(MemFlags::USER) {
            attr |= Self::AP_EL0 | Self::PXN;
            if !flags.contains(MemFlags::EXECUTE) {
                attr |= Self::UXN;
            }
        } else {
            attr |= Self::UXN;
            if !flags.contains(MemFlags::EXECUTE) {
                attr |= Self::PXN;
            }
        }
        attr
    }
}

const PA_1TB_BITS: usize = 40;
const PAGE_SIZE: usize = 0x1000;
const PHYSADDR_MAX: usize = (1 << PA_1TB_BITS) - 1;  //最大物理地址 是 0x0FF FFFF FFFF

#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct PageTableEntry(u64);

impl PageTableEntry {
    const PHYS_ADDR_MASK: usize = PHYSADDR_MAX & !(PAGE_SIZE - 1); //这里取掩码,就是0xFF FFFF F000
    pub const fn empty() -> Self {
        Self(0)               //创建一个值为0的实例
    }
    pub fn new_page(paddr: u64, flags: MemFlags, is_block: bool) -> Self {
        let mut attr = DescriptorAttr::from(flags) | DescriptorAttr::AF;
        if !is_block {
            attr |= DescriptorAttr::NON_BLOCK;
        }
        Self(attr.bits() | (paddr as usize & Self::PHYS_ADDR_MASK) as u64) //高24位是页表项属性，低40位是物理地址
    }
    pub fn new_table(paddr: u64) -> Self {
        let attr = DescriptorAttr::NON_BLOCK | DescriptorAttr::VALID;
        Self(attr.bits() | (paddr as usize & Self::PHYS_ADDR_MASK) as u64)
    }
    pub fn clear(&mut self) {
        self.0 = 0;
    }
}
