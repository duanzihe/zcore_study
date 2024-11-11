// aarch64

use spin::Once;

static OFFSET: Once<usize> = Once::new();  //once是为了确保代码只执行一次，是惰性，且线程安全的

#[inline]
pub(super) fn save_offset(offset: usize) {
    OFFSET.call_once(|| offset);
}

#[inline]
pub fn phys_to_virt_offset() -> usize {
    *OFFSET.wait()
}
