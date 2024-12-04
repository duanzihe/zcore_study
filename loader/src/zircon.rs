//! Run Zircon user program (userboot) and manage trap/interrupt/syscall.
//!
//! Reference: <https://fuchsia.googlesource.com/fuchsia/+/3c234f79f71/zircon/kernel/lib/userabi/userboot.cc>

use alloc::{boxed::Box, sync::Arc, vec::Vec};
use core::{future::Future, pin::Pin};

use xmas_elf::ElfFile;

use kernel_hal::context::{TrapReason, UserContext, UserContextField};
use kernel_hal::{MMUFlags, PAGE_SIZE};
use zircon_object::dev::{Resource, ResourceFlags, ResourceKind};
use zircon_object::ipc::{Channel, MessagePacket};
use zircon_object::kcounter;
use zircon_object::object::{Handle, KernelObject, Rights};
use zircon_object::task::{CurrentThread, ExceptionType, Job, Process, Thread, ThreadState};
use zircon_object::util::elf_loader::{ElfExt, VmarExt};
use zircon_object::vm::{VmObject, VmarFlags};

//这一块儿都是handles的索引，一会儿用到就清楚了。
// These describe userboot itself
const K_PROC_SELF: usize = 0;
const K_VMARROOT_SELF: usize = 1;
// Essential job and resource handles
const K_ROOTJOB: usize = 2;
const K_ROOTRESOURCE: usize = 3;
// Essential VMO handles
const K_ZBI: usize = 4;
const K_FIRSTVDSO: usize = 5; //之所以没有6和7,是因为他被分配给了vdso的两个子视图。
const K_CRASHLOG: usize = 8;
const K_COUNTER_NAMES: usize = 9;
const K_COUNTERS: usize = 10;
const K_FISTINSTRUMENTATIONDATA: usize = 11;
const K_HANDLECOUNT: usize = 15;

//根据目标架构和编译时配置来包含不同的库文件
macro_rules! boot_library {  
    ($name: expr) => {{  //如果只传入了一个name参数
        cfg_if::cfg_if! {  //就利用cfg_if::cfg_if! 来实现条件编译。这允许根据编译时的配置和目标架构来选择不同的代码路径。
            if #[cfg(target_arch = "x86_64")] {   //如果是x64
                boot_library!($name, "../../prebuilt/zircon/x64")  //就自己调用自己的两参数实现，来部署对应路径的库
            } else if #[cfg(target_arch = "aarch64")] { //arm64同理
                boot_library!($name, "../../prebuilt/zircon/arm64")
            } else {   //都不是就报编译失败，不支持这架构。
                compile_error!("Unsupported architecture for zircon mode!")
            }
        }
    }};
    ($name: expr, $base_dir: expr) => {{  //如果传入了两个参数
        #[cfg(feature = "libos")]  //如果启用了libos
        {   //include_bytes! 是一个编译时宏，它在编译期间将文件的内容嵌入到生成的二进制文件中。
            include_bytes!(concat!($base_dir, "/", $name, "-libos.so")) //就静态嵌入对应的库文件,注意！！这里没有冒号，这里是一个表达式而非语句！是返回值的！他返回了一个字节数组！
        }
        #[cfg(not(feature = "libos"))]  //同理
        {
            include_bytes!(concat!($base_dir, "/", $name)) //Z报错！couldn't read loader/src/../../prebuilt/zircon/arm64/userboot.so: No such file or directory
        }
    }};
}

//为计数器分配VMO
fn kcounter_vmos() -> (Arc<VmObject>, Arc<VmObject>) {  //返回两个 VmObject 类型的对象，用于管理描述符表和计数器数据
    let (desc_vmo, arena_vmo) = if cfg!(feature = "libos") {  //如果启用了libos,则执行此分支
        // dummy VMOs
        use zircon_object::util::kcounter::DescriptorVmoHeader;  //使用 DescriptorVmoHeader 结构体，该结构体用于描述符表的头部信息
        const HEADER_SIZE: usize = core::mem::size_of::<DescriptorVmoHeader>(); //HEADER_SIZE 保存了 DescriptorVmoHeader 结构体的大小。
        let desc_vmo = VmObject::new_paged(1); //创建了两个新的分页（paged）虚拟内存对象（VMO），每个大小为1页。
        let arena_vmo = VmObject::new_paged(1);

        let header = DescriptorVmoHeader::default(); //创建默认的描述符表头
        let header_buf: [u8; HEADER_SIZE] = unsafe { core::mem::transmute(header) };//core::mem::transmute 将 header 结构体转换为字节数组 header_buf。
        //注意，VmObject 的 write 方法要求输入的是一个字节数组或类似的字节切片（&[u8]），而不是直接的结构体。所以要先转换成字节数组，再写入。
        //这是因为 VmObject 操作的是原始内存区域，通常表示文件、内存映射或其他二进制数据。
        desc_vmo.write(0, &header_buf).unwrap(); // 将头部信息写入到 desc_vmo 的起始地址
        (desc_vmo, arena_vmo)
    } else {   //如果没有启用libos
        use kernel_hal::vm::{GenericPageTable, PageTable}; //引入通用页表和页表，用于管理虚拟内存到物理内存的映射
        use zircon_object::{util::kcounter::AllCounters, vm::pages};
        let pgtable = PageTable::from_current(); //获取当前页表

        // kcounters names table.
        //获取包含DescriptorVmoHeader 和描述符表（table of Descriptor）的VMO数据的原始二进制形式的引用。
        let desc_vmo_data = AllCounters::raw_desc_vmo_data(); 
        //通过as_ptr获取指向desc_vmo_data虚拟地址的指针，再通过pgtable来query得到物理地址（physical_addr)。
        let paddr = pgtable.query(desc_vmo_data.as_ptr() as usize).unwrap().0;   //Z报错！这里说undefined symbol: kcounters_desc_vmo_start
        //创建一个新的虚拟内存对象desc_vmo，代表一段从paddr开始，连续占据desc_vmo_data大小的物理内存
        let desc_vmo = VmObject::new_physical(paddr, pages(desc_vmo_data.len()));

        // kcounters live data.
        //获取kcounter内存池的原始数据
        let arena_vmo_data = AllCounters::raw_arena_vmo_data();
        //同上获取虚拟地址指针再查物理地址
        let paddr = pgtable.query(arena_vmo_data.as_ptr() as usize).unwrap().0;
        //根据物理地址和数据大小创建arena_vmo
        let arena_vmo = VmObject::new_physical(paddr, pages(arena_vmo_data.len()));
        (desc_vmo, arena_vmo)
    };
    //疑惑：为什么要再设置一个别名？
    desc_vmo.set_name("counters/desc");
    arena_vmo.set_name("counters/arena");
    (desc_vmo, arena_vmo)
}

/// Run Zircon `userboot` process from the prebuilt path, and load the ZBI file as the bootfs.
/// 
/// 从预定的路径运行zircon的userboot程序，并加载ZBI（zircon boot image）作为bootfs（根文件系统）
/// 获取userboot和作为vdso的libzircon的elf文件，并为他们初始化对应的vmo并map到虚拟地址区
/// 再把实际的系统调用入口点映射到vdso_vmo中zcore_syscall_entry的位置，实现“系统调用的跳板“
/// 为zbi初始化一个vmo
pub fn run_userboot(zbi: impl AsRef<[u8]>, cmdline: &str) -> Arc<Process> {

    let userboot = boot_library!("nebula_libuserboot.so"); //用userboot接收嵌入的userboot程序 Z报错！


    let vdso = boot_library!("libzircon.so"); //用vdso接收嵌入的libzircon系统调用库


    let job = Job::root(); //创建根任务  Z报错！页面错误
    

    let proc = Process::create(&job, "userboot").unwrap();//创建userboot进程
    

    let thread = Thread::create(&proc, "userboot").unwrap();//创建userboot线程
    

    let resource = Resource::create( //分配资源
        "root",
        ResourceKind::ROOT,
        0,
        0x1_0000_0000,
        ResourceFlags::empty(),
    );
    

    let vmar = proc.vmar(); //初始化进程的虚拟地址区域
    

    // 用elf加载器把userboot程序加载到内存，并用entry记录程序入口点的虚拟地址，userboot_size记录大小。
    let (entry, userboot_size) = {
        let elf = ElfFile::new(userboot).unwrap(); //解析userboot的elf文件
        let size = elf.load_segment_size();//获取所有加载段的总大小。
        //为即将加载的userboot程序分配足够的虚拟内存区，none表示分配的起始位置由系统来定
        let vmar = vmar
            .allocate(None, size, VmarFlags::CAN_MAP_RXW, PAGE_SIZE)
            .unwrap();
        //为所有可加载段创建vmo,并把他们map到vmar中
        vmar.load_from_elf(&elf).unwrap();
        //虚拟内存区的起始地址+elf程序中的入口点的偏移量，得到程序入口点的虚拟地址，再返回userboot的size
        (vmar.addr() + elf.header.pt2.entry_point() as usize, size)
    };
    

    // vdso
    let vdso_vmo = {
        let elf = ElfFile::new(vdso).unwrap(); //解析作为vdso的libzircon的elf文件
        let vdso_vmo = VmObject::new_paged(vdso.len() / PAGE_SIZE + 1);//为vdso创建一个vmo
        vdso_vmo.write(0, vdso).unwrap(); //把vdso以字节数组的形式写入vmo
        let size = elf.load_segment_size(); //获取所有加载段的总大小
        //注意，这里的vmar是上面已经随机分配过一次的vmar,所以这里的分配要用allocate_at，意思就是从之前的vmar的再偏移一个userboot_size的位置来做vdso的起始地址
        let vmar = vmar 
            .allocate_at(
                userboot_size,    //偏移量为userboot_size，意思就是vdso的起始地址就跟在userboot程序的虚拟内存区后面
                size,
                VmarFlags::CAN_MAP_RXW | VmarFlags::SPECIFIC,
                PAGE_SIZE,
            )
            .unwrap();
        //疑惑：为什么这里不像加载userboot的elf程序那样，用load_from_elf,而是先创建好vdso_vmo，再用map_from-elf?
        //解答：load_from_elf 适用于简单的 ELF 文件加载，而 map_from_elf 适用于需要更精细控制和数据准备的场景，之后还需要对vdso_vmo进行具体的操作，所以这里先创建，再map。
        vmar.map_from_elf(&elf, vdso_vmo.clone()).unwrap();

        #[cfg(feature = "libos")]  //如果启用了libos,则编译以下代码
        //这段代码主要是把实际的系统调用入口点映射到vdso_vmo中zcore_syscall_entry的位置
        //用户态程序可以通过调用 zcore_syscall_entry 来触发系统调用，而不必每次都陷入内核态，从而提高性能
        {
            let offset = elf
                .get_symbol_address("zcore_syscall_entry") //尝试从 ELF 程序中获取名为 "zcore_syscall_entry" 的符号的地址。
                .expect("failed to locate syscall entry") as usize;
            //获取系统调用入口点的地址，将其转换为 usize 类型，然后再转换成网络字节序的字节序列
            //确保在设置 VDSO时,系统调用入口点的地址能够在不同的系统间正确地传递和使用
            let syscall_entry = &(kernel_hal::context::syscall_entry as usize).to_ne_bytes();
            // fill syscall entry x3
            //疑惑：为什么要在三个地方写入syscall_entry?有关对齐？防止找不到？ 姑且认为是提高兼容性和鲁棒性的手段。
            vdso_vmo.write(offset, syscall_entry).unwrap();
            vdso_vmo.write(offset + 8, syscall_entry).unwrap();
            vdso_vmo.write(offset + 16, syscall_entry).unwrap();
        }
        vdso_vmo
    };


    // 为传入的zbi创建并初始化了一个vmo
    let zbi_vmo = {
        let vmo = VmObject::new_paged(zbi.as_ref().len() / PAGE_SIZE + 1);   
        vmo.write(0, zbi.as_ref()).unwrap(); //Z报错！页面错误
        vmo.set_name("zbi");
        vmo
    };

    // stack
    //为用户进程分配栈空间，并设置栈指针（sp）。处理了栈的内存分配、映射，并在不同的架构下做了相应的处理
    const STACK_PAGES: usize = 8;  //定义了一个常量 STACK_PAGES，表示栈的页数为 8 页（一页 4KB，所以一个栈总大小为 32KB）。
    let stack_vmo = VmObject::new_paged(STACK_PAGES); //创建一个8页的vmo
    let flags = MMUFlags::READ | MMUFlags::WRITE | MMUFlags::USER;//标志表示栈的内存区域将具有读 (READ)、写 (WRITE) 和用户态 (USER) 访问权限
    //将 stack_vmo 映射到当前虚拟地址空间中的某个位置（注意，这里是none,是由系统分配），并返回映射的起始地址 stack_bottom
    //疑惑：栈的位置也是由系统自动分配，如果分配到较低地址，因为栈向下生长，那么栈上方的大量地址空间无法被利用，且可能离堆很近，生长空间很小，不利于动态扩展和有效利用空间。
    let stack_bottom = vmar
        .map(None, stack_vmo.clone(), 0, stack_vmo.len(), flags)
        .unwrap();
    //在 x86_64 架构下，栈指针 sp 设置为栈底地址 stack_bottom 加上栈的总长度再减去 8 字节
    //因为在 x86_64 架构下，栈需要对齐到 16 字节，所以栈指针得减去 8 字节来配合接下来的call压入的8字节返回地址，来凑够16字节对齐。
    //注意，是栈指针先-8,再call压入，因为x64是小端格式，从低向高寻址读数据，所以要把有效数据放在低字节，填充对齐放在高字节。
    let sp = if cfg!(target_arch = "x86_64") {
        // WARN: align stack to 16B, then emulate a 'call' (push rip)
        stack_bottom + stack_vmo.len() - 8
    } else {  //每个架构的约定方式不一样，即使都是16字节对齐，也不一定需要像x64那样对栈指针-8.
        stack_bottom + stack_vmo.len()
    };
    

    // channel
    //创建一个新的Channel。这个通道允许用户空间和内核空间之间的通信。
    let (user_channel, kernel_channel) = Channel::create();
    //创建一个handle,其拥有对user_channel的默认权限
    let handle = Handle::new(user_channel, Rights::DEFAULT_CHANNEL);
    // 创建一个动态大小的vector handles，初始化时包含 K_HANDLECOUNT 个引用了proc的Handle 对象
    let mut handles = alloc::vec![Handle::new(proc.clone(), Rights::empty()); K_HANDLECOUNT];
    //表示进程自己在 handles 向量中的索引。这些索引就在在本文件的最上方定义。
    handles[K_PROC_SELF] = Handle::new(proc.clone(), Rights::DEFAULT_PROCESS);
    //表示虚拟地址空间根对象在 handles 向量中的索引。
    handles[K_VMARROOT_SELF] = Handle::new(proc.vmar(), Rights::DEFAULT_VMAR | Rights::IO);
    //根任务
    handles[K_ROOTJOB] = Handle::new(job, Rights::DEFAULT_JOB);
    //资源
    handles[K_ROOTRESOURCE] = Handle::new(resource, Rights::DEFAULT_RESOURCE);
    //zbi_vmo
    handles[K_ZBI] = Handle::new(zbi_vmo, Rights::DEFAULT_VMO);
    

    //接下来是将内核中vdsoa相关的数据，注入到作为参数传入的vdso文件里，制作得到完整的vdso
    // set up handles[K_FIRSTVDSO..K_LASTVDSO + 1]
    //从VDSO的起始地址向后偏移 0x4a50 字节处开始，接下来的 0x78 字节就是存储常量数据的区域
    const VDSO_DATA_CONSTANTS: usize = 0x4a50;
    //疑惑：为什么 VDSO 常量数据大小被设置为 0x78？
    const VDSO_DATA_CONSTANTS_SIZE: usize = 0x78;
    //kernel_hal::vdso::vdso_constants() 返回了一个包含 VDSO 常量数据的结构体。
    //通过 transmute 将这个结构体转换成一个字节数组（[u8; VDSO_DATA_CONSTANTS_SIZE]），这样可以直接操作这些数据。
    let constants: [u8; VDSO_DATA_CONSTANTS_SIZE] =
        unsafe { core::mem::transmute(kernel_hal::vdso::vdso_constants()) };
    //然后将这些常量数据写入 vdso_vmo 对象的指定位置（VDSO_DATA_CONSTANTS 处）。
    //这样就把内核中的vdso相关数据写入预定路径对应的vdso里了！得到了完整了vdso_vmo
    vdso_vmo.write(VDSO_DATA_CONSTANTS, &constants).unwrap();
    vdso_vmo.set_name("vdso/full"); //full意为这里是完整的源vdso镜像
    //create_child 方法用于创建一个 VMO 的“子视图”，允许不同的进程或线程使用这些子 VMO 以不同的方式访问同一片内存。
    let vdso_test1 = vdso_vmo.create_child(false, 0, vdso_vmo.len()).unwrap();
    vdso_test1.set_name("vdso/test1");
    let vdso_test2 = vdso_vmo.create_child(false, 0, vdso_vmo.len()).unwrap();
    vdso_test2.set_name("vdso/test2");
    //为完整的vdso和他的孩子们创建handles
    handles[K_FIRSTVDSO] = Handle::new(vdso_vmo, Rights::DEFAULT_VMO | Rights::EXECUTE);
    handles[K_FIRSTVDSO + 1] = Handle::new(vdso_test1, Rights::DEFAULT_VMO | Rights::EXECUTE);
    handles[K_FIRSTVDSO + 2] = Handle::new(vdso_test2, Rights::DEFAULT_VMO | Rights::EXECUTE);

    // TODO: use correct CrashLogVmo handle
    //这里的log_vmo只是个虚有其表的对象，他虽然被分配了一页，但里面什么也没有写入
    //是一个空的vmo，可以理解为一个“占位符，留着以后todo
    let crash_log_vmo = VmObject::new_paged(1);
    crash_log_vmo.set_name("crashlog");
    handles[K_CRASHLOG] = Handle::new(crash_log_vmo, Rights::DEFAULT_VMO);

    // 表示kcounter的描述符表和内存池对应的vmo在handles中的索引
    let (desc_vmo, arena_vmo) = kcounter_vmos(); //Z报错！这里报错，许多kcounters中的符号未定义
    handles[K_COUNTER_NAMES] = Handle::new(desc_vmo, Rights::DEFAULT_VMO);
    handles[K_COUNTERS] = Handle::new(arena_vmo, Rights::DEFAULT_VMO);

    // TODO: use correct Instrumentation data handle
    //同理，也是“占位符”将来可能会用于仪器数据的handles索引,这个甚至连一页都没分配（
    let instrumentation_data_vmo = VmObject::new_paged(0);
    instrumentation_data_vmo.set_name("UNIMPLEMENTED_VMO");
    handles[K_FISTINSTRUMENTATIONDATA] =
        Handle::new(instrumentation_data_vmo.clone(), Rights::DEFAULT_VMO);
    handles[K_FISTINSTRUMENTATIONDATA + 1] =
        Handle::new(instrumentation_data_vmo.clone(), Rights::DEFAULT_VMO);
    handles[K_FISTINSTRUMENTATIONDATA + 2] =
        Handle::new(instrumentation_data_vmo.clone(), Rights::DEFAULT_VMO);
    handles[K_FISTINSTRUMENTATIONDATA + 3] =
        Handle::new(instrumentation_data_vmo, Rights::DEFAULT_VMO);
       
    // check: handle to root proc should be only
    let data = Vec::from(cmdline.replace(':', "\0") + "\0");//构建命令行数据，这里做的替换和添加可能是为了迎合接收C风格字符串作为参数的函数
    let msg = MessagePacket { data, handles }; //把数据和句柄打包成数据包
    //用kernel_channel传递数据包到user_channel，在zCore中这个过程我记得是通过查询kernel_channel的peel找到user_channel，然后在user_channel的recv_queue中写入这个数据
    kernel_channel.write(msg).unwrap(); 
    //引用之前创建的thread,用proc来start一个实际的线程,从之前计算好的userboot程序的入口点entry开始执行，
    //并传递之前创建好的，引用了user_channel且拥有默认channel权限的handle，用来接受kernel_channel传递的数据。
    //这里的thread_fn是一个函数指针，（在 Rust 中，可以直接将函数名作为参数传入，实际上这就是函数指针的使用。）
    //这个thread_fn返回一个被pin包装的，固定内存的future，start还把这个future传递给“异步运行时”来管理。

    //疑惑：这里start会怎么处理thread_fn返回的run_user的future？不管怎么说，都是从entry开始，然而userboot中的代码我看不见，或许会在其中某个合适的位置进行回调函数的调用吧。
    //解答：run_user完成了上下文设置，用户态切换，异常处理等工作，推测此回调函数会在userboot运行前执行。
    //不过，这里就体现出回调函数的作用了，不管传入的是什么样的userboot程序,都可以让它通过函数指针来调用这个异步函数，减少了代码耦合，支持异步操作，提高了复用率。
    //疑惑：一路追溯下去会发现这里用到了async-std的spawn来创建任务，然而async-std应当是“开发环境”才能使用的库，为什么在生产环境也能使用？
    proc.start(&thread, entry, sp, Some(handle), 0, thread_fn)
        .expect("failed to start main thread");
    proc
}

kcounter!(EXCEPTIONS_USER, "exceptions.user");
kcounter!(EXCEPTIONS_IRQ, "exceptions.irq");
kcounter!(EXCEPTIONS_PGFAULT, "exceptions.pgfault");
//解析一下这个回调函数吧
//thread_fn 的主要目的是将run-user封装为一个可以安全固定在内存中的异步任务，以供操作系统调度和管理。
//Pin<Box<dyn Future<Output = ()> + Send + 'static>>：这是一个被固定在内存中的 Box，其中装有一个实现了 Future 特性的对象。
//这个 Future 是异步的，它最终不会返回任何值（Output = ()），且可以在线程之间安全传递（Send），并且它的生命周期是 'static，这意味着它可以在整个程序生命周期内有效。
fn thread_fn(thread: CurrentThread) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
    //调用了 run_user(thread) 函数，并用 Box::pin 将其包装成 Pin<Box<...>>，返回给调用者。 
    //Box::pin 是用来创建一个固定内存位置的 Box，这在使用 Future 这样的异步对象时是必要的。
    //run_user是接下来的一个异步函数，会返回一个future。
    Box::pin(run_user(thread))
}

///根据他的功能，推测其会在userboot之前运行，上下文设置，用户态切换，异常处理等工作由它来完成。
async fn run_user(thread: CurrentThread) {
    //利用当前线程的inner来设置CURRENT_THREAD这个TLS变量，提供了一个更灵活和统一的方式来管理和访问线程的上下文信息（如TID和PID）
    kernel_hal::thread::set_current_thread(Some(thread.inner()));
    //如果当前线程是进程的第一个线程，处理 ProcessStarting 异常。这个操作是异步的，意味着线程在等待 handle_exception 完成时可以继续执行其他任务
    if thread.is_first_thread() {
        thread
            .handle_exception(ExceptionType::ProcessStarting)
            .await;
    };
    //处理 ThreadStarting 异常
    thread.handle_exception(ExceptionType::ThreadStarting).await;
    //进入循环，。
    loop {
        // wait，不断等待线程运行。当线程处于 Dying 状态时，退出循环。wait_for_run() 是一个异步操作，挂起当前线程的执行，直到线程准备好运行
        let mut ctx = thread.wait_for_run().await; //ctx是context，上下文的意思
        if thread.state() == ThreadState::Dying {
            break;
        }

        // run，线程被调度器选中后，准备真正执行用户态代码的阶段
        //这是一个调试信息，使用 trace! 宏来记录进入用户态代码执行的时刻。
        //ctx 是线程的上下文信息，包含寄存器状态等。这些信息被打印出来，便于后续调试和日志记录。
        trace!("go to user: {:#x?}", ctx);
        //这是另一条调试信息，使用 debug! 宏记录线程切换的时刻。
        //thread.proc().name() 返回的是当前线程所属进程的名称。
        //thread.name() 返回的是当前线程的名称。
        //这条日志信息在系统中切换到某个线程执行时生成，便于跟踪哪个进程和线程在当前运行。
        debug!("switch to {}|{}", thread.proc().name(), thread.name());
        let tmp_time = kernel_hal::timer::timer_now().as_nanos();

        // * Attention
        // The code will enter a magic zone from here.
        // `enter_uspace` will be executed into a wrapped library where context switching takes place.
        // The details are available in the `trapframe` crate on crates.io.

        //代码即将进入一个一个非常重要且敏感的区域。这个区域涉及到上下文切换（context switching），具体的实现是在一个叫 trapframe 的库中。
        //trapframe 是一个与处理器架构相关的库，负责处理陷入和切换用户态与内核态之间的上下文。可以在 crates.io 上找到它的实现细节。

        //enter_uspace() 方法是关键，它负责将当前的 CPU 上下文切换到用户态，也就是线程的用户代码将从这里开始执行。
        //当前的线程上下文（包括CPU寄存器状态、程序计数器等）将被加载到 CPU 中，执行流将从内核态切换到用户态，开始执行用户代码。
        ctx.enter_uspace();

        // Back from the userspace
        //这行代码计算从进入用户空间到返回内核空间所经过的时间。tmp_time 是进入用户空间前的时间戳，
        //通过当前时间减去 tmp_time 来获取执行的时间。这通常用于性能监测或统计线程的执行时间。
        let time = kernel_hal::timer::timer_now().as_nanos() - tmp_time;
        //这行代码将计算出的执行时间添加到线程的累计运行时间中。这有助于跟踪线程的实际运行时间，对于调度和性能分析都很重要。
        thread.time_add(time);
        //这行代码记录从用户空间返回后的日志，通常用于调试和追踪。ctx 是线程上下文，记录该信息有助于了解线程的状态。
        trace!("back from user: {:#x?}", ctx);
        //这行代码将 EXCEPTIONS_USER 计数器加 1。这个计数器可能用于跟踪异常处理的次数或其他相关的统计信息。
        EXCEPTIONS_USER.add(1);

        // handle trap/interrupt/syscall
        //handler_user_trap 是一个异步函数，用于处理用户态程序执行期间的异常情况，如陷阱（trap）、中断（interrupt）或系统调用（syscall）。
        if let Err(e) = handler_user_trap(&thread, ctx).await {
            if let ExceptionType::ThreadExiting = e {
                break;
            }
            //对于其他类型的异常，调用 thread.handle_exception(e).await 来处理。这个方法可能会执行一些必要的清理工作、记录日志或其他操作，以处理当前线程的异常情况。
            thread.handle_exception(e).await;
        }
    }
    thread.handle_exception(ExceptionType::ThreadExiting).await;
}

/// handler_user_trap 异步函数处理用户态陷阱（trap），包括系统调用、页面错误、以及各种异常。
async fn handler_user_trap(
    thread: &CurrentThread,
    mut ctx: Box<UserContext>,
) -> Result<(), ExceptionType> {
    let reason = ctx.trap_reason();
//如果是因为syscall而陷入内核态，提取系统调用号和参数，处理系统调用，并将返回值设置到用户上下文中
    if let TrapReason::Syscall = reason {
        let num = syscall_num(&ctx);
        let args = syscall_args(&ctx);
        ctx.advance_pc(reason);
        thread.put_context(ctx);
        let mut syscall = zircon_syscall::Syscall { thread, thread_fn };
        //调用 syscall.syscall(num as u32, args).await 来执行系统调用，这可能会涉及等待操作（如 I/O 操作）。
        let ret = syscall.syscall(num as u32, args).await as usize;
        //更新用户上下文的返回值，并恢复处理流程。
        thread
            .with_context(|ctx| ctx.set_field(UserContextField::ReturnValue, ret))
            .map_err(|_| ExceptionType::ThreadExiting)?;
        return Ok(());
    }

    thread.put_context(ctx);//将线程的上下文（ctx）保存回线程结构体中
    match reason {
        //中断处理
        TrapReason::Interrupt(vector) => {
            EXCEPTIONS_IRQ.add(1); // FIXME
            kernel_hal::interrupt::handle_irq(vector);
            kernel_hal::thread::yield_now().await;
            Ok(())
        }
        //页面错误（缺页异常）
        TrapReason::PageFault(vaddr, flags) => {
            EXCEPTIONS_PGFAULT.add(1);
            info!("page fault from user mode @ {:#x}({:?})", vaddr, flags);
            let vmar = thread.proc().vmar();
            vmar.handle_page_fault(vaddr, flags).map_err(|err| {
                error!(
                    "failed to handle page fault from user mode @ {:#x}({:?}): {:?}\n{:#x?}",
                    vaddr,
                    flags,
                    err,
                    thread.context_cloned()
                );
                ExceptionType::FatalPageFault
            })
        }
        //未定义仪器
        TrapReason::UndefinedInstruction => Err(ExceptionType::UndefinedInstruction),
        //软件断点
        TrapReason::SoftwareBreakpoint => Err(ExceptionType::SoftwareBreakpoint),
        //硬件断点
        TrapReason::HardwareBreakpoint => Err(ExceptionType::HardwareBreakpoint),
        //访问未对齐地址
        TrapReason::UnalignedAccess => Err(ExceptionType::UnalignedAccess),
        //通用错误类型（用来全匹配，防止有其他错误）
        TrapReason::GernelFault(_) => Err(ExceptionType::General),
        _ => unreachable!(),
    }
}

//最后俩函数是为不同架构的系统调用机制提供支持的。
//它们通过检查目标架构（例如 x86_64、aarch64、riscv64）来提取相应的系统调用编号和参数。
//这种设计使得代码能够在多种架构上运行，而无需修改核心逻辑。
//提取系统调用号
fn syscall_num(ctx: &UserContext) -> usize {
    let regs = ctx.general();
    cfg_if! {
        if #[cfg(target_arch = "x86_64")] {
            regs.rax
        } else if #[cfg(target_arch = "aarch64")] {
            regs.x16
        } else if #[cfg(target_arch = "riscv64")] {
            regs.a7
        } else {
            unimplemented!()
        }
    }
}
///提取系统调用参数
fn syscall_args(ctx: &UserContext) -> [usize; 8] {
    let regs = ctx.general();
    cfg_if! {
        if #[cfg(target_arch = "x86_64")] {
            if cfg!(feature = "libos") {
                let arg7 = unsafe{ (regs.rsp as *const usize).read() };
                let arg8 = unsafe{ (regs.rsp as *const usize).add(1).read() };
                [regs.rdi, regs.rsi, regs.rdx, regs.rcx, regs.r8, regs.r9, arg7, arg8]
            } else {
                [regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9, regs.r12, regs.r13]
            }
        } else if #[cfg(target_arch = "aarch64")] {
            [regs.x0, regs.x1, regs.x2, regs.x3, regs.x4, regs.x5, regs.x6, regs.x7]
        } else if #[cfg(target_arch = "riscv64")] {
            [regs.a0, regs.a1, regs.a2, regs.a3, regs.a4, regs.a5, regs.a6, regs.a7]
        } else {
            unimplemented!()
        }
    }
}
