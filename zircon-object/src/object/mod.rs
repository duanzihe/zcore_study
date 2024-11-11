//! Kernel object basis.
//!
//! # Create new kernel object
//! 创建一个新的内核对象类型
//! - Create a new struct.
//! - Make sure it has a field named `base` with type [`KObjectBase`].
//! - Implement [`KernelObject`] trait with [`impl_kobject`] macro.
//!
//! ## Example
//! ```
//! use zircon_object::object::*;
//! extern crate alloc;
//!
//! pub struct SampleObject {
//!    base: KObjectBase,
//! }
//! impl_kobject!(SampleObject);
//! ```
//!
//! # Implement methods for kernel object
//! 为这个内核对象实现方法
//! ## Constructor
//!
//! Each kernel object should have a constructor returns `Arc<Self>`
//! (or a pair of them, e.g. [`Channel`]).
//! 每个内核对象都应该有一个返回Arc<Self>的构造函数，之所以用Arc（原子引用计数）是因为内核对象常常在多个所有者之间共享。
//! Don't return `Self` since it must be created on heap.
//! 不要返回self,返回self可能会将对象保存在栈上，超出作用域就销毁了，构造内核对象必须在堆上！
//! ### Example
//! ```
//! use zircon_object::object::*;
//! use std::sync::Arc;
//!
//! pub struct SampleObject {
//!     base: KObjectBase,
//! }
//! impl SampleObject {
//!     pub fn new() -> Arc<Self> {
//!         Arc::new(SampleObject {
//!             base: KObjectBase::new(),
//!         })
//!     }
//! }
//! ```
//!
//! ## Interior mutability
//! 用inner实现内部可变性，以保护其他不该修改的成员。
//! 
//! All kernel objects use the [interior mutability pattern] :
//! each method takes either `&self` or `&Arc<Self>` as the first argument.
//!
//! To handle mutable variable, create another **inner structure**,
//! and put it into the object with a lock wrapped.
//!
//! ### Example
//! ```
//! use zircon_object::object::*;
//! use std::sync::Arc;
//! use lock::Mutex;
//!
//! pub struct SampleObject {
//!     base: KObjectBase,
//!     inner: Mutex<SampleObjectInner>,
//! }
//! struct SampleObjectInner {
//!     x: usize,
//! }
//!
//! impl SampleObject {
//!     pub fn set_x(&self, x: usize) {
//!         let mut inner = self.inner.lock();
//!         inner.x = x;
//!     }
//! }
//! ```
//!
//! # Downcast trait to concrete type
//! 将一个泛型或 trait 对象转换（向下转换）为它的具体类型（concrete type）的过程。
//! [`KernelObject`] inherit [`downcast_rs::DowncastSync`] trait.
//! You can use `downcast_arc` method to downcast `Arc<dyn KernelObject>` to `Arc<T: KernelObject>`.
//! 可以用downcast_arc方法把一个“实现了kernelobject特性”类型转换成具体的T类型。
//! ## Example
//! ```
//! use zircon_object::object::*;
//! use std::sync::Arc;
//!
//! let object: Arc<dyn KernelObject> = DummyObject::new();
//! let concrete = object.downcast_arc::<DummyObject>().unwrap();
//! ```
//!
//! [`Channel`]: crate::ipc::Channel
//! [`KObjectBase`]: KObjectBase
//! [`KernelObject`]: KernelObject
//! [`impl_kobject`]: impl_kobject
//! [`downcast_rs::DowncastSync`]: downcast_rs::DowncastSync
//! [interior mutability pattern]: https://doc.rust-lang.org/reference/interior-mutability.html

use {
    crate::signal::*,
    alloc::{boxed::Box, string::String, sync::Arc, vec::Vec},
    core::{
        fmt::Debug,
        future::Future,
        pin::Pin,
        sync::atomic::*,
        task::{Context, Poll},
    },
    downcast_rs::{impl_downcast, DowncastSync},
    lock::Mutex,
};

pub use {super::*, handle::*, rights::*, signal::*};

mod handle;
mod rights;
mod signal;

/// Common interface of a kernel object.
/// 通用的内核对象接口 KernelObject
/// Implemented by [`impl_kobject`] macro.
/// 通过impl_kobject这个宏来按照一定规则生成
/// [`impl_kobject`]: impl_kobject
pub trait KernelObject: DowncastSync + Debug {
    /// Get object's KoID.
    /// 获取内核对象的ID
    fn id(&self) -> KoID;
    /// Get the name of the type of the kernel object.
    /// 获取内核对象类型的名字
    fn type_name(&self) -> &str;
    /// Get object's name.
    /// 获取内核对象本身的名字
    fn name(&self) -> alloc::string::String;
    /// Set object's name.
    /// 设置内核对象的名字
    fn set_name(&self, name: &str);
    /// Get the signal status.
    /// 获取signal状态
    fn signal(&self) -> Signal;
    /// Assert `signal`.
    /// 设置signal
    fn signal_set(&self, signal: Signal);
    /// Deassert `signal`.
    /// 清除signal状态
    fn signal_clear(&self, signal: Signal);
    /// Change signal status: first `clear` then `set` indicated bits.
    ///先清除由 clear 参数指定的信号位，然后设置由 set 参数指定的信号位
    /// All signal callbacks will be called.
    /// 所有的signal callbacks都会被回调。
    fn signal_change(&self, clear: Signal, set: Signal);
    /// Add `callback` for signal status changes.
    ///为信号状态的变化添加一个回调函数。这个回调函数会在信号状态发生变化时被调用。
    /// 
    /// The `callback` is a function of `Fn(Signal) -> bool`.
    /// It returns a bool indicating whether the handle process is over.
    /// 回调函数的返回值是一个布尔值，用于指示是否处理过程已经结束
    /// 
    /// If true, the function will never be called again.
    /// 如果返回true,说明处理完了，那么这个函数就不会再被调用了。
    fn add_signal_callback(&self, callback: SignalHandler);
    /// Attempt to find a child of the object with given KoID.
    /// 尝试查找具有指定 KoID 的子对象
    /// 
    /// If the object is a *Process*, the *Threads* it contains may be obtained.
    /// 如果调用该方法的对象是一个进程（Process），那么可以获取到它包含的线程（Threads）。这意味着 get_child 方法可以用来查找属于某个特定进程的线程。
    /// 
    /// If the object is a *Job*, its (immediate) child *Jobs* and the *Processes*
    /// it contains may be obtained.
    ///如果调用该方法的对象是一个作业（Job），则可以获取到它的（直接）子作业（Jobs）和它包含的进程（Processes）。
    /// 这表明 get_child 方法不仅可以查找子作业，还可以查找属于某个作业的进程。
    /// 
    /// If the object is a *Resource*, its (immediate) child *Resources* may be obtained.
    /// 如果调用该方法的对象是一个资源（Resource），则可以获取到它的（直接）子资源（Resources）。
    /// 这意味着 get_child 方法可以用来查找某个资源下的其他资源。
    fn get_child(&self, _id: KoID) -> ZxResult<Arc<dyn KernelObject>> {
        Err(ZxError::WRONG_TYPE)
    }
    /// Attempt to get the object's peer.
    /// 尝试获取对象的对端
    /// 
    /// An object peer is the opposite endpoint of a `Channel`, `Socket`, `Fifo`, or `EventPair`.
    /// 对端是这些对象类型中的另一端点
    /// 
    fn peer(&self) -> ZxResult<Arc<dyn KernelObject>> {
        Err(ZxError::NOT_SUPPORTED)  //这个功能暂不支持
    }
    /// If the object is related to another (such as the other end of a channel, or the parent of
    /// a job), returns the KoID of that object, otherwise returns zero.
    /// 返回与当前对象相关的另一个对象的 KoID（Kernel Object ID）
    fn related_koid(&self) -> KoID {
        0   //这个功能未实装，直接返回0了
    }
    /// Get object's allowed signals.
    /// 接受这个对象允许的信号（注意，允许不是激活！）
    fn allowed_signals(&self) -> Signal {
        Signal::USER_ALL
    }
}
//为线程安全的kernelobject这个trait实现线程安全的向下转换”
// 这里的sync不是显得很奇怪吗？
// 如果kernelobject本身是sync的，就没必要写他， Rust 的类型系统会自动确保任何实现了 Sync trait 的类型在多线程中是安全的。
//如果不是，即使使用 sync 标志来生成线程安全的向下转换代码也没有实际意义，因为该类型本身并不满足线程安全的要求，也没必要写它啊？
// 可能是为了明确要求用宏生成的代码是“线程安全”的吧。  
impl_downcast!(sync KernelObject);

/// The base struct of a kernel object.
/// 这儿可以理解是”基类“
/// 
/// KObjectBase的方法：
/// 
/// 创建默认实例，创建实例并初始化其siganl，创建实例并初始化其name,创建实例并初始化name和signal；
/// 生成koid,获取或设置name，获取或设置signal，添加信号回调函数等等
pub struct KObjectBase {
    /// The object's KoID.
    pub id: KoID,
    inner: Mutex<KObjectBaseInner>,
}

/// The mutable part of `KObjectBase`.
/// 这儿是”基类“中的”内部可变“部分，其中包含了name,signal,signal_call
#[derive(Default)]
struct KObjectBaseInner {
    name: String,
    signal: Signal,
    signal_callbacks: Vec<SignalHandler>,
}

///为其实现default trait以创建默认实例
impl Default for KObjectBase {
    fn default() -> Self {
        KObjectBase {
            id: Self::new_koid(),
            inner: Default::default(),
        }
    }
}
///基类方法的具体实现
impl KObjectBase {
    /// Create a new kernel object base.
    /// 创建一个默认的基类实例
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a kernel object base with initial `signal`.
    /// 创建一个基类，并初始化signal
    pub fn with_signal(signal: Signal) -> Self {
        KObjectBase::with(Default::default(), signal)
    }

    /// Create a kernel object base with `name`.
    /// 创建一个实例，并初始化name
    pub fn with_name(name: &str) -> Self {
        KObjectBase::with(name, Default::default())
    }

    /// Create a kernel object base with both signal and name
    /// 创建一个实例，并初始化name和signal
    pub fn with(name: &str, signal: Signal) -> Self {
        KObjectBase {
            id: Self::new_koid(),
            inner: Mutex::new(KObjectBaseInner {
                name: String::from(name),
                signal,
                ..Default::default()
            }),
        }
    }

    /// Generate a new KoID.
    /// 生成一个新KOID
    fn new_koid() -> KoID {
        static KOID: AtomicU64 = AtomicU64::new(1024);
        KOID.fetch_add(1, Ordering::SeqCst)
    }

    /// Get object's name.
    /// 获取对象名字
    pub fn name(&self) -> String {
        self.inner.lock().name.clone()
    }

    /// Set object's name.
    /// 设置对象名
    pub fn set_name(&self, name: &str) {
        self.inner.lock().name = String::from(name);
    }

    /// Get the signal status.
    /// 获取信号状态
    pub fn signal(&self) -> Signal {
        self.inner.lock().signal
    }

    /// Change signal status: first `clear` then `set` indicated bits.
    ///
    /// All signal callbacks will be called.
    /// 
    /// 修改信号的状态，首先清除指定的信号位（clear），然后设置指定的信号位。
    /// 然后它会触发所有与信号相关的回调函数，并根据回调的返回值决定是否保留该回调。
    pub fn signal_change(&self, clear: Signal, set: Signal) {
        let mut inner = self.inner.lock();
        let old_signal = inner.signal;
        inner.signal.remove(clear);
        inner.signal.insert(set);
        let new_signal = inner.signal;
        if new_signal == old_signal {
            return;
        }
        inner.signal_callbacks.retain(|f| !f(new_signal));
    }

    /// Assert `signal`.
    /// 设置信号
    pub fn signal_set(&self, signal: Signal) {
        self.signal_change(Signal::empty(), signal);
    }

    /// Deassert `signal`.
    /// 清空信号
    pub fn signal_clear(&self, signal: Signal) {
        self.signal_change(signal, Signal::empty());
    }

    /// Add `callback` for signal status changes.
    ///
    /// The `callback` is a function of `Fn(Signal) -> bool`.
    /// It returns a bool indicating whether the handle process is over.
    /// If true, the function will never be called again.
    /// 
    /// 为内核对象添加”在信号改变时触发的回调函数“
    /// 其中调用的callbcak会返回一个bool,如果回调函数处理完了就返回true,如果没处理或者没处理完就返回false
    /// 在这里添加回调的时候就会立刻尝试执行一次，防止在注册等待锁的时候”错过信号“
    pub fn add_signal_callback(&self, callback: SignalHandler) {
        let mut inner = self.inner.lock();
        // Check the callback immediately, in case that a signal arrives just before the call of
        // `add_signal_callback` (since lock is acquired inside it) and the callback is not triggered
        // in time.
        //“立即检查回调”的逻辑是为了防止竞态条件。因为需要连续完成：inner锁的获取，立即检查当前的信号状态，注册相应的回调，这三个动作是”连续“的，需要保证期间signal不会改变。
        //而因为锁是在函数内部获取的，有可能在调用 add_signal_callback 等待获取锁的时候，信号已经发生了变化。
        //然而，这个时候add_siganl_callback还没有获取锁，没法完成回调函数的注册，自然也就没法执行。
        //
        //如果callback(inner.signal)返回true,说明在注册等待锁的过程中，当前信号状态发生了改变，并且回调函数已经被处理完了，这样就不需要再注册回调，也就不需要将其push到回调队列中了。
        //如果在注册过程中，信号发生了改变，callback执行了回调函数，但没执行完，导致返回了false，会把回调函数push到回调队列中，等到下次信号变化继续执行；
        //或者在注册过程中，信号压根没改变，也会返回false,那就把回调函数push到回调队列中，等到未来信号变化了再执行
        if !callback(inner.signal) {
            inner.signal_callbacks.push(callback);
        }
    }
}
//为kernelobjecth这个trait实现支持运行时确认动态分发的方法。
impl dyn KernelObject {
    /// Asynchronous wait for one of `signal`.
    /// 定义了一个异步等待信号的功能，并实现了一个自定义的 Future。
    /// 返回值是一个实现了 Future trait 的类型，这个 Future 的 Output 是 Signal。方法的参数 self 是一个 Arc<Self>，表示 KernelObject 的一个引用，signal 是需要等待的信号。
    pub fn wait_signal(self: &Arc<Self>, signal: Signal) -> impl Future<Output = Signal> {
        #[must_use = "wait_signal does nothing unless polled/`await`-ed"]
        struct SignalFuture {
            object: Arc<dyn KernelObject>,
            signal: Signal,
            first: bool,
        }

        impl Future for SignalFuture {
            type Output = Signal;

            fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
                let current_signal = self.object.signal();
                if !(current_signal & self.signal).is_empty() {
                    return Poll::Ready(current_signal);
                }
                if self.first {
                    self.object.add_signal_callback(Box::new({
                        let signal = self.signal;
                        let waker = cx.waker().clone();
                        move |s| {
                            if (s & signal).is_empty() {
                                return false;
                            }
                            waker.wake_by_ref();
                            true
                        }
                    }));
                    self.first = false;
                }
                Poll::Pending
            }
        }

        SignalFuture {
            object: self.clone(),
            signal,
            first: true,
        }
    }

    /// Once one of the `signal` asserted, push a packet with `key` into the `port`,
    ///
    /// It's used to implement `sys_object_wait_async`.
    #[allow(unsafe_code)]
    pub fn send_signal_to_port_async(self: &Arc<Self>, signal: Signal, port: &Arc<Port>, key: u64) {
        let current_signal = self.signal();
        if !(current_signal & signal).is_empty() {
            port.push(PortPacketRepr {
                key,
                status: ZxError::OK,
                data: PayloadRepr::Signal(PacketSignal {
                    trigger: signal,
                    observed: current_signal,
                    count: 1,
                    timestamp: 0,
                    _reserved1: 0,
                }),
            });
            return;
        }
        self.add_signal_callback(Box::new({
            let port = port.clone();
            move |s| {
                if (s & signal).is_empty() {
                    return false;
                }
                port.push(PortPacketRepr {
                    key,
                    status: ZxError::OK,
                    data: PayloadRepr::Signal(PacketSignal {
                        trigger: signal,
                        observed: s,
                        count: 1,
                        timestamp: 0,
                        _reserved1: 0,
                    }),
                });
                true
            }
        }));
    }
}

/// Asynchronous wait signal for multiple objects.
pub fn wait_signal_many(
    targets: &[(Arc<dyn KernelObject>, Signal)],
) -> impl Future<Output = Vec<Signal>> {
    #[must_use = "wait_signal_many does nothing unless polled/`await`-ed"]
    struct SignalManyFuture {
        targets: Vec<(Arc<dyn KernelObject>, Signal)>,
        first: bool,
    }

    impl SignalManyFuture {
        fn happened(&self, current_signals: &[Signal]) -> bool {
            self.targets
                .iter()
                .zip(current_signals)
                .any(|(&(_, desired), &current)| !(current & desired).is_empty())
        }
    }

    impl Future for SignalManyFuture {
        type Output = Vec<Signal>;

        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            let current_signals: Vec<_> =
                self.targets.iter().map(|(obj, _)| obj.signal()).collect();
            if self.happened(&current_signals) {
                return Poll::Ready(current_signals);
            }
            if self.first {
                for (object, signal) in self.targets.iter() {
                    object.add_signal_callback(Box::new({
                        let signal = *signal;
                        let waker = cx.waker().clone();
                        move |s| {
                            if (s & signal).is_empty() {
                                return false;
                            }
                            waker.wake_by_ref();
                            true
                        }
                    }));
                }
                self.first = false;
            }
            Poll::Pending
        }
    }

    SignalManyFuture {
        targets: Vec::from(targets),
        first: true,
    }
}

/// Macro to auto implement `KernelObject` trait.
#[macro_export]
macro_rules! impl_kobject {
    ($class:ident $( $fn:tt )*) => {
        impl $crate::object::KernelObject for $class {
            fn id(&self) -> KoID {
                self.base.id
            }
            fn type_name(&self) -> &str {
                stringify!($class)
            }
            fn name(&self) -> alloc::string::String {
                self.base.name()
            }
            fn set_name(&self, name: &str){
                self.base.set_name(name)
            }
            fn signal(&self) -> Signal {
                self.base.signal()
            }
            fn signal_set(&self, signal: Signal) {
                self.base.signal_set(signal);
            }
            fn signal_clear(&self, signal: Signal) {
                self.base.signal_clear(signal);
            }
            fn signal_change(&self, clear: Signal, set: Signal) {
                self.base.signal_change(clear, set);
            }
            fn add_signal_callback(&self, callback: $crate::object::SignalHandler) {
                self.base.add_signal_callback(callback);
            }
            $( $fn )*
        }
        impl core::fmt::Debug for $class {
            fn fmt(
                &self,
                f: &mut core::fmt::Formatter<'_>,
            ) -> core::result::Result<(), core::fmt::Error> {
                use $crate::object::KernelObject;
                f.debug_tuple(&stringify!($class))
                    .field(&self.id())
                    .field(&self.name())
                    .finish()
            }
        }
    };
}

/// Define a pair of kcounter (create, destroy),
/// and a helper struct `CountHelper` which increases the counter on construction and drop.
#[macro_export]
macro_rules! define_count_helper {
    ($class:ident) => {
        struct CountHelper(());
        impl CountHelper {
            fn new() -> Self {

                $crate::kcounter!(CREATE_COUNT, concat!(stringify!($class), ".create"));

                CREATE_COUNT.add(1);//Z报错，页面错误

                CountHelper(())
            }
        }
        impl Drop for CountHelper {
            fn drop(&mut self) {
                $crate::kcounter!(DESTROY_COUNT, concat!(stringify!($class), ".destroy"));
                DESTROY_COUNT.add(1);
            }
        }
    };
}

/// The type of kernel object ID.
pub type KoID = u64;

/// The type of kernel object signal handler.
pub type SignalHandler = Box<dyn Fn(Signal) -> bool + Send>;

/// Empty kernel object. Just for test.
pub struct DummyObject {
    base: KObjectBase,
}

impl_kobject!(DummyObject);

impl DummyObject {
    /// Create a new `DummyObject`.
    pub fn new() -> Arc<Self> {
        Arc::new(DummyObject {
            base: KObjectBase::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_std::sync::Barrier;
    use std::time::Duration;

    #[async_std::test]
    async fn wait() {
        let object = DummyObject::new();
        let barrier = Arc::new(Barrier::new(2));
        async_std::task::spawn({
            let object = object.clone();
            let barrier = barrier.clone();
            async move {
                async_std::task::sleep(Duration::from_millis(20)).await;

                // Assert an irrelevant signal to test the `false` branch of the callback for `READABLE`.
                object.signal_set(Signal::USER_SIGNAL_0);
                object.signal_clear(Signal::USER_SIGNAL_0);
                object.signal_set(Signal::READABLE);
                barrier.wait().await;

                object.signal_set(Signal::WRITABLE);
            }
        });
        let object: Arc<dyn KernelObject> = object;

        let signal = object.wait_signal(Signal::READABLE).await;
        assert_eq!(signal, Signal::READABLE);
        barrier.wait().await;

        let signal = object.wait_signal(Signal::WRITABLE).await;
        assert_eq!(signal, Signal::READABLE | Signal::WRITABLE);
    }

    #[async_std::test]
    async fn wait_many() {
        let objs = [DummyObject::new(), DummyObject::new()];
        let barrier = Arc::new(Barrier::new(2));
        async_std::task::spawn({
            let objs = objs.clone();
            let barrier = barrier.clone();
            async move {
                async_std::task::sleep(Duration::from_millis(20)).await;

                objs[0].signal_set(Signal::READABLE);
                barrier.wait().await;

                objs[1].signal_set(Signal::WRITABLE);
            }
        });
        let obj0: Arc<dyn KernelObject> = objs[0].clone();
        let obj1: Arc<dyn KernelObject> = objs[1].clone();

        let signals = wait_signal_many(&[
            (obj0.clone(), Signal::READABLE),
            (obj1.clone(), Signal::READABLE),
        ])
        .await;
        assert_eq!(signals, [Signal::READABLE, Signal::empty()]);
        barrier.wait().await;

        let signals = wait_signal_many(&[
            (obj0.clone(), Signal::WRITABLE),
            (obj1.clone(), Signal::WRITABLE),
        ])
        .await;
        assert_eq!(signals, [Signal::READABLE, Signal::WRITABLE]);
    }

    #[test]
    fn test_trait_with_dummy() {
        let dummy = DummyObject::new();
        assert_eq!(dummy.name(), String::from(""));
        dummy.set_name("test");
        assert_eq!(dummy.name(), String::from("test"));
        dummy.signal_set(Signal::WRITABLE);
        assert_eq!(dummy.signal(), Signal::WRITABLE);
        dummy.signal_change(Signal::WRITABLE, Signal::READABLE);
        assert_eq!(dummy.signal(), Signal::READABLE);

        assert_eq!(dummy.get_child(0).unwrap_err(), ZxError::WRONG_TYPE);
        assert_eq!(dummy.peer().unwrap_err(), ZxError::NOT_SUPPORTED);
        assert_eq!(dummy.related_koid(), 0);
        assert_eq!(dummy.allowed_signals(), Signal::USER_ALL);

        assert_eq!(
            format!("{:?}", dummy),
            format!("DummyObject({}, \"test\")", dummy.id())
        );
    }
}
