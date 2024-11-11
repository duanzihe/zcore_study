//! Thread spawning.

use alloc::sync::Arc;
use async_std::task_local;
use core::{any::Any, cell::RefCell, future::Future};

task_local! {
    static CURRENT_THREAD: RefCell<Option<Arc<dyn Any + Send + Sync>>> = RefCell::new(None);
}

hal_fn_impl! {
    impl mod crate::hal_fn::thread {
       
        fn spawn(future: impl Future<Output = ()> + Send + 'static) {
            //疑惑：为什么在这部分也可以用开发环境的async_std库？
            //解惑，这里是kernel-hal，在开发早期处于“宿主操作系统”提供的环境时，可以利用HAL与之交互，
            //而宿主z擦偶偶系统是有std的，所以可以用async_std库
            
            //这里其实就是将异步任务的创建（如 spawn 函数）委托给 async-std 的异步运行时
            //spawn 函数接受一个实现了 Future 特性的对象，并在异步运行时中安排它的执行。
            async_std::task::spawn(future); 
        }
        //将当前线程的上下文信息（如 tid 和 pid）设置到线程局部存储中。这有助于在执行任务时维护和管理线程的状态，以便在需要时可以正确地恢复或切换线程上下文。
        fn set_current_thread(thread: Option<Arc<dyn Any + Send + Sync>>) {
            CURRENT_THREAD.with(|t| *t.borrow_mut() = thread);
        }

        fn get_current_thread() -> Option<Arc<dyn Any + Send + Sync>> {
            CURRENT_THREAD.try_with(|t| {
                t.borrow().as_ref().cloned()
            }).unwrap_or(None)
        }
    }
}
