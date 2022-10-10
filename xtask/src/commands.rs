﻿use std::{ffi::OsStr, path::Path};

macro_rules! fetch_online {
    ($dst:expr, $f:expr) => {{
        use os_xtask_utils::{dir, CommandExt};
        use std::{fs, path::PathBuf};

        dir::rm(&$dst).unwrap();
        let tmp: usize = rand::random();
        let tmp = PathBuf::from("/tmp").join(tmp.to_string());
        let mut ext = $f(tmp.clone());
        let status = ext.status();
        if status.success() {
            dir::create_parent(&$dst).unwrap();
            if tmp.is_dir() {
                dircpy::copy_dir(&tmp, &$dst).unwrap();
            } else {
                fs::copy(&tmp, &$dst).unwrap();
            }
            dir::rm(tmp).unwrap();
        } else {
            dir::rm(tmp).unwrap();
            panic!(
                "Failed with code {} from {:?}",
                status.code().unwrap(),
                ext.info()
            );
        }
    }};
}

pub(crate) use fetch_online;

pub(crate) fn wget(url: impl AsRef<OsStr>, dst: impl AsRef<Path>) {
    use os_xtask_utils::Ext;

    let dst = dst.as_ref();
    if dst.exists() {
        println!("{dst:?} already exist. You can delete it manually to re-download.");
        return;
    }

    println!("wget {} from {:?}", dst.display(), url.as_ref());
    fetch_online!(dst, |tmp| {
        let mut wget = Ext::new("wget");
        wget.arg(&url).arg("-O").arg(tmp);
        wget
    });
}
