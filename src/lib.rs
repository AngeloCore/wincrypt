#![deny(clippy::all)]

use napi::bindgen_prelude::*;
use napi_derive::napi;
use std::ptr::{null, null_mut};
use winapi::{
    shared::minwindef::DWORD,
    um::{
        dpapi::{CryptProtectData, CryptUnprotectData, CRYPTPROTECT_LOCAL_MACHINE},
        wincrypt::DATA_BLOB,
    },
};

struct Output {
    success: i32,
    data: Vec<u8>,
}

#[napi(string_enum)]
pub enum Flags {
    CurrentUser,
    LocalMachine,
}

#[napi]
pub fn protect_data(
    mut data: Buffer,
    optional_entropy: Option<Buffer>,
    flags: Option<Flags>,
) -> Result<Buffer> {
    let mut data_in = DATA_BLOB {
        cbData: data.len() as u32,
        pbData: data.as_mut_ptr(),
    };

    let mut data_out = DATA_BLOB {
        cbData: 0,
        pbData: null_mut(),
    };

    let mut entropy = match optional_entropy {
        Some(mut e) => DATA_BLOB {
            cbData: e.len() as u32,
            pbData: e.as_mut_ptr(),
        },
        None => DATA_BLOB {
            cbData: 0,
            pbData: std::ptr::null_mut(),
        },
    };

    let dw_flags: DWORD = match flags {
        Some(Flags::LocalMachine) => CRYPTPROTECT_LOCAL_MACHINE,
        _ => 0,
    };

    let output = unsafe {
        let success = CryptProtectData(
            &mut data_in,
            null(),
            &mut entropy,
            null_mut(),
            null_mut(),
            dw_flags,
            &mut data_out,
        );

        Output {
            success,
            data: Vec::from_raw_parts(
                data_out.pbData,
                data_out.cbData as usize,
                data_out.cbData as usize,
            ),
        }
    };

    if output.success != 0 {
        Ok(Buffer::from(output.data))
    } else {
        let error_message = std::io::Error::last_os_error().to_string();
        let error = Error::new(napi::Status::Unknown, error_message);

        Err(error)
    }
}

#[napi]
pub fn unprotect_data(
    mut data: Buffer,
    optional_entropy: Option<Buffer>,
    flags: Option<Flags>,
) -> Result<Buffer> {
    let mut data_in = DATA_BLOB {
        cbData: data.len() as u32,
        pbData: data.as_mut_ptr(),
    };

    let mut data_out = DATA_BLOB {
        cbData: 0,
        pbData: null_mut(),
    };

    let mut entropy = match optional_entropy {
        Some(mut e) => DATA_BLOB {
            cbData: e.len() as u32,
            pbData: e.as_mut_ptr(),
        },
        None => DATA_BLOB {
            cbData: 0,
            pbData: std::ptr::null_mut(),
        },
    };

    let dw_flags: DWORD = match flags {
        Some(Flags::LocalMachine) => CRYPTPROTECT_LOCAL_MACHINE,
        _ => 0,
    };

    let output = unsafe {
        let success = CryptUnprotectData(
            &mut data_in,
            null_mut(),
            &mut entropy,
            null_mut(),
            null_mut(),
            dw_flags,
            &mut data_out,
        );

        Output {
            success,
            data: Vec::from_raw_parts(
                data_out.pbData,
                data_out.cbData as usize,
                data_out.cbData as usize,
            ),
        }
    };

    if output.success != 0 {
        Ok(Buffer::from(output.data))
    } else {
        let error_message = std::io::Error::last_os_error().to_string();
        let error = Error::new(napi::Status::Unknown, error_message);

        Err(error)
    }
}
