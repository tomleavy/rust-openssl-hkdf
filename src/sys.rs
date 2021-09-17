use std::os::raw::c_int;
use openssl_sys::{EVP_PKEY_CTX, EVP_PKEY_CTX_ctrl, EVP_MD};
use std::ffi::c_void;
use core::ptr;

pub const EVP_PKEY_HKDF: c_int = 1036;
pub const EVP_PKEY_ALG_CTRL: c_int = 0x1000;
pub const EVP_PKEY_HKDEF_MODE_EXTRACT_AND_EXPAND: c_int = 0;
pub const EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY: c_int = 1;
pub const EVP_PKEY_HKDEF_MODE_EXPAND_ONLY: c_int = 2;
pub const EVP_PKEY_CTRL_HKDF_MD: c_int = EVP_PKEY_ALG_CTRL + 3;
pub const EVP_PKEY_CTRL_HKDF_SALT: c_int = EVP_PKEY_ALG_CTRL + 4;
pub const EVP_PKEY_CTRL_HKDF_KEY: c_int = EVP_PKEY_ALG_CTRL + 5;
pub const EVP_PKEY_CTRL_HKDF_INFO: c_int = EVP_PKEY_ALG_CTRL + 6;
pub const EVP_PKEY_CTRL_HKDF_MODE: c_int = EVP_PKEY_ALG_CTRL + 7;
pub const EVP_PKEY_OP_DERIVE: c_int = 1 << 10;

pub unsafe fn EVP_PKEY_CTX_hkdf_mode(ctx: *mut EVP_PKEY_CTX, mode: c_int) -> c_int {
    EVP_PKEY_CTX_ctrl(
        ctx,
        -1,
        EVP_PKEY_OP_DERIVE,
        EVP_PKEY_CTRL_HKDF_MODE,
        mode,
        ptr::null_mut(),
    )
}

pub unsafe fn EVP_PKEY_CTX_set_hkdf_md(ctx: *mut EVP_PKEY_CTX, md: *const EVP_MD) -> c_int {
    EVP_PKEY_CTX_ctrl(
        ctx,
        -1,
        EVP_PKEY_OP_DERIVE,
        EVP_PKEY_CTRL_HKDF_MD,
        0,
        md as *mut c_void,
    )
}

pub unsafe fn EVP_PKEY_CTX_set1_hkdf_salt(
    ctx: *mut EVP_PKEY_CTX,
    salt: *const u8,
    saltlen: c_int,
) -> c_int {
    EVP_PKEY_CTX_ctrl(
        ctx,
        -1,
        EVP_PKEY_OP_DERIVE,
        EVP_PKEY_CTRL_HKDF_SALT,
        saltlen,
        salt as *mut c_void,
    )
}

pub unsafe fn EVP_PKEY_CTX_set1_hkdf_key(
    ctx: *mut EVP_PKEY_CTX,
    key: *const u8,
    keylen: c_int,
) -> c_int {
    EVP_PKEY_CTX_ctrl(
        ctx,
        -1,
        EVP_PKEY_OP_DERIVE,
        EVP_PKEY_CTRL_HKDF_KEY,
        keylen,
        key as *mut c_void,
    )
}

pub unsafe fn EVP_PKEY_CTX_add1_hkdf_info(
    ctx: *mut EVP_PKEY_CTX,
    info: *const u8,
    infolen: c_int,
) -> c_int {
    EVP_PKEY_CTX_ctrl(
        ctx,
        -1,
        EVP_PKEY_OP_DERIVE,
        EVP_PKEY_CTRL_HKDF_INFO,
        infolen,
        info as *mut c_void,
    )
}