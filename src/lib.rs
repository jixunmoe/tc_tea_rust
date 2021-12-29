//! _Tencent modified TEA_ (tc_tea) is a variant of the standard TEA (Tiny Encryption Algorithm).
//!
//! Notably, it uses a different round number and uses a "tweaked" CBC mode.

mod stream_ext;
mod tc_tea_public;
mod tc_tea_internal;
mod tc_tea_cbc;

pub use tc_tea_public::*;
