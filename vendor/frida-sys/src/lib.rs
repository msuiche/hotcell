/*
 * Copyright © 2020-2022 Keegan Saunders
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(improper_ctypes)]

#[allow(clippy::all)]
mod bindings {
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

pub use bindings::*;

#[cfg(not(any(target_vendor = "apple", target_os = "windows")))]
pub use crate::{
    _frida_g_bytes_get_data as g_bytes_get_data, _frida_g_bytes_new as g_bytes_new,
    _frida_g_bytes_unref as g_bytes_unref, _frida_g_cancellable_cancel as g_cancellable_cancel,
    _frida_g_cancellable_new as g_cancellable_new, _frida_g_clear_object as g_clear_object,
    _frida_g_error_free as g_error_free, _frida_g_hash_table_iter_init as g_hash_table_iter_init,
    _frida_g_hash_table_iter_next as g_hash_table_iter_next,
    _frida_g_hash_table_size as g_hash_table_size, _frida_g_idle_source_new as g_idle_source_new,
    _frida_g_main_context_default as g_main_context_default,
    _frida_g_main_context_iteration as g_main_context_iteration,
    _frida_g_main_context_ref as g_main_context_ref,
    _frida_g_main_context_unref as g_main_context_unref, _frida_g_object_unref as g_object_unref,
    _frida_g_signal_connect_data as g_signal_connect_data,
    _frida_g_signal_handler_disconnect as g_signal_handler_disconnect,
    _frida_g_source_attach as g_source_attach,
    _frida_g_source_set_callback as g_source_set_callback, _frida_g_source_unref as g_source_unref,
    _frida_g_variant_get_boolean as g_variant_get_boolean,
    _frida_g_variant_get_int64 as g_variant_get_int64,
    _frida_g_variant_get_string as g_variant_get_string,
    _frida_g_variant_get_type_string as g_variant_get_type_string,
    _frida_g_variant_iter_init as g_variant_iter_init,
    _frida_g_variant_iter_loop as g_variant_iter_loop,
};
