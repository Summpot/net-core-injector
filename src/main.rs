use std::ffi::{c_char, c_uint, c_void, CStr, CString};
use std::os::raw::c_int;

use libloading::{Library, Symbol};

#[derive(Debug, PartialEq, Eq)]
#[repr(u32)]
enum InitializeResult {
    Success,
    HostFxrLoadError,
    InitializeRuntimeConfigError,
    GetRuntimeDelegateError,
    EntryPointError,
}

// HostFxr and CoreCLR delegates
type HostfxrHandle = *mut c_void;
type HostfxrInitializeForRuntimeConfigFn =
    unsafe extern "C" fn(*const c_char, *const c_void, *mut HostfxrHandle) -> c_int;
type HostfxrGetRuntimeDelegateFn =
    unsafe extern "C" fn(HostfxrHandle, HostfxrDelegateType, *mut *mut c_void) -> c_int;
type HostfxrCloseFn = unsafe extern "C" fn(HostfxrHandle) -> c_int;
type LoadAssemblyAndGetFunctionPointerFn = unsafe extern "C" fn(
    *const c_char,
    *const c_char,
    *const c_char,
    c_uint,
    *const c_void,
    *mut *mut c_void,
) -> c_int;

#[repr(u32)]
enum HostfxrDelegateType {
    HdtLoadAssemblyAndGetFunctionPointer = 2,
}

const UNMANAGEDCALLERSONLY_METHOD: c_uint = 0;

#[no_mangle]
pub unsafe extern "C" fn bootstrapper_load_assembly(
    runtime_config_path: *const c_char,
    assembly_path: *const c_char,
    type_name: *const c_char,
    method_name: *const c_char,
) -> anyhow::Result<()> {
    #[cfg(windows)]
    let library_name = String::from("hostfxr.dll");
    #[cfg(unix)]
    let library_name = String::from("libhostfxr.so");
    let library = libloading::Library::new(library_name)?;

    let hostfxr_initialize_for_runtime_config_fptr: libloading::Symbol<
        HostfxrInitializeForRuntimeConfigFn,
    > = library.get(b"hostfxr_initialize_for_runtime_config")?;

    let hostfxr_get_runtime_delegate_fptr: libloading::Symbol<HostfxrGetRuntimeDelegateFn> =
        library.get(b"hostfxr_get_runtime_delegate")?;

    let hostfxr_close_fptr: libloading::Symbol<HostfxrCloseFn> = library.get(b"hostfxr_close")?;

    let mut ctx: HostfxrHandle = std::ptr::null_mut();
    let rc =
        hostfxr_initialize_for_runtime_config_fptr(runtime_config_path, std::ptr::null(), &mut ctx);

    if rc != 1 || ctx.is_null() {
        hostfxr_close_fptr(ctx);
        return InitializeResult::InitializeRuntimeConfigError;
    }

    let mut delegate: *mut c_void = std::ptr::null_mut();
    let ret = hostfxr_get_runtime_delegate_fptr(
        ctx,
        HostfxrDelegateType::HdtLoadAssemblyAndGetFunctionPointer,
        &mut delegate,
    );

    if ret != 0 || delegate.is_null() {
        return InitializeResult::GetRuntimeDelegateError;
    }

    let load_assembly_fptr: LoadAssemblyAndGetFunctionPointerFn =
        std::mem::transmute_copy(&delegate);

    type CustomEntryPointFn = unsafe extern "C" fn();
    let mut custom: *mut c_void = std::ptr::null_mut();

    let ret = load_assembly_fptr(
        assembly_path,
        type_name,
        method_name,
        UNMANAGEDCALLERSONLY_METHOD,
        std::ptr::null(),
        &mut custom,
    );

    if ret != 0 || custom.is_null() {
        return InitializeResult::EntryPointError;
    }

    let custom_fn: CustomEntryPointFn = std::mem::transmute_copy(&custom);
    custom_fn();

    hostfxr_close_fptr(ctx);

    Ok(())
}

#[cfg(unix)]
fn get_env_var(name: &str) -> Option<String> {
    std::env::var(name).ok()
}

#[cfg(unix)]
#[ctor::ctor]
fn initialize_library() {
    if let (Some(runtime_config_path), Some(assembly_path), Some(type_name), Some(method_name)) = (
        get_env_var("RUNTIME_CONFIG_PATH"),
        get_env_var("ASSEMBLY_PATH"),
        get_env_var("TYPE_NAME"),
        get_env_var("METHOD_NAME"),
    ) {
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::std::time::Duration::from_secs(1));
            let runtime_config_path_cstr = CString::new(runtime_config_path).unwrap();
            let assembly_path_cstr = CString::new(assembly_path).unwrap();
            let type_name_cstr = CString::new(type_name).unwrap();
            let method_name_cstr = CString::new(method_name).unwrap();

            let ret = bootstrapper_load_assembly(
                runtime_config_path_cstr.as_ptr(),
                assembly_path_cstr.as_ptr(),
                type_name_cstr.as_ptr(),
                method_name_cstr.as_ptr(),
            );
            println!("[+] api.inject() => {:?}", ret);
        });
    }
}

fn main() {}
