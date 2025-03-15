use std::ffi::{c_char, c_uint, c_void, CStr, CString};
use std::mem::transmute;
use std::os::raw::c_int;
use std::path::PathBuf;
use std::{fs, slice};

use clap::{Parser, Subcommand};
use frida::{DeviceManager, Frida, Inject, Injector, Session};
use netcorehost::error::HostingError;
use netcorehost::hostfxr::{GetManagedFunctionError, Hostfxr};
use netcorehost::nethost::{self, LoadHostfxrError};
use netcorehost::pdcstring::PdCStr;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug)]
#[repr(u32)]
enum InitializeError {
    #[error("LoadHostfxrError")]
    LoadHostfxr(#[from] LoadHostfxrError),
    #[error("HostingError")]
    Hosting(#[from] HostingError),
    #[error("InitializeRuntimeConfigError")]
    GetManagedFunction(#[from] GetManagedFunctionError),
    #[error("GetRuntimeDelegateError")]
    GetRuntimeDelegateError,
    #[error("EntryPointError")]
    EntryPointError,
}

#[derive(Debug)]
#[repr(u32)]
enum InitializeResult {
    Success,
    Error(InitializeError),
}

#[no_mangle]
pub unsafe extern "C" fn bootstrapper_load_assembly(
    runtime_config_path: *const c_char,
    assembly_path: *const c_char,
    type_name: *const c_char,
    method_name: *const c_char,
) -> Result<(), InitializeError> {
    let hostfxr = nethost::load_hostfxr()?;
    let context = hostfxr
        .initialize_for_runtime_config(PdCStr::from_str_ptr(runtime_config_path as *const u16))?;
    let fn_loader = context
        .get_delegate_loader_for_assembly(PdCStr::from_str_ptr(assembly_path as *const u16))
        .unwrap();
    let hello = fn_loader.get_function_with_unmanaged_callers_only::<fn()>(
        PdCStr::from_str_ptr(transmute(type_name)),
        PdCStr::from_str_ptr(transmute(method_name)),
    )?;
    Ok(())
}
#[no_mangle]
pub unsafe extern "C" fn initialize(payload: *const i8) {
    if let Ok(payload) = serde_json::from_slice::<Payload>(CStr::from_ptr(payload).to_bytes()) {
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_secs(1));
            let runtime_config_path_cstr = CString::new(payload.runtime_config_path).unwrap();
            let assembly_path_cstr = CString::new(payload.assembly_path).unwrap();
            let type_name_cstr = CString::new(payload.type_name).unwrap();
            let method_name_cstr = CString::new(payload.method_name).unwrap();

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

#[derive(Parser)]
#[clap(name = "net-core-injector", about = "Inject C# library into process")]
#[clap(version)]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Inject {
        #[clap(value_name = "process_name")]
        process_name: String,
        #[clap(value_name = "runtime_config_path")]
        runtime_config_path: String,
        #[clap(value_name = "assembly_path")]
        assembly_path: String,
        #[clap(value_name = "type_name")]
        type_name: String,
        #[clap(value_name = "method_name")]
        method_name: String,
    },
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
struct Payload {
    runtime_config_path: String,
    assembly_path: String,
    type_name: String,
    method_name: String,
}

fn run_inject(args: Commands) -> Result<(), Box<dyn std::error::Error>> {
    if let Commands::Inject {
        process_name,
        runtime_config_path,
        assembly_path,
        type_name,
        method_name,
    } = args
    {
        let frida = unsafe { Frida::obtain() };

        let device_manager = DeviceManager::obtain(&frida);
        let mut device = device_manager.get_local_device()?;
        let payload = Payload {
            runtime_config_path,
            assembly_path,
            type_name,
            method_name,
        };
        device.inject_library_file_sync(123, process_name, "1", "1")?;
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    match &cli.command {
        Commands::Inject { .. } => {
            run_inject(cli.command)?;
        }
    }
    Ok(())
}
