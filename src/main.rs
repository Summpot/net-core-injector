use std::ffi::{c_char, c_uint, c_void, CStr, CString};
use std::fs;
use std::mem::transmute;
use std::os::raw::c_int;
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use frida::Session;
use libloading::{Library, Symbol};
use netcorehost::hostfxr::Hostfxr;
use netcorehost::nethost;
use netcorehost::pdcstring::PdCStr;
use thiserror::Error;

#[derive(Error, Debug)]
#[repr(u32)]
enum InitializeError {
    #[error("HostFxrLoadError")]
    HostFxrLoadError,
    #[error("InitializeRuntimeConfigError")]
    InitializeRuntimeConfigError,
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

impl InitializeResult {
    fn from_u32(value: u32) -> Option<Self> {
        match value {
            0 => Some(Self::Success),
            1 => Some(Self::Error(InitializeError::HostFxrLoadError)),
            2 => Some(Self::Error(InitializeError::InitializeRuntimeConfigError)),
            3 => Some(Self::Error(InitializeError::GetRuntimeDelegateError)),
            4 => Some(Self::Error(InitializeError::EntryPointError)),
            _ => None,
        }
    }
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
) -> Result<(), InitializeError> {
    let hostfxr = nethost::load_hostfxr()?;
    let context = hostfxr
        .initialize_for_runtime_config(PdCStr::from_str_ptr(runtime_config_path as *const u16))?;
    let fn_loader = context
        .get_delegate_loader_for_assembly(PdCStr::from_str_ptr(assembly_path as *const u16))
        .unwrap();
    let hello = fn_loader
        .get_function_with_unmanaged_callers_only::<fn()>(
            PdCStr::from_str_ptr(transmute(type_name)),
            PdCStr::from_str_ptr(transmute(method_name)),
        )
        .unwrap();
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
        #[clap(value_name = "bootstrapper")]
        bootstrapper: PathBuf,
        #[clap(value_name = "runtime_config_path")]
        runtime_config_path: PathBuf,
        #[clap(value_name = "assembly_path")]
        assembly_path: PathBuf,
        #[clap(value_name = "type_name")]
        type_name: String,
        #[clap(value_name = "method_name")]
        method_name: String,
    },
}

async fn run_inject(args: &Commands) -> Result<(), Box<dyn std::error::Error>> {
    if let Commands::Inject {
        process_name,
        bootstrapper,
        runtime_config_path,
        assembly_path,
        type_name,
        method_name,
    } = args
    {
        let session = Session::attach(process_name).await?;

        let source = fs::read_to_string("dist/agent.js")?;

        let script = session.create_script(&source).await?;
        script.load().await?;

        let api = script.exports()?; // Need to verify the type of api from frida-rs

        // Assuming api.call_function exists in frida-rs and inject is the javascript function name
        let ret_value = api
            .call_function(
                "inject",
                &frida::Value::from_string(&bootstrapper.canonicalize()?.to_string_lossy()), // Convert PathBuf to String
                &frida::Value::from_string(&runtime_config_path.canonicalize()?.to_string_lossy()),
                &frida::Value::from_string(&assembly_path.canonicalize()?.to_string_lossy()),
                &frida::Value::from_string(type_name),
                &frida::Value::from_string(method_name),
            )
            .await?;

        // Assuming the return value from javascript inject is a number
        let ret_u32 = ret_value.to_u32().unwrap_or(999); // 999 as default unknown error code
        let initialize_result = InitializeResult::from_u32(ret_u32).unwrap_or_else(|| {
            println!(
                "[*] api.inject() => {} (InitializeResult::Unknown)",
                ret_u32
            );
            InitializeResult::EntryPointError // Or choose a default unknown error enum value
        });

        println!(
            "[*] api.inject() => {} (InitializeResult::{})",
            ret_u32, initialize_result
        );

        if ret_u32 != InitializeResult::Success as u32 {
            println!("An error occurred while injection into {}", process_name);
        }

        script.unload().await?;
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Inject { .. } => {
            run_inject(&cli.command).await?;
        }
    }

    Ok(())
}
