import { log } from "./logger.js";

const allocUtfString =
    Process.platform === "windows"
        ? Memory.allocUtf16String
        : Memory.allocUtf8String;

rpc.exports = {
    bootstrap: (
        runtime_config_path: string,
        assembly_path: string,
        type_name: string,
        method_name: string
    ) => {
        const hostfxr: string = {
            windows: "hostfxr.dll",
            linux: "libhostfxr.so",
            darwin: "libhostfxr.dylib",
            barebone: "",
            freebsd: "",
            qnx: "",
        }[Process.platform];

        const hostfxr_initialize_for_runtime_config = Module.getExportByName(
            hostfxr,
            "hostfxr_initialize_for_runtime_config"
        ) as NativeFunction<
            number,
            [NativePointerValue, NativePointerValue, NativePointerValue]
        >;
        const hostfxr_get_runtime_delegate = Module.getExportByName(
            hostfxr,
            "hostfxr_get_runtime_delegate"
        );
        const hostfxr_close = Module.getExportByName(hostfxr, "hostfxr_close");
        let hostfxr_context = Memory.alloc(Process.pointerSize);
        hostfxr_initialize_for_runtime_config(
            allocUtfString(runtime_config_path),
            NULL,
            hostfxr_context
        );
        log(hostfxr_context.toString());
    },
};
