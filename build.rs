use std::path::Path;

fn main() {
    let target = std::env::var("TARGET").unwrap();

    if target.contains("windows") && target.contains("msvc") {
        let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
        let manifest_path = Path::new(&manifest_dir);
        let def_path = manifest_path.join("injector.def");
        let def_path = def_path.canonicalize().unwrap();
        // Windows 平台，传递 .def 文件
        println!("cargo:rustc-link-arg=/DEF:{}", def_path.to_str().unwrap());
    } else {
        // 其他平台，传递 -rdynamic
        println!("cargo:rustc-link-arg=-rdynamic");
    }
}
