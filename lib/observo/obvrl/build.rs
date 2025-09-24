/**
This file is NOT part of the open-source components licensed under the Mozilla Public License, v. 2.0 (MPL-2.0).
Proprietary and Confidential – © 2025 Observo Inc.
Unauthorized copying, modification, distribution, or disclosure of this file, via any medium, is strictly prohibited.
This file is distributed separately and is not subject to the terms of the MPL-2.0.
**/
use std::{
    collections::BTreeMap, env, fs, path::PathBuf, process::{Command, Stdio}, time::Duration
};

fn cmd(exe: &str) -> Command {
    let mut c = Command::new(exe);
    c
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .stdin(Stdio::null());
    c
}

fn main() {
    let target_arch = env::var("TARGET").expect("TARGET not set by Cargo");
    let host_arch = env::var("HOST").expect("HOST not set by Cargo");

    println!("cargo:warning=Host architecture: {}", host_arch);
    println!("cargo:warning=Target architecture: {}", target_arch);

    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let target_dir = PathBuf::from(manifest_dir).join("target");
    let build_dir = target_dir.join("build.d").join(&target_arch);
    fs::create_dir_all(&build_dir).unwrap();
    let cache_dir = target_dir.join("cache.d").join(&target_arch).join("lib");
    fs::create_dir_all(&cache_dir).expect("Failed to create cache dir");

    let lib_path = cache_dir.join("libxml2.a");
    if lib_path.exists() {
        println!("cargo:warning=Found cached libxml2 for {} (at {}), will reuse.", target_arch, lib_path.display());
        print_libxml2_cargo_directives(&cache_dir);
        return;
    }

    println!("cargo:warning=Building libxml2 for {}", target_arch);

    let version = "2.11.9";
    let url = format!("https://download.gnome.org/sources/libxml2/2.11/libxml2-{version}.tar.xz");
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(300))
        .build()
        .expect("Failed to create HTTP client");

    let response = client
        .get(&url)
        .send()
        .expect("Failed to download libxml2")
        .bytes()
        .expect("Failed to read response");

    let archive_path = build_dir.join("libxml2.tar.xz");
    fs::write(&archive_path, &response).expect("Failed to save archive");

    let status = cmd("tar")
        .args(&["xJf", archive_path.to_str().unwrap()])
        .current_dir(build_dir.clone())
        .status()
        .expect("Failed to extract archive");

    if !status.success() {
        panic!("Failed to extract libxml2 archive");
    }

    let mut configure_args = vec![
        "--enable-static",
        "--disable-shared",
        "--without-http",
        "--without-icu",
        "--without-lzma",
        "--without-python",
        "--without-zlib",
    ];
    let host_arg = format!("--host={}", host_arch);
    let build_arg = format!("--build={}", target_arch);
    configure_args.push(host_arg.as_str());
    configure_args.push(build_arg.as_str());

    #[derive(Clone)]
    struct BuildConfig {
        cc: &'static str,
        ar: &'static str,
        ranlib: &'static str,
    }

    impl BuildConfig {
        fn ok(&self) -> Option<&Self> {
            let ok = vec![self.cc, self.ar, self.ranlib].into_iter().all(|exe| {

                let exe = exe.to_string();
                cmd("which")
                    .arg(&exe)
                    .status()
                    .map(|s| s.success())
                    .unwrap_or(false)
            });
            if ok {
                Some(self)
            } else {
                None
            }
        }
    }

    let default = BuildConfig{
        cc: "gcc",
        ar: "ar",
        ranlib: "ranlib"
    };
    let arm64 = BuildConfig{
        cc: "aarch64-linux-gnu-gcc",
        ar: "aarch64-linux-gnu-ar",
        ranlib: "aarch64-linux-gnu-ranlib"
    };
    let pref: BTreeMap<&'static str, BuildConfig> = BTreeMap::from([
        ("x86_64", BuildConfig{
            cc: "x86_64-linux-gnu-gcc",
            ar: "x86_64-linux-gnu-ar",
            ranlib: "x86_64-linux-gnu-ranlib"
        }),
        ("aarch64", arm64.clone()),
        ("arm64", arm64),
        ("armv7l", BuildConfig{
            cc: "arm-linux-gnueabihf-gcc",
            ar: "arm-linux-gnueabihf-ar",
            ranlib: "arm-linux-gnueabihf-ranlib"
        })]);
    let build_tools: &BuildConfig = pref.get(target_arch.split('-').next().unwrap()).unwrap_or(&default);
    let &BuildConfig{cc, ar, ranlib} = build_tools.ok().unwrap_or(&default);
    let build_env: BTreeMap<&str, &str> = BTreeMap::from([
        ("CFLAGS", "-O3 -fPIC"),
        ("CC", cc),
        ("AR", ar),
        ("RANLIB", ranlib),
    ]);

    let source_dir = build_dir.join(format!("libxml2-{}", version));
    let status = cmd("./configure")
        .args(configure_args)
        .envs(build_env.clone())
        .current_dir(&source_dir)
        .status()
        .expect("Failed to configure libxml2");
    if !status.success() {
        panic!("Failed to configure libxml2");
    }

    let num_jobs = num_cpus::get().to_string();
    let status = cmd("make")
        .arg("-j")
        .arg(&num_jobs)
        .envs(build_env)
        .current_dir(&source_dir)
        .status()
        .expect("Failed to build libxml2");
    if !status.success() {
        panic!("Failed to build libxml2");
    }

    fs::copy(
        source_dir.join(".libs/libxml2.a"),
        cache_dir.join("libxml2.a"),
    ).expect("Failed to copy libxml2.a to cache");

    println!("cargo:warning=Successfully built libxml2 for {}", target_arch);
    print_libxml2_cargo_directives(&cache_dir);
}

fn print_libxml2_cargo_directives(cache_lib_dir: &PathBuf) {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=TARGET");
    println!("cargo:rerun-if-env-changed=HOST");
    println!("cargo:rustc-link-search=native={}", cache_lib_dir.display());
    println!("cargo:rustc-link-lib=static=xml2");
}