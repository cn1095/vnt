/// 参考
/// https://github.com/meh/rust-tun
/// https://github.com/Tazdevil971/tap-windows
/// https://github.com/nulldotblack/wintun
pub mod device;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::Device;

#[cfg(any(target_os = "android", target_os = "ios"))]
mod android;
#[cfg(any(target_os = "android", target_os = "ios"))]
pub use android::Device;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::Device;

#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub use unix::Fd;
#[cfg(windows)]
mod windows;

#[cfg(windows)]
pub use windows::Device;

#[cfg(windows)]
mod packet;
