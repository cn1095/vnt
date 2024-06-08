use std::io;
use std::sync::Arc;

use crossbeam_utils::atomic::AtomicCell;
use parking_lot::Mutex;

use tun::device::IFace;
use tun::Device;

use crate::channel::context::ChannelContext;
use crate::cipher::Cipher;
use crate::compression::Compressor;
use crate::external_route::ExternalRoute;
use crate::handle::tun_tap::DeviceStop;
use crate::handle::{CurrentDeviceInfo, PeerDeviceInfo};
#[cfg(feature = "ip_proxy")]
use crate::ip_proxy::IpProxyMap;
use crate::tun_tap_device::vnt_device::DeviceWrite;
use crate::util::{SingleU64Adder, StopManager};

#[repr(transparent)]
#[derive(Clone, Default)]
pub struct DeviceAdapter {
    tun: Arc<Mutex<Option<Arc<Device>>>>,
}

impl DeviceAdapter {
    pub fn insert(&self, device: Arc<Device>) {
        let r = self.tun.lock().replace(device);
        assert!(r.is_none());
    }
    /// 要保证先remove 再insert
    pub fn remove(&self) {
        drop(self.tun.lock().take());
    }
}

impl DeviceWrite for DeviceAdapter {
    #[inline]
    fn write(&self, buf: &[u8]) -> io::Result<usize> {
        if let Some(tun) = self.tun.lock().as_ref() {
            tun.write(buf)
        } else {
            Err(io::Error::new(io::ErrorKind::NotFound, "not tun device"))
        }
    }

    fn into_device_adapter(self) -> DeviceAdapter {
        self
    }
}

#[derive(Clone)]
pub struct TunDeviceHelper {
    inner: Arc<Mutex<TunDeviceHelperInner>>,
    device_adapter: DeviceAdapter,
    device_stop: Arc<Mutex<Option<DeviceStop>>>,
}

#[derive(Clone)]
struct TunDeviceHelperInner {
    stop_manager: StopManager,
    context: ChannelContext,
    current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
    ip_route: ExternalRoute,
    #[cfg(feature = "ip_proxy")]
    ip_proxy_map: Option<IpProxyMap>,
    client_cipher: Cipher,
    server_cipher: Cipher,
    up_counter: SingleU64Adder,
    device_list: Arc<Mutex<(u16, Vec<PeerDeviceInfo>)>>,
    compressor: Compressor,
}

impl TunDeviceHelper {
    pub fn new(
        stop_manager: StopManager,
        context: ChannelContext,
        current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
        ip_route: ExternalRoute,
        #[cfg(feature = "ip_proxy")] ip_proxy_map: Option<IpProxyMap>,
        client_cipher: Cipher,
        server_cipher: Cipher,
        up_counter: SingleU64Adder,
        device_list: Arc<Mutex<(u16, Vec<PeerDeviceInfo>)>>,
        compressor: Compressor,
        device_adapter: DeviceAdapter,
    ) -> Self {
        let inner = TunDeviceHelperInner {
            stop_manager,
            context,
            current_device,
            ip_route,
            #[cfg(feature = "ip_proxy")]
            ip_proxy_map,
            client_cipher,
            server_cipher,
            up_counter,
            device_list,
            compressor,
        };
        Self {
            inner: Arc::new(Mutex::new(inner)),
            device_adapter,
            device_stop: Default::default(),
        }
    }
    pub fn stop(&self) {
        //先停止旧的，再启动新的，改变旧网卡的IP太麻烦
        if let Some(device_stop) = self.device_stop.lock().take() {
            self.device_adapter.remove();
            loop {
                device_stop.stop();
                std::thread::sleep(std::time::Duration::from_millis(300));
                //确保停止了
                if device_stop.is_stop() {
                    break;
                }
            }
        }
    }
    /// 要保证先stop 再start
    pub fn start(&self, device: Arc<Device>) -> io::Result<()> {
        self.device_adapter.insert(device.clone());
        let device_stop = DeviceStop::default();
        let s = self.device_stop.lock().replace(device_stop.clone());
        assert!(s.is_none());
        let inner = self.inner.lock().clone();
        crate::handle::tun_tap::tun_handler::start(
            inner.stop_manager,
            inner.context,
            device,
            inner.current_device,
            inner.ip_route,
            #[cfg(feature = "ip_proxy")]
            inner.ip_proxy_map,
            inner.client_cipher,
            inner.server_cipher,
            inner.up_counter,
            inner.device_list,
            inner.compressor,
            device_stop,
        )
    }
}
