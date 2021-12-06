use std::collections::HashSet;
use std::iter::FromIterator;
use std::net::Ipv4Addr;
use std::ops::RangeInclusive;
use std::process::Stdio;
use std::str::FromStr;
use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use cidr_utils::cidr::{IpCidr, Ipv4Cidr};
use cidr_utils::utils::Ipv4CidrSeparator;
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use tokio::net::TcpStream;
use tokio::process::Command;

#[derive(Clone, Debug)]
struct PortScan {
    ip_rang: Vec<Ipv4Cidr>,
    concurrency: usize,
    timeout: Duration,
    result: Vec<SocketAddr>,
}

impl PortScan {
    pub fn new(target: String, timeout: u64) -> Self {
        let mut ipv4_cidr: Vec<Ipv4Cidr> = vec![];
        if let Ok(ip_rang) = IpCidr::from_str(target) {
            if let IpCidr::V4(cidr) = ip_rang {
                let mut bits = 24;
                if cidr.get_bits() >= bits {
                    bits = cidr.get_bits()
                }
                ipv4_cidr = Ipv4CidrSeparator::sub_networks(&cidr, bits).unwrap();
            }
        }
        Self {
            ip_rang: ipv4_cidr,
            concurrency: 512,
            timeout: Duration::from_millis(timeout),
            result: vec![],
        }
    }
}

async fn connect_port(target: IpAddr, port: u16, timeout: Duration) -> Option<SocketAddr> {
    let socket_address = SocketAddr::new(target.clone(), port);
    match tokio::time::timeout(timeout, TcpStream::connect(&socket_address)).await {
        Ok(Ok(host_port)) => {
            println!("open: {:?}", host_port.peer_addr().unwrap());
            return Some(host_port.peer_addr().unwrap());
        }
        _ => {}
    }
    None
}

async fn exec_ping(ip_address_string: String) -> Option<String> {
    let mut ping = Command::new("ping");
    let mut wait_time = "1";
    let mut count = "-c";
    let mut wait_time_args = "-W";
    //  c on linux, n on windows
    if cfg!(windows) {
        count = "-n";
        wait_time_args = "-w";
    }
    if let Ok(ip_address) = Ipv4Addr::from_str(ip_address_string.as_str()) {
        if !ip_address.is_private() {
            wait_time = "3";
        }
    }
    let status = ping
        .args([count, "1"])
        .args([wait_time_args, wait_time])
        .arg(&ip_address_string)
        .arg("-4")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .unwrap();
    return if status.success() {
        Some(ip_address_string.clone())
    } else {
        None
    };
}

impl PortScan {
    async fn scan_port_open(&mut self, target: IpAddr) {
        let mut ports = self.get_ports();
        let mut ftrs = FuturesUnordered::new();
        for _ in 0..self.concurrency {
            if let Some(port) = ports.next() {
                ftrs.push(connect_port(target, port, self.timeout));
            } else {
                break;
            }
        }
        while let Some(result) = ftrs.next().await {
            if let Some(port) = ports.next() {
                ftrs.push(connect_port(target, port, self.timeout));
            }
            match result {
                Some(socket) => self.result.push(socket),
                None => {}
            }
        }
    }

    fn get_ports(&self) -> RangeInclusive<u16> {
        (1..=u16::MAX).into_iter()
    }

    async fn run(&mut self) {
        for ipv4_cidr in self.ip_rang.clone() {
            let mut futures_e = FuturesUnordered::new();
            let mut socket_iterator = ipv4_cidr.iter_as_ipv4_addr().into_iter();
            for _ in 0..16 {
                if let Some(socket) = socket_iterator.next() {
                    futures_e.push(exec_ping(socket.to_string()));
                } else {
                    break;
                }
            }
            while let Some(result) = futures_e.next().await {
                if let Some(socket) = socket_iterator.next() {
                    futures_e.push(exec_ping(socket.to_string()));
                }
                if let Some(host) = result {
                    self.scan_port_open(IpAddr::from_str(host.as_str()).unwrap())
                        .await;
                }
            }
        }
    }
}

pub async fn ip_cidr_to_host_port(target: &String) -> HashSet<String> {
    let mut port_scan = PortScan::new(target.clone(), 300);
    port_scan.run().await;
    let result = port_scan.result;
    let targets: Vec<String> = result.into_iter().map(|ip| ip.to_string()).collect();
    return HashSet::from_iter(targets);
}
