use std::{net::{IpAddr, Ipv4Addr, SocketAddr}, str::FromStr};
use trust_dns_client::client::{Client, SyncClient};
use trust_dns_client::udp::UdpClientConnection;
use trust_dns_client::rr::{DNSClass, Name, RecordType, Record};
use rand::thread_rng;
use rand::seq::SliceRandom;
use tokio::sync::mpsc;

pub const DNS_SERVERS: &'static [&'static str] = &[
    "8.8.8.8",
    "9.9.9.9",
    "8.8.4.4",
    "185.228.168.9",
    "185.228.169.9",
    "149.112.112.112",
    "208.67.222.222",
    "208.67.220.220",
    "87.117.196.200",
    "62.134.11.4",
    "213.171.217.147",
    "194.145.240.6",
    "213.171.217.148",
    "195.27.1.1",
    "195.182.110.132",
    "213.52.192.198",
    "154.32.105.18",
    "158.43.192.1",
    "84.8.2.11",
    "154.32.109.18",
    "154.32.107.18",
    "5.253.114.91",
    "212.118.241.33",
    "178.62.57.141",
    "188.227.240.58",
    "194.187.251.67",
    "193.111.200.191",
    "158.43.128.72",
    "158.43.240.4",
    "1.1.1.1",
    "1.0.0.1",
    "8.26.56.26",
    "8.20.247.20",
    "64.6.64.6",
    "64.6.65.6",
    "4.2.2.1",
    "4.2.2.2",
    "4.2.2.3",
    "4.2.2.4",
    "4.2.2.5",
    "192.250.35.250",
    "129.250.35.251",
    "204.117.214.10",
    "199.2.252.10",
    "76.86.19.19",
    "76.223.122.150",
    "94.140.14.14",
    "94.140.15.15"
];

pub async fn try_query(domain_name: String, tx :mpsc::Sender<(String, Vec<Record>)>) {
    // Read URIs to query
    let name = Name::from_utf8(format!("_dmarc.{}", domain_name)).unwrap();

    loop {
        // Clone for request
        let name = name.clone();

        // Open Udp connection for DNS client
        let conn = UdpClientConnection::with_timeout(
            get_dns_ip().await, 
            std::time::Duration::from_millis(200)
        ).unwrap();

        // DNS client stuff
        let client = SyncClient::new(conn);
       
        // Spawn blocking task and check for errors
        match tokio::task::spawn_blocking(move || {
            client.query(&name, DNSClass::IN, RecordType::TXT)
        }).await.unwrap() {
            Ok(dns_response) => {
                // Success to send domain name and DNS response to channel
                let _ = tx.send((domain_name, dns_response.answers().to_owned())).await;
                return
            }
            Err(_e) => {
                //eprintln!("Failed '{}'", e)
            },
        }
    }
}

async fn get_dns_ip() -> SocketAddr {
        // Choose random DNS server IP from DNS_SERVERS
        let dns_server = DNS_SERVERS.choose(&mut thread_rng()).unwrap();

        // Conver to SockAddr
        SocketAddr::new(IpAddr::V4(Ipv4Addr::from_str(dns_server).unwrap()), 53)
}
