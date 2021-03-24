use crate::fmt_err;
use std::net::Ipv4Addr;
use std::str::FromStr;
use trust_dns_client::client::{Client, ClientConnection, SyncClient};
use trust_dns_client::error::{ClientError, ClientErrorKind};
use trust_dns_client::op::DnsResponse;
use trust_dns_client::rr::{DNSClass, Name, RData, Record, RecordType};
use trust_dns_client::udp::UdpClientConnection;
use trust_dns_proto::DnsStreamHandle;

const DNS_SERVERS: &[&str] = &[
    "8.8.8.8:53",
    "8.8.4.4:53",
    "9.9.9.9:53",
    "149.122.122.122:53",
    "208.67.222.222:53",
    "1.1.1.1:53",
    "1.0.0.1:53",
    "185.228.168.9:53",
    "185.228.169.9:53",
    "76.76.19.19:53",
    "76.223.122.150:53",
    "94.140.14.14:53",
    "94.140.15.15:53",
];

const SERVER_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(200);

pub fn try_dmarc_query(domain_name: &str) -> Result<Option<String>, String> {
    loop {
        for s in DNS_SERVERS.iter() {
            let soc_addr: std::net::SocketAddr = s.parse().map_err(|e| fmt_err!("{}", e))?;
            let conn = UdpClientConnection::with_timeout(soc_addr, SERVER_TIMEOUT).unwrap();
            let client = SyncClient::new(conn);

            match dmarc(domain_name, client) {
                Ok(r) => return Ok(r),
                Err(e) => match e.kind() {
                    ClientErrorKind::Timeout => {
                        info!("Request timeout for: {} - trying next dns server", s);
                        continue;
                    }
                    e @ _ => return Err(fmt_err!("{}", e)),
                },
            }
        }
    }
}

fn dmarc(
    domain_name: &str,
    client: SyncClient<UdpClientConnection>,
) -> Result<Option<String>, ClientError> {
    let name = Name::from_str(&format!("_dmarc.{}", domain_name)).map_err(|e| fmt_err!("{}", e))?;

    let r = client.query(&name, DNSClass::IN, RecordType::TXT)?;

    let a = r.answers();

    if a.len() == 0 {
        return Ok(None);
    }

    let dmarc_result = match a[0].rdata().as_txt().and_then(|t| Some(t.txt_data())) {
        Some(r) => r,
        None => return Ok(None),
    };

    let txt = dmarc_result
        .iter()
        .map(|i| std::str::from_utf8(i))
        .try_fold(String::new(), |a, i| {
            i.map(|i| {
                let mut a = a;
                a.push_str(i);
                a
            })
        })
        .map_err(|e| fmt_err!("{}", e))?;

    Ok(Some(txt))
}
