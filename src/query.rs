use crate::fmt_err;
use std::net::Ipv4Addr;
use std::str::FromStr;
use trust_dns_client::client::{Client, ClientConnection, SyncClient};
use trust_dns_client::error::{ClientError, ClientErrorKind};
use trust_dns_client::op::DnsResponse;
use trust_dns_client::rr::{DNSClass, Name, RData, Record, RecordType};
use trust_dns_client::udp::UdpClientConnection;

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

pub fn try_dmarc_query(domain_name: &str) -> Result<Option<StringRecords>, String> {
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

pub enum StringRecords {
    Single(Option<String>),
    Multiple(Vec<Option<String>>),
}

impl StringRecords {
    fn new(r: &[Record]) -> Option<Self> {
        match r.len() {
            0 => None,
            1 => {
                Some(Self::Single(record_to_string(&r[0])))
            }
            n @ _ => {
                let mut strings: Vec<Option<String>> = Vec::with_capacity(n);

                for i in r.iter() {
                    strings.push(record_to_string(i))
                }

                Some(Self::Multiple(strings))
            }
        }
    }
}

fn record_to_string(r: &Record) -> Option<String> {
    match r.rdata().to_record_type() {
        RecordType::CNAME => r
            .rdata()
            .as_cname()
            .and_then(|cname| Some(cname.to_string())),
        RecordType::TXT => r
            .rdata()
            .as_txt()
            .and_then(|txt_data| Some(txt_data.to_string())),
        _ => None,
    }
}

fn dmarc(
    domain_name: &str,
    client: SyncClient<UdpClientConnection>,
) -> Result<Option<StringRecords>, ClientError> {
    let name = Name::from_str(&format!("_dmarc.{}", domain_name)).map_err(|e| fmt_err!("{}", e))?;
    let dns_response = client.query(&name, DNSClass::IN, RecordType::TXT)?;
    let records = dns_response.answers();

    Ok(StringRecords::new(records))
}
