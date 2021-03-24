use crate::fmt_err;
use std::net::Ipv4Addr;
use std::str::FromStr;
use trust_dns_client::client::{Client, ClientConnection, SyncClient};
use trust_dns_client::op::DnsResponse;
use trust_dns_client::rr::{DNSClass, Name, RData, Record, RecordType};
use trust_dns_client::udp::UdpClientConnection;
use trust_dns_proto::DnsStreamHandle;

pub struct Querier {
    pub client: SyncClient<UdpClientConnection>,
}

impl Querier {
    pub fn new(dns_server: &str) -> Result<Self, String> {
        let soc_addr: std::net::SocketAddr = dns_server.parse().map_err(|e| fmt_err!("{}", e))?;

        let con = UdpClientConnection::new(soc_addr).unwrap();

        Ok(Self {
            client: SyncClient::new(con),
        })
    }

    pub fn dmarc(&self, domain: &str) -> Result<Option<String>, String> {
        let name = Name::from_str(domain).map_err(|e| fmt_err!("{}", e))?;

        let r = self
            .client
            .query(&name, DNSClass::IN, RecordType::TXT)
            .map_err(|e| fmt_err!("{}", e))?;

        let a = r.answers();

        println!("answers: {:#X?}", a);

        if a.len() == 0 {
            return Ok(None)
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
}
