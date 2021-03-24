#![feature(backtrace)]
use clap::{App, Arg};
use std::fs;
use std::fs::File;
use trust_dns_client::op::DnsResponse;
mod query;
#[macro_use]
extern crate log;
#[macro_use]
mod util;
mod parse;

fn main() -> Result<(), ()> {
    let args = App::new("dmarc_checker")
        .version("0.1")
        .about("Checks for dmarc misconfigurations")
        .arg(
            Arg::with_name("domain_list")
                .short("l")
                .long("domain_list")
                .value_name("DOMAIN_NAME_LIST_CSV")
                .help("List of domain names to query")
                .required(true)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("output_file")
                .short("o")
                .long("output_file")
                .value_name("PARSED_DOMAIN_LIST_CSV")
                .help("output file containing results")
                .required(true)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("dns_server")
                .short("d")
                .long("dns_server")
                .value_name("DNS_SERVER_IP")
                .help("ip of dns server to resolve records with")
                .required(false)
                .takes_value(true),
        )
        .get_matches();

    env_logger::init();
    info!("Welcome!");

    let input_file: &str = args.value_of("domain_list").unwrap();
    let output_file: &str = args.value_of("output_file").unwrap();
    let dns_server: &str = args.value_of("dns_server").unwrap_or("1.1.1.1");

    let domain_list: Vec<u8> = std::fs::read(input_file)
        .map_err(|e| print_err!("File read error for: {} - {}", input_file, e))?;

    let mut domain_list_reader: csv::Reader<&[u8]> = csv::Reader::from_reader(&domain_list[..]);

    let output_file = File::create(output_file)
        .map_err(|e| print_err!("Failed to create output file: {} - {}", output_file, e))?;

    let output_file_writer = csv::Writer::from_writer(output_file);

    let q = query::Querier::new(dns_server).map_err(|e| eprintln!("{}", e))?;

    for entry in domain_list_reader.deserialize::<parse::DomainName>() {
        let domain_name: parse::DomainName =
            entry.map_err(|e| print_err!("Failed to deserialize entry - {}", e))?;
        
        let dmarc_txt_opt: Option<String> = q.dmarc(&domain_name.0).map_err(|e| eprintln!("{}", e))?;

        let dmarc = parse::Dmarc::new(dmarc_txt_opt);
        
        info!("{:#?}", dmarc);

        
    }

    Ok(())
}
