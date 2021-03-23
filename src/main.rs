#![feature(backtrace)]
use clap::{App, Arg};
use serde::{Deserialize, Serialize};
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
                .short("d")
                .long("domain_list")
                .value_name("DOMAIN_NAME_LIST_CSV")
                .help("List of domain names to query")
                .required(true)
                .takes_value(true),
        )
        .get_matches();

    env_logger::init();
    info!("Welcome!");

    let input_file: &str = args.value_of("domain_list").unwrap();

    let q = query::Querier::new("1.1.1.1:53").map_err(|e| eprintln!("{}", e))?;

    let r = q.dmarc("_dmarc.google.co.uk")
        .map_err(|e| eprintln!("{}", e))?;

    let dmarc_parsed = parse::DmarcParsed::new(&r);
    let dmarc = parse::Dmarc::new(dmarc_parsed);

    println!("{:#?}", dmarc);

    Ok(())
}
