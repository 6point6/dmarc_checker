#![feature(backtrace)]
use clap::{App, Arg};
use std::fs::File;
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
        .get_matches();

    env_logger::init();
    info!("Welcome!");

    let input_file: &str = args.value_of("domain_list").unwrap();
    let output_file: &str = args.value_of("output_file").unwrap();

    let domain_list: Vec<u8> = std::fs::read(input_file)
        .map_err(|e| print_err!("File read error for: {} - {}", input_file, e))?;

    let mut domain_list_reader: csv::Reader<&[u8]> = csv::Reader::from_reader(&domain_list[..]);

    let out_file = File::create(output_file)
        .map_err(|e| print_err!("Failed to create output file: {} - {}", output_file, e))?;

    let mut output_file_writer = csv::Writer::from_writer(out_file);

    for entry in domain_list_reader.deserialize::<parse::DomainName>() {
        let domain_name: parse::DomainName =
            entry.map_err(|e| print_err!("Failed to deserialize entry - {}", e))?;

        let string_records: Option<query::StringRecords> =
            query::try_dmarc_query(&domain_name.0).map_err(|e| eprintln!("{}", e))?;

        match string_records {
            Some(sr) => match sr {
                query::StringRecords::Single(s) => {
                    let dmarc = parse::Dmarc::new(&domain_name.0, s);
                    info!("{:#?}", &dmarc);

                    output_file_writer
                        .serialize::<parse::Dmarc>(dmarc)
                        .map_err(|e| {
                            print_err!("Failed to serialze data in Single record - {}", e)
                        })?;
                }
                query::StringRecords::Multiple(vs) => {
                    for s in vs {
                        let dmarc = parse::Dmarc::new(&domain_name.0, s);
                        info!("{:#?}", &dmarc);

                        output_file_writer
                            .serialize::<parse::Dmarc>(dmarc)
                            .map_err(|e| {
                                print_err!("Failed to serialze data for in Multiple record - {}", e)
                            })?;
                    }
                }
            },
            None => {
                let dmarc = parse::Dmarc::new(&domain_name.0, None);
                info!("{:#?}", &dmarc);

                output_file_writer
                    .serialize::<parse::Dmarc>(dmarc)
                    .map_err(|e| print_err!("Failed to serialze data fo empty record - {}", e))?;
            }
        }
    }

    output_file_writer
        .flush()
        .map_err(|e| print_err!("Error flushing output file: {} - {}", output_file, e))?;

    Ok(())
}
