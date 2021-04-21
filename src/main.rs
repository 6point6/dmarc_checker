use csv_async::AsyncSerializer;
use tokio::fs::File;
use tokio::sync::mpsc;
use trust_dns_client::rr::Record;

mod parse;
mod query;
#[macro_use]
mod utils;

#[tokio::main]
async fn main() -> Result<(), ()> {
    let config = utils::Config::new();

    // Open asynchronous file writers and serializers
    let output_dmarc_file = File::create(&config.output_dmarc_file).await.map_err(|e| {
        print_err!(
            "Failed to create output file: {} - {}",
            config.input_domain_file,
            e
        )
    })?;

    let mut output_dmarc_filewriter = csv_async::AsyncSerializer::from_writer(output_dmarc_file);
    
    // Read all domains for batching
    let domain_names = std::fs::read_to_string(&config.input_domain_file)
        .map_err(|e| {
            print_err!(
                "Failed to read file: {}
        - {}",
                config.input_domain_file,
                e
            )
        })?;
    
    // Batch into iter chunks of batch_size
    for domain_chunk in domain_names
        .lines()
        .collect::<Vec<&str>>()
        .chunks(config.batch_size) {

        let (tx, rx) = mpsc::channel(query::DNS_SERVERS.len());

        for domain_name in domain_chunk {
            
            // Convert domain name to string for tokio task
            let domain_name = domain_name.to_string();

            // Clone Sender tx for task move
            let tx = tx.clone();

            tokio::spawn(async move { query::try_query(domain_name, tx).await });
        }
        // Close original Sender tx to prevent a dead lock
        drop(tx);
        
        // Write output to csv file
        output_dmarc_filewriter = write_dmarc_output_to_csv(output_dmarc_filewriter, rx)
            .await
            .map_err(|e| { 
                eprintln!(
                    "Failed to write output to file: {} - {}",
                    config.input_domain_file, e
                )})?;
    }

    // Flush filewriter buffers
    output_dmarc_filewriter
        .flush()
        .await
        .map_err(|e| eprintln!("Failed to flush file {} - {}", config.input_domain_file, e))?;

    Ok(())
}

async fn write_dmarc_output_to_csv(
    mut output_dmarc_filewriter: AsyncSerializer<File>,
    mut rx: mpsc::Receiver<(String, Vec<Record>)>,
) -> Result<AsyncSerializer<File>, String> {
    // Recieve data from channel asynchronously
    while let Some((domain_name, dns_respoonse_answers)) = rx.recv().await {
        println!("Scanned '{}'", &domain_name);

        let string_records = parse::StringRecords::new(&dns_respoonse_answers);

        match string_records {
            Some(sr) => match sr {
                // Write single DMARC record
                parse::StringRecords::Single(s) => {
                    let dmarc = parse::Dmarc::new(&domain_name, s);
                    output_dmarc_filewriter
                        .serialize::<parse::Dmarc>(dmarc)
                        .await
                        .map_err(|e| {
                            fmt_err!(
                                "Failed to write single record for domain name: {} - {}",
                                domain_name,
                                e
                            )
                        })?
                }
                // Write multiple DMARC record
                parse::StringRecords::Multiple(vs) => {
                    for s in vs {
                        let dmarc = parse::Dmarc::new(&domain_name, s);
                        output_dmarc_filewriter
                            .serialize::<parse::Dmarc>(dmarc)
                            .await
                            .map_err(|e| {
                                fmt_err!(
                                    "Failed to write multiple record for domain name: {} - {}",
                                    domain_name,
                                    e
                                )
                            })?
                    }
                }
            },
            // No DMARC record
            None => {
                let dmarc = parse::Dmarc::new(&domain_name, None);
                output_dmarc_filewriter
                    .serialize::<parse::Dmarc>(dmarc)
                    .await
                    .map_err(|e| {
                        fmt_err!(
                            "Failed to write empty record for domain name: {} - {}",
                            domain_name,
                            e
                        )
                    })?
            }
        }
    }

    Ok(output_dmarc_filewriter)
}
