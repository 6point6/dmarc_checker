use csv_async::AsyncSerializer;
use trust_dns_client::rr::Record;
use tokio::sync::mpsc;
use tokio::fs::File;

mod parse;
mod utils;
mod query;

#[tokio::main]
async fn main() {

    let config = utils::Config::new();
    let (tx, rx) = mpsc::channel(query::DNS_SERVERS.len());
    
    // Loop through domains in file provider by user
    for domain_name in std::fs::read_to_string(config.input_domain_file).unwrap().lines() {
        
        // Convert domain name to string for tokio task
        let domain_name = domain_name.to_string();

        // Clone Sender tx for task move
        let tx = tx.clone();

        tokio::spawn(async move { 
            query::try_query(domain_name, tx).await
        });
    }
    // Close original Sender tx to prevent a dead lock
    drop(tx);

    // Open asynchronous file writers and serializers
    let output_dmarc_file = File::create(config.output_dmarc_file).await.unwrap();
    let mut output_dmarc_filewriter = csv_async::AsyncSerializer::from_writer(output_dmarc_file);
    
    // Write output to csv file
    output_dmarc_filewriter = write_dmarc_output_to_csv(output_dmarc_filewriter, rx).await;

    // Flush filewriter buffers
    let _ = output_dmarc_filewriter.flush();
}

async fn write_dmarc_output_to_csv(mut output_dmarc_filewriter: AsyncSerializer<File>, 
                                   mut rx: mpsc::Receiver<(String, Vec<Record>)>) -> AsyncSerializer<File> {
    
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
                        .serialize::<parse::Dmarc>(dmarc).await.unwrap()
                },
                // Write multiple DMARC record
                parse::StringRecords::Multiple(vs) => {
                    for s in vs {
                    let dmarc = parse::Dmarc::new(&domain_name, s);
                    output_dmarc_filewriter
                        .serialize::<parse::Dmarc>(dmarc).await.unwrap()
                    }
                },
            },
            // No DMARC record
            None => {
                let dmarc = parse::Dmarc::new(&domain_name, None);
                output_dmarc_filewriter
                    .serialize::<parse::Dmarc>(dmarc).await.unwrap()
            },
        }
    }

    output_dmarc_filewriter
}
