use clap::{App, Arg};

static DEFAULT_BATCH_SIZE: usize = 50000;

pub struct Config {
    pub input_domain_file: String,
    pub output_dmarc_file: String,
    pub batch_size: usize,
}

impl Config {
    pub fn new() -> Self {
        let args = App::new("dmarc_checker")
            .version("0.1")
            .about("Checks for dmarc misconfigurations")
            .arg(
                Arg::with_name("input_domain_file")
                    .short("i")
                    .long("input_domain_file")
                    .value_name("DOMAIN_NAME_LIST_CSV")
                    .help("List of domain names to query")
                    .required(true)
                    .takes_value(true),
            )
            .arg(
                Arg::with_name("output_dmarc_file")
                    .short("o")
                    .long("output_dmarc_file")
                    .value_name("PARSED_DOMAIN_LIST_CSV")
                    .help("output file containing results")
                    .required(true)
                    .takes_value(true),
            )
            .arg(
                Arg::with_name("batch_size")
                    .short("b")
                    .long("batch_size")
                    .value_name("BATCH_SIZE")
                    .help("batch size of domains to process")
                    .required(false)
                    .takes_value(true),
            )
            .get_matches();
       
        // If batch size exists set it to CLI argument, otherwise set it to default
        let batch_size = if args.occurrences_of("batch_size") > 0 {
            // Attempt to extract valid u32 from string CLI value
            match args.value_of("batch_size")
                    .unwrap()
                    .parse::<usize>() {
                        Ok(num) => num,
                        Err(e) => {
                            eprintln!("Cannot parse provided batch size '{}'\r\nUsing default!", e);
                            DEFAULT_BATCH_SIZE
                        }
                    }
        // Default condition
        } else {
            DEFAULT_BATCH_SIZE
        };

        eprintln!("Using batch size of {}", batch_size);

        Self {
            input_domain_file: String::from(args.value_of("input_domain_file").unwrap()),
            output_dmarc_file: String::from(args.value_of("output_dmarc_file").unwrap()),
            batch_size
        }
    }
}

#[macro_export]
macro_rules! fmt_err {
    ($($arg:tt)*) => {{
        let res = std::fmt::format(format_args!($($arg)*));

        format!(
            "[-] Error:\n\t- Cause: {}\n\t- Line: {}\n\t- File: {}\n\n",
            res,
            line!(),
            file!(),
        )
    }}
}

macro_rules! print_err {
    ($($arg:tt)*) => {{
        let res = fmt_err!($($arg)*);
        eprintln!("{}", res);
    }}
}
