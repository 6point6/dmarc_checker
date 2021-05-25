## DMARC Checker
DMARC Checker is a Rust powered asynchronous DMARC lookup engine. It takes a list of domains as its input and generates a CSV output of the parsed DMARC records.

For individual domains, it's simpler to use the dig utility, e.g. `dig dmarc.example.org TXT +short`. 

However, unlike dig, DMARC Check is fast. It averages around 500 lookups per second and can parse the top 1 million domains within 30 minutes.

### Identifying Vulnerable Domains
Please see the Wiki located here.

### Build
DMARC Checker is built in Rust, meaning you can compile it using the Cargo engine on Rust supported platforms. Within the Git directory, use the following commands.

`cargo build` for debug versions, and
`cargo build --release` for release versions.

### Usage
Provide a file of domains with the `-i' flag, and specify a file to output for the `-o' flag.

**domain_list.txt**
```
google.com
cia.gov
nca.gov.uk
dwp.gov.uk
gmail.com
```

`./dmarc_checker -i domain_list.txt -o domain_output.csv`

OR

`cargo run -- -i domain_list.txt -o domain_output.csv`

The tool parses batches of 50,000 domains — it prevents I/O kernel problems — and writes results to the `domain_output.csv` file.

You can increase or decrease the batch size by specifying `-b`.

`./dmarc_checker -i domain_list.txt -o domain_output.csv -b 100`

OR

`cargo run -- -i domain_list.txt -o domain_output.csv -b 100`

#### Domain Examples
We've tested the DMARC Checker against the following list of domains.
- [UK Government](https://assets.publishing.service.gov.uk/government/uploads/system/uploads/attachment_data/file/842955/List_of_gov.uk_domain_names_as_at_28_Oct_2019.csv/preview)
- [USA Government](https://github.com/cisagov/dotgov-data)
- [Majestic Top 1 Million](https://blog.majestic.com/development/majestic-million-csv-daily)

The repository contains a parse list of the above domains and their results from DMARC Checker. Note that this was the current data as of 26/04/2020.

### Notes
Some DMARC records specify CNAME domains. We list these records with CNAME entries but DO NOT recursively check the CNAME tree.

We felt that the effort required to write the check, especially asynchronously, wasn't worth the time as not many DMARC domains use CNAME records.

We've also added helpful hints where DMARC records are empty if a domain is vulnerable to subdomain spoofing only and inconsistencies arise with the percentage specifier.
