use serde::{Deserialize, Serialize, Serializer};
use trust_dns_client::rr::{Record, RecordType};

const DMARC1: &str = "DMARC1";

const V_TAG: &str = "v";
const P_TAG: &str = "p";
const PCT_TAG: &str = "pct";
const RUA_TAG: &str = "rua";
const RUF_TAG: &str = "ruf";
const SP_TAG: &str = "sp";
const ADKIM_TAG: &str = "adkim";
const ASPF_TAG: &str = "aspf";

const TAG_NONE: &str = "none";
const TAG_QURANTINE: &str = "quarantine";
const TAG_REJECT: &str = "reject";
const TAG_INVALID: &str = "INVALID";

#[derive(Debug, Deserialize)]
pub struct DomainName(pub String);

#[derive(Serialize)]
pub struct ParseResult {
    pub domain_name: String,
}

pub enum StringRecords {
    Single(Option<String>),
    Multiple(Vec<Option<String>>),
}

impl StringRecords {
    pub fn new(r: &[Record]) -> Option<Self> {
        match r.len() {
            0 => None,
            1 => Some(Self::Single(record_to_string(&r[0]))),
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

#[derive(Debug)]
enum DmarcVersion {
    Dmarc1,
    Invalid(String),
}

impl Serialize for DmarcVersion {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match *self {
            Self::Dmarc1 => serializer.serialize_unit_variant(DMARC1, 0, DMARC1),
            Self::Invalid(ref s) => {
                serializer.serialize_newtype_variant("Invalid", 1, "Invalid", s)
            }
        }
    }
}

impl DmarcVersion {
    fn to_ver(v_tag_val: &str) -> Self {
        match v_tag_val {
            DMARC1 => Self::Dmarc1,
            _ => Self::Invalid(v_tag_val.to_string()),
        }
    }
}

fn match_tag<'a>(tag: &str, dmarc_entries: &'a mut Vec<DmarcEntry>) -> Option<DmarcEntry<'a>> {
    for (i, e) in dmarc_entries.iter_mut().enumerate() {
        if e.tag == tag {
            return Some(dmarc_entries.remove(i));
        }
    }

    return None;
}

#[derive(Debug)]
enum TagAction {
    None,
    Qurantine,
    Reject,
    Invalid(String),
}

impl Serialize for TagAction {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match *self {
            Self::None => serializer.serialize_unit_variant("None", 0, TAG_NONE),
            Self::Qurantine => serializer.serialize_unit_variant("Quarantine", 1, TAG_QURANTINE),
            Self::Reject => serializer.serialize_unit_variant("Reject", 2, TAG_REJECT),
            Self::Invalid(ref s) => {
                serializer.serialize_newtype_variant("Invalid", 3, "Invalid", s)
            }
        }
    }
}

impl TagAction {
    fn to_enum(p_tag_val: &str) -> Self {
        match p_tag_val {
            // Should this be case insensitive?
            TAG_NONE => Self::None,
            TAG_QURANTINE => Self::Qurantine,
            TAG_REJECT => Self::Reject,
            _ => Self::Invalid(p_tag_val.to_string()),
        }
    }
}

#[derive(Debug)]
struct DmarcEntry<'a> {
    tag: &'a str,
    val: &'a str,
}

impl<'a> DmarcEntry<'a> {
    pub fn new(tag: &'a str, val: &'a str) -> Self {
        Self { tag, val }
    }
}
#[derive(Debug, Serialize)]
pub struct Dmarc {
    domain_name: String,
    v: Option<DmarcVersion>,
    p: Option<TagAction>,
    pct: Option<String>, // TODO: Should change this to a u8 later
    rua: Option<String>,
    ruf: Option<String>,
    sp: Option<TagAction>,
    adkim: Option<String>,
    aspf: Option<String>,
    others: Option<String>,
    invalid: Option<String>,
    raw_data: String,
}

impl Default for Dmarc {
    fn default() -> Self {
        Self {
            domain_name: Default::default(),
            v: Default::default(),
            p: Default::default(),
            pct: Default::default(),
            rua: Default::default(),
            ruf: Default::default(),
            sp: Default::default(),
            adkim: Default::default(),
            aspf: Default::default(),
            others: Default::default(),
            invalid: Default::default(),
            raw_data: Default::default(),
        }
    }
}

impl Dmarc {
    pub fn new(domain_name: &str, txt: Option<String>) -> Self {
        let dmarc_parsed = match txt {
            Some(ref r) => DmarcParsed::new(r),
            None => {
                let mut res = Self::default();
                res.domain_name = domain_name.to_string();
                return res;
            }
        };

        if dmarc_parsed.dmarc_entries.is_none() {
            let mut res = Self::default();
            res.domain_name = domain_name.to_string();
            res.invalid = dmarc_parsed.invalid_entries;
            res.raw_data = dmarc_parsed.raw_txt;
            return res;
        }

        let mut dmarc_entries = dmarc_parsed.dmarc_entries.unwrap();

        Self {
            domain_name: domain_name.to_string(),
            v: match_tag(V_TAG, &mut dmarc_entries)
                .and_then(|v_entry| Some(DmarcVersion::to_ver(v_entry.val))),
            p: match_tag(P_TAG, &mut dmarc_entries)
                .and_then(|p_entry| Some(TagAction::to_enum(p_entry.val))),
            pct: match_tag(PCT_TAG, &mut dmarc_entries)
                .and_then(|pct_entry| Some(pct_entry.val.to_string())),
            rua: match_tag(RUA_TAG, &mut dmarc_entries)
                .and_then(|rua_entry| Some(rua_entry.val.to_string())),
            ruf: match_tag(RUF_TAG, &mut dmarc_entries)
                .and_then(|ruf_entry| Some(ruf_entry.val.to_string())),
            sp: match_tag(SP_TAG, &mut dmarc_entries)
                .and_then(|sp_entry| Some(TagAction::to_enum(sp_entry.val))),
            adkim: match_tag(ADKIM_TAG, &mut dmarc_entries)
                .and_then(|adkim_entry| Some(adkim_entry.val.to_string())),
            aspf: match_tag(ASPF_TAG, &mut dmarc_entries)
                .and_then(|aspf_entry| Some(aspf_entry.val.to_string())),
            others: {
                match dmarc_entries.is_empty() {
                    true => None,
                    false => {
                        let mut others_tmp = String::new();
                        for e in dmarc_entries {
                            others_tmp.push_str(&format!("{}={} ", e.tag, e.val));
                        }

                        Some(others_tmp)
                    }
                }
            },
            invalid: dmarc_parsed.invalid_entries,
            raw_data: dmarc_parsed.raw_txt,
        }
    }
}

#[derive(Debug)]
struct DmarcParsed<'a> {
    dmarc_entries: Option<Vec<DmarcEntry<'a>>>,
    invalid_entries: Option<String>,
    raw_txt: String,
}

impl<'a> DmarcParsed<'a> {
    fn new(txt: &'a String) -> Self {
        let raw_txt_quoted = format!("\"{}\"", txt.clone());

        if txt.is_empty() {
            return Self {
                dmarc_entries: None,
                invalid_entries: None,
                raw_txt: raw_txt_quoted,
            };
        }

        let mut dmarc_entries: Vec<DmarcEntry> = Vec::new();
        let mut invalid_entries = String::new();
        let entry_iter = txt.split(';');

        for e in entry_iter {
            match e.find('=') {
                Some(idx) => dmarc_entries.push(DmarcEntry::new(
                    &e[0..idx].trim(),
                    &e[idx + 1..e.len()].trim(),
                )),
                None => {
                    if !e.is_empty() {
                        invalid_entries.push_str(e)
                    }
                }
            }
        }

        let invalid_entries_opt = match invalid_entries.is_empty() {
            true => None,
            false => Some(invalid_entries),
        };

        let dmarc_entries_opt = match dmarc_entries.is_empty() {
            true => None,
            false => Some(dmarc_entries),
        };

        Self {
            dmarc_entries: dmarc_entries_opt,
            invalid_entries: invalid_entries_opt,
            raw_txt: raw_txt_quoted,
        }
    }
}

enum DmarcFieldResult {
    ValidConfig,
    BadConfig(String),
    Invalid(String),
    NonExistant,
}

pub struct DmarcCheck {
    v: DmarcFieldResult,
    p: DmarcFieldResult,
    v_and_p: DmarcFieldResult,
    sp: DmarcFieldResult,
}

impl DmarcCheck {
    fn check_v(dmarc: &Dmarc) -> DmarcFieldResult {
        match &dmarc.v {
            Some(v) => match v {
                DmarcVersion::Dmarc1 => DmarcFieldResult::ValidConfig,
                DmarcVersion::Invalid(s) => DmarcFieldResult::Invalid(s.clone()),
            },
            None => DmarcFieldResult::NonExistant,
        }
    }

    fn check_p(dmarc: &Dmarc) -> DmarcFieldResult {
        match &dmarc.p {
            Some(v) => match v {
                TagAction::Invalid(s) => DmarcFieldResult::Invalid(s.clone()),
                _ => DmarcFieldResult::ValidConfig,
            },
            None => DmarcFieldResult::NonExistant,
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
