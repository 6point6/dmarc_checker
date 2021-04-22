#[cfg(test)]
use pretty_assertions::assert_eq;
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

const CNAME_RECORD: &str = "CNAME";
const TXT_RECORD: &str = "TXT";
const OTHER_RECORD: &str = "OTHER";

const YES: &str = "Yes";
const NO: &str = "No";

const ERR_FLAG_NOT_PRESENT: &str = "Flag not present";
const ERR_MISSING_V_OR_P_FLAG: &str = "V or P flag missing";
const ERR_FIRST_FLAG_NOT_V: &str = "First flag is not V";
const ERR_SECOND_FLAG_NOT_P: &str = "Second flag is not P";

const ERR_P_FLAG_MISSING_AND_SP_NOT_SET: &str = "Missing p flag and sp not set";
const ERR_P_FLAG_MISSING: &str = "P flag missing";
const ERR_IGNORE_SUBDOMAIN_DMARC_FAILS: &str = "sp=none: Ignores subdomain DMARC fails";
const ERR_PERMITS_SUBDOMAIN_SPOOFING: &str =
    "p=reject, sp=none: Ignores subdomain DMARC fails and permits subdomain spoofing";

#[derive(Debug, Deserialize)]
pub struct DomainName(pub String);

#[derive(Serialize)]
pub struct ParseResult {
    pub domain_name: String,
}

#[derive(Debug)]
pub enum StringRecords {
    Single(DmarcRecordType),
    Multiple(Vec<DmarcRecordType>),
}

#[derive(Debug)]
pub enum DmarcRecordType {
    Cname(Option<String>),
    Txt(Option<String>),
    Other,
}

impl DmarcRecordType {
    fn new(r: &Record) -> Self {
        match r.rdata().to_record_type() {
            RecordType::CNAME => Self::Cname(
                r.rdata()
                    .as_cname()
                    .and_then(|cname| Some(cname.to_string())),
            ),
            RecordType::TXT => Self::Txt(
                r.rdata()
                    .as_txt()
                    .and_then(|txt_data| Some(txt_data.to_string())),
            ),
            _ => Self::Other,
        }
    }
}

impl StringRecords {
    pub fn new(r: &[Record]) -> Option<Self> {
        match r.len() {
            0 => None,
            1 => Some(Self::Single(DmarcRecordType::new(&r[0]))),
            n @ _ => {
                let mut dmarc_records: Vec<DmarcRecordType> = Vec::with_capacity(n);

                for i in r.iter() {
                    dmarc_records.push(DmarcRecordType::new(i))
                }

                Some(Self::Multiple(dmarc_records))
            }
        }
    }
}

#[derive(Debug, PartialEq)]
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

#[derive(Debug, PartialEq)]
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
        match p_tag_val.to_lowercase().as_str() {
            TAG_NONE => Self::None,
            TAG_QURANTINE => Self::Qurantine,
            TAG_REJECT => Self::Reject,
            _ => Self::Invalid(p_tag_val.to_string()),
        }
    }
}

#[derive(Debug, PartialEq)]
struct DmarcEntry<'a> {
    tag: &'a str,
    val: &'a str,
}

impl<'a> DmarcEntry<'a> {
    pub fn new(tag: &'a str, val: &'a str) -> Self {
        Self { tag, val }
    }
}
#[derive(Debug, Default, PartialEq, Serialize)]
pub struct Dmarc {
    domain_name: String,
    returned_record: String,
    record_type: String,
    v: Option<DmarcVersion>,
    p: Option<TagAction>,
    pct: Option<String>, // TODO: Should change this to a u8 later
    rua: Option<String>,
    ruf: Option<String>,
    sp: Option<TagAction>,
    adkim: Option<String>,
    aspf: Option<String>,
    others: Option<String>,
    invalid_flags: Option<String>,
    config_v_p_order: Option<String>,
    config_v: Option<String>,
    config_p: Option<String>,
    config_pct: Option<String>,
    config_sp: Option<String>,
    raw_data: String,
}

impl Dmarc {
    pub fn new(domain_name: &str, dmarc_record: Option<DmarcRecordType>) -> Self {
        let mut dmarc = Self::default();
        dmarc.domain_name = domain_name.to_string();

        let dmarc_parsed = match dmarc_record {
            Some(ref r) => match r {
                DmarcRecordType::Cname(opt_url) => {
                    dmarc.record_type = CNAME_RECORD.to_string();
                    dmarc.returned_record = YES.to_string();
                    if let Some(url) = opt_url {
                        dmarc.raw_data = url.to_string();
                    }
                    return dmarc;
                }
                DmarcRecordType::Txt(ref opt_txt) => match opt_txt {
                    Some(ref txt) => {
                        dmarc.record_type = TXT_RECORD.to_string();
                        dmarc.returned_record = YES.to_string();
                        DmarcParsed::new(txt)
                    }
                    None => {
                        dmarc.record_type = TXT_RECORD.to_string();
                        dmarc.returned_record = YES.to_string();
                        return dmarc;
                    }
                },
                DmarcRecordType::Other => {
                    dmarc.record_type = OTHER_RECORD.to_string();
                    dmarc.returned_record = YES.to_string();
                    return dmarc;
                }
            },
            None => {
                dmarc.returned_record = NO.to_string();
                return dmarc;
            }
        };

        let mut dmarc_entries = match dmarc_parsed.dmarc_entries {
            Some(de) => de,
            None => {
                dmarc.invalid_flags = dmarc_parsed.invalid_entries;
                dmarc.raw_data = dmarc_parsed.raw_txt;
                return dmarc;
            }
        };

        let config_v_p_order = Self::check_v_and_p_order(&dmarc_entries).to_string();

        dmarc.v = match_tag(V_TAG, &mut dmarc_entries)
            .and_then(|v_entry| Some(DmarcVersion::to_ver(v_entry.val)));

        dmarc.p = match_tag(P_TAG, &mut dmarc_entries)
            .and_then(|p_entry| Some(TagAction::to_enum(p_entry.val)));

        dmarc.pct = match_tag(PCT_TAG, &mut dmarc_entries)
            .and_then(|pct_entry| Some(pct_entry.val.to_string()));

        dmarc.rua = match_tag(RUA_TAG, &mut dmarc_entries)
            .and_then(|rua_entry| Some(rua_entry.val.to_string()));

        dmarc.ruf = match_tag(RUF_TAG, &mut dmarc_entries)
            .and_then(|ruf_entry| Some(ruf_entry.val.to_string()));

        dmarc.sp = match_tag(SP_TAG, &mut dmarc_entries)
            .and_then(|sp_entry| Some(TagAction::to_enum(sp_entry.val)));

        dmarc.adkim = match_tag(ADKIM_TAG, &mut dmarc_entries)
            .and_then(|adkim_entry| Some(adkim_entry.val.to_string()));

        dmarc.aspf = match_tag(ASPF_TAG, &mut dmarc_entries)
            .and_then(|aspf_entry| Some(aspf_entry.val.to_string()));

        dmarc.others = match dmarc_entries.is_empty() {
            true => None,
            false => {
                let mut others_tmp = String::new();
                for e in dmarc_entries {
                    others_tmp.push_str(&format!("{}={} ", e.tag, e.val));
                }

                Some(others_tmp)
            }
        };

        dmarc.invalid_flags = dmarc_parsed.invalid_entries;
        dmarc.config_v_p_order = Some(config_v_p_order);
        dmarc.config_v = Some(dmarc.check_v().to_string());
        dmarc.config_p = Some(dmarc.check_p().to_string());
        dmarc.config_pct = Some(dmarc.check_pct().to_string());
        dmarc.config_sp = Some(dmarc.check_sp().to_string());
        dmarc.raw_data = dmarc_parsed.raw_txt;

        dmarc
    }

    fn check_v(&self) -> DmarcFieldResult {
        match &self.v {
            Some(ver) => match ver {
                DmarcVersion::Dmarc1 => DmarcFieldResult::ValidConfig,
                DmarcVersion::Invalid(s) => DmarcFieldResult::InvalidConfig(s.clone()),
            },
            None => DmarcFieldResult::InvalidConfig(ERR_FLAG_NOT_PRESENT.to_string()),
        }
    }

    fn check_p(&self) -> DmarcFieldResult {
        match &self.p {
            Some(v) => match v {
                TagAction::Invalid(s) => DmarcFieldResult::InvalidConfig(s.clone()),
                TagAction::None => DmarcFieldResult::VeryBadConfig(TAG_NONE.to_string()),
                _ => DmarcFieldResult::ValidConfig,
            },
            None => DmarcFieldResult::InvalidConfig(ERR_FLAG_NOT_PRESENT.to_string()),
        }
    }

    fn check_pct(&self) -> DmarcFieldResult {
        match &self.pct {
            Some(p) => match &p.parse::<u8>() {
                Ok(n) => {
                    if *n < 25 {
                        DmarcFieldResult::VeryBadConfig(p.clone())
                    } else if *n < 100 {
                        DmarcFieldResult::BadConfig(p.clone())
                    } else if *n > 100 {
                        DmarcFieldResult::InvalidConfig(p.clone())
                    } else {
                        DmarcFieldResult::ValidConfig
                    }
                }
                Err(_) => DmarcFieldResult::InvalidConfig(format!(
                    "{} <- {}",
                    p,
                    "Is not a number".to_string()
                )),
            },
            None => DmarcFieldResult::ValidConfig,
        }
    }

    fn check_v_and_p_order(dmarc_entries: &Vec<DmarcEntry>) -> DmarcFieldResult {
        if dmarc_entries.len() < 2 {
            return DmarcFieldResult::InvalidConfig(ERR_MISSING_V_OR_P_FLAG.to_string());
        }

        let (v, p) = (&dmarc_entries[0], &dmarc_entries[1]);

        if v.tag != V_TAG {
            return DmarcFieldResult::InvalidConfig(ERR_FIRST_FLAG_NOT_V.to_string());
        }

        if p.tag != P_TAG {
            return DmarcFieldResult::InvalidConfig(ERR_SECOND_FLAG_NOT_P.to_string());
        }

        DmarcFieldResult::ValidConfig
    }

    fn check_sp(&self) -> DmarcFieldResult {
        let sp = match &self.sp {
            Some(sp) => sp,
            None => match &self.p {
                Some(p) => p,
                None => {
                    return DmarcFieldResult::InvalidConfig(
                        ERR_P_FLAG_MISSING_AND_SP_NOT_SET.to_string(),
                    )
                }
            },
        };

        match sp {
            TagAction::None => match &self.p {
                Some(p) => match p {
                    TagAction::Reject => {
                        DmarcFieldResult::VeryBadConfig(ERR_PERMITS_SUBDOMAIN_SPOOFING.to_string())
                    }
                    _ => DmarcFieldResult::BadConfig(ERR_IGNORE_SUBDOMAIN_DMARC_FAILS.to_string()),
                },
                None => DmarcFieldResult::InvalidConfig(ERR_P_FLAG_MISSING.to_string()),
            },
            _ => DmarcFieldResult::ValidConfig,
        }
    }
}

#[derive(Debug, PartialEq)]
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

        if entry_iter.clone().count() > 1 {
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

#[derive(Debug, PartialEq)]
pub enum DmarcFieldResult {
    ValidConfig,
    BadConfig(String),
    VeryBadConfig(String),
    InvalidConfig(String),
    Empty,
}

impl ToString for DmarcFieldResult {
    fn to_string(&self) -> String {
        match self {
            Self::ValidConfig => "Valid".to_string(),
            Self::BadConfig(s) => format!("Bad: {}", s),
            Self::VeryBadConfig(s) => format!("Very bad: {}", s),
            Self::InvalidConfig(s) => format!("Invalid: {}", s),
            Self::Empty => "Empty".to_string(),
        }
    }
}

#[test]
fn dmarc_parsed_new() {
    assert_eq!(
        DmarcParsed::new(&"".to_string()),
        DmarcParsed {
            dmarc_entries: None,
            invalid_entries: None,
            raw_txt: "\"\"".to_string()
        }
    );

    let invalid_entry = format!("{}={} {}={}", V_TAG, DMARC1, P_TAG, TAG_NONE);
    assert_eq!(
        DmarcParsed::new(&invalid_entry),
        DmarcParsed {
            dmarc_entries: None,
            invalid_entries: None,
            raw_txt: format!("\"{}\"", invalid_entry),
        }
    );

    let invalid_tag = "p%fsa";
    let invalid_entry = format!("{}={};{};", V_TAG, DMARC1, invalid_tag);
    assert_eq!(
        DmarcParsed::new(&invalid_entry),
        DmarcParsed {
            dmarc_entries: Some(vec![DmarcEntry::new(V_TAG, DMARC1)]),
            invalid_entries: Some(invalid_tag.to_string()),
            raw_txt: format!("\"{}\"", invalid_entry),
        }
    );

    let valid_entry = format!("{}={}; {}={};", V_TAG, DMARC1, P_TAG, TAG_NONE);
    assert_eq!(
        DmarcParsed::new(&valid_entry),
        DmarcParsed {
            dmarc_entries: Some(vec![
                DmarcEntry::new(V_TAG, DMARC1),
                DmarcEntry::new(P_TAG, TAG_NONE)
            ]),
            invalid_entries: None,
            raw_txt: format!("\"{}\"", valid_entry),
        }
    );
}

// Tests
#[test]
fn dmarc_version_to_ver() {
    assert_eq!(
        DmarcVersion::Invalid("blah".to_string()),
        DmarcVersion::to_ver("blah")
    );

    assert_eq!(
        DmarcVersion::Invalid("dmarc1".to_string()),
        DmarcVersion::to_ver("dmarc1")
    );

    assert_eq!(DmarcVersion::Dmarc1, DmarcVersion::to_ver(DMARC1));
}

#[test]
fn dmarc_check_v() {
    let mut dmarc = Dmarc::default();

    dmarc.v = None;
    assert_eq!(
        DmarcFieldResult::InvalidConfig(ERR_FLAG_NOT_PRESENT.to_string()),
        dmarc.check_v()
    );

    let invalid_ver = "smark";
    dmarc.v = Some(DmarcVersion::Invalid(invalid_ver.to_string()));
    assert_eq!(
        DmarcFieldResult::InvalidConfig(invalid_ver.to_string()),
        dmarc.check_v()
    );

    dmarc.v = Some(DmarcVersion::Dmarc1);
    assert_eq!(DmarcFieldResult::ValidConfig, dmarc.check_v());
}

#[test]
fn dmarc_check_p() {
    let mut dmarc = Dmarc::default();

    dmarc.p = None;
    assert_eq!(
        DmarcFieldResult::InvalidConfig(ERR_FLAG_NOT_PRESENT.to_string()),
        dmarc.check_p()
    );

    dmarc.p = Some(TagAction::None);
    assert_eq!(
        DmarcFieldResult::VeryBadConfig(TAG_NONE.to_string()),
        dmarc.check_p()
    );

    dmarc.p = Some(TagAction::Qurantine);
    assert_eq!(DmarcFieldResult::ValidConfig, dmarc.check_p());

    dmarc.p = Some(TagAction::Reject);
    assert_eq!(DmarcFieldResult::ValidConfig, dmarc.check_p());
}

#[test]
fn dmarc_check_pct() {
    let mut dmarc = Dmarc::default();

    dmarc.pct = None;
    assert_eq!(DmarcFieldResult::ValidConfig, dmarc.check_pct());

    let zero_pct = "0".to_string();
    let twenty_six_pct = "26".to_string();
    let one_hundred_pct = "100".to_string();
    let two_hundred_pct = "200".to_string();

    dmarc.pct = Some(zero_pct.clone());
    assert_eq!(DmarcFieldResult::VeryBadConfig(zero_pct), dmarc.check_pct());

    dmarc.pct = Some(twenty_six_pct.clone());
    assert_eq!(
        DmarcFieldResult::BadConfig(twenty_six_pct),
        dmarc.check_pct()
    );

    dmarc.pct = Some(one_hundred_pct.clone());
    assert_eq!(DmarcFieldResult::ValidConfig, dmarc.check_pct());

    dmarc.pct = Some(two_hundred_pct.clone());
    assert_eq!(
        DmarcFieldResult::InvalidConfig(two_hundred_pct),
        dmarc.check_pct()
    );
}

#[test]
fn dmarc_check_sp() {
    let mut dmarc = Dmarc::default();

    dmarc.p = None;
    dmarc.sp = None;
    assert_eq!(
        DmarcFieldResult::InvalidConfig(ERR_P_FLAG_MISSING_AND_SP_NOT_SET.to_string()),
        dmarc.check_sp()
    );

    dmarc.sp = Some(TagAction::None);
    assert_eq!(
        DmarcFieldResult::InvalidConfig(ERR_P_FLAG_MISSING.to_string()),
        dmarc.check_sp()
    );

    dmarc.p = Some(TagAction::None);
    assert_eq!(
        DmarcFieldResult::BadConfig(ERR_IGNORE_SUBDOMAIN_DMARC_FAILS.to_string()),
        dmarc.check_sp()
    );

    dmarc.p = Some(TagAction::Reject);
    assert_eq!(
        DmarcFieldResult::VeryBadConfig(ERR_PERMITS_SUBDOMAIN_SPOOFING.to_string()),
        dmarc.check_sp()
    );

    dmarc.p = Some(TagAction::Qurantine);
    assert_eq!(
        DmarcFieldResult::BadConfig(ERR_IGNORE_SUBDOMAIN_DMARC_FAILS.to_string()),
        dmarc.check_sp()
    );

    dmarc.sp = Some(TagAction::Reject);
    assert_eq!(DmarcFieldResult::ValidConfig, dmarc.check_sp());

    dmarc.sp = Some(TagAction::Qurantine);
    assert_eq!(DmarcFieldResult::ValidConfig, dmarc.check_sp());
}

#[test]
fn dmarc_check_v_and_p_order() {
    let mut dmarc_entries: Vec<DmarcEntry> = Vec::new();

    assert_eq!(
        Dmarc::check_v_and_p_order(&dmarc_entries),
        DmarcFieldResult::InvalidConfig(ERR_MISSING_V_OR_P_FLAG.to_string()),
    );

    dmarc_entries.push(DmarcEntry::new("A", DMARC1));
    assert_eq!(
        Dmarc::check_v_and_p_order(&dmarc_entries),
        DmarcFieldResult::InvalidConfig(ERR_MISSING_V_OR_P_FLAG.to_string()),
    );

    dmarc_entries.push(DmarcEntry::new("B", TAG_NONE));
    assert_eq!(
        Dmarc::check_v_and_p_order(&dmarc_entries),
        DmarcFieldResult::InvalidConfig(ERR_FIRST_FLAG_NOT_V.to_string()),
    );

    dmarc_entries[0] = DmarcEntry::new(V_TAG, DMARC1);
    assert_eq!(
        Dmarc::check_v_and_p_order(&dmarc_entries),
        DmarcFieldResult::InvalidConfig(ERR_SECOND_FLAG_NOT_P.to_string()),
    );

    dmarc_entries[1] = DmarcEntry::new(P_TAG, TAG_NONE);
    assert_eq!(
        Dmarc::check_v_and_p_order(&dmarc_entries),
        DmarcFieldResult::ValidConfig,
    );
}

#[test]
fn tag_action_to_enum() {
    let invalid_tag = "Destroy";
    assert_eq!(
        TagAction::to_enum(invalid_tag),
        TagAction::Invalid(invalid_tag.to_string())
    );

    assert_eq!(TagAction::to_enum(TAG_NONE), TagAction::None);
    assert_eq!(TagAction::to_enum(TAG_QURANTINE), TagAction::Qurantine);
    assert_eq!(TagAction::to_enum(TAG_REJECT), TagAction::Reject);
}

#[test]
fn dmarc_new() {
    let test_domain = "google.com";
    let valid = "Valid";

    let dmarc = Dmarc::new(test_domain, None);
    let mut dmarc_compare = Dmarc::default();

    dmarc_compare.domain_name = test_domain.to_string();
    dmarc_compare.returned_record = NO.to_string();
    assert_eq!(dmarc, dmarc_compare);

    let raw_cname = "microsoft.com".to_string();
    let cname_record = DmarcRecordType::Cname(Some(raw_cname.clone()));
    let dmarc = Dmarc::new(test_domain, Some(cname_record));
    dmarc_compare.returned_record = YES.to_string();
    dmarc_compare.record_type = CNAME_RECORD.to_string();
    dmarc_compare.raw_data = raw_cname.clone();
    assert_eq!(dmarc, dmarc_compare);

    let cname_record = DmarcRecordType::Cname(None);
    let dmarc = Dmarc::new(test_domain, Some(cname_record));
    dmarc_compare.returned_record = YES.to_string();
    dmarc_compare.record_type = CNAME_RECORD.to_string();
    dmarc_compare.raw_data = "".to_string();
    assert_eq!(dmarc, dmarc_compare);

    let txt_record = DmarcRecordType::Txt(None);
    let dmarc = Dmarc::new(test_domain, Some(txt_record));
    dmarc_compare.returned_record = YES.to_string();
    dmarc_compare.record_type = TXT_RECORD.to_string();
    dmarc_compare.raw_data = "".to_string();
    assert_eq!(dmarc, dmarc_compare);

    let txt_record = DmarcRecordType::Other;
    let dmarc = Dmarc::new(test_domain, Some(txt_record));
    dmarc_compare.returned_record = YES.to_string();
    dmarc_compare.record_type = OTHER_RECORD.to_string();
    dmarc_compare.raw_data = "".to_string();
    assert_eq!(dmarc, dmarc_compare);

    let raw_txt = format!("{}={}; {}={};", V_TAG, DMARC1, P_TAG, TAG_NONE);
    let txt_record = DmarcRecordType::Txt(Some(raw_txt.clone()));
    let dmarc = Dmarc::new(test_domain, Some(txt_record));
    dmarc_compare.returned_record = YES.to_string();
    dmarc_compare.record_type = TXT_RECORD.to_string();
    dmarc_compare.v = Some(DmarcVersion::Dmarc1);
    dmarc_compare.p = Some(TagAction::None);
    dmarc_compare.config_v_p_order = Some(valid.to_string());
    dmarc_compare.config_v = Some(dmarc.check_v().to_string());
    dmarc_compare.config_p = Some(dmarc.check_p().to_string());
    dmarc_compare.config_pct = Some(dmarc.check_pct().to_string());
    dmarc_compare.config_sp = Some(dmarc.check_sp().to_string());
    dmarc_compare.raw_data = format!("\"{}\"", raw_txt);
    assert_eq!(dmarc, dmarc_compare);
}
