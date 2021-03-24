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
const TAG_QURANTINE: &str = "qurantine";
const TAG_REJECT: &str = "reject";
const TAG_INVALID: &str = "INVALID";

#[derive(Debug)]
enum DmarcVersion {
    Dmarc1,
    Invalid(String),
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

    fn to_string(&self) -> String {
        match self {
            Self::None => TAG_NONE.to_string(),
            Self::Qurantine => TAG_QURANTINE.to_string(),
            Self::Reject => TAG_REJECT.to_string(),
            Self::Invalid(_) => TAG_INVALID.to_string(),
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
#[derive(Debug)]
pub struct Dmarc {
    v: Option<DmarcVersion>,
    p: Option<TagAction>,
    pct: Option<String>, // TODO: Should change this to a u8 later
    rua: Option<String>,
    ruf: Option<String>,
    sp: Option<TagAction>,
    adkim: Option<String>,
    aspf: Option<String>,
    others: Option<Vec<String>>,
    invalid: Option<Vec<String>>,
    raw_data: String,
}

impl Dmarc {
    pub fn new(dmarc_parsed: DmarcParsed) -> Self {
        if dmarc_parsed.dmarc_entries.is_none() {
            return Self {
                v: None,
                p: None,
                pct: None,
                rua: None,
                ruf: None,
                sp: None,
                adkim: None,
                aspf: None,
                others: None,
                invalid: dmarc_parsed.invalid_entries,
                raw_data: dmarc_parsed.raw_txt,
            };
        }

        let mut dmarc_entries = dmarc_parsed.dmarc_entries.unwrap();

        Self {
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
                        let mut others_tmp: Vec<String> =
                            Vec::with_capacity(dmarc_entries.iter().count());
                        for e in dmarc_entries {
                            others_tmp.push(format!("{}={}", e.tag, e.val));
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
pub struct DmarcParsed<'a> {
    dmarc_entries: Option<Vec<DmarcEntry<'a>>>,
    invalid_entries: Option<Vec<String>>,
    raw_txt: String,
}

impl<'a> DmarcParsed<'a> {
    pub fn new(txt: &'a String) -> Self {
        if txt.is_empty() {
            return Self {
                dmarc_entries: None,
                invalid_entries: None,
                raw_txt: txt.clone(),
            };
        }

        let mut dmarc_entries: Vec<DmarcEntry> = Vec::new();
        let mut invalid_entries = Vec::new();
        let entry_iter = txt.split(';');

        for e in entry_iter {
            match e.find('=') {
                Some(idx) => dmarc_entries.push(DmarcEntry::new(
                    &e[0..idx].trim(),
                    &e[idx + 1..e.len()].trim(),
                )),
                None => {
                    if !e.is_empty() {
                        invalid_entries.push(e.to_string())
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
            raw_txt: txt.clone(),
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
    sp: DmarcFieldResult,
}

impl DmarcCheck {
    /*
    pub fn new(dmarc: &Dmarc) -> Self {
        Self {}
    }*/

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
