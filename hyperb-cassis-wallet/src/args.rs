//! The arguments of an action: its payload, over the fields of the draft
//! it names with `draft` (the signal `hw.<draft>`).

use hypereffect::{Action, Map, Value};

pub struct Args(Map<String, Value>);

impl Args {
    pub fn of(action: &Action) -> Self {
        let mut payload = match &action.payload {
            Some(Value::Object(payload)) => payload.clone(),
            _ => Map::new(),
        };
        let mut args = payload
            .remove("draft")
            .and_then(|draft| {
                action
                    .signal(&format!("hw.{}", draft.as_str()?))?
                    .as_object()
                    .cloned()
            })
            .unwrap_or_default();
        args.extend(payload);
        Args(args)
    }

    /// A field as trimmed text, empty if it is not there.
    pub fn text(&self, key: &str) -> String {
        match self.0.get(key) {
            Some(Value::String(text)) => text.trim().to_string(),
            Some(Value::Number(n)) => n.to_string(),
            _ => String::new(),
        }
    }

    pub fn required(&self, key: &str) -> Result<String, String> {
        match self.text(key) {
            text if text.is_empty() => Err(format!("{key} is required")),
            text => Ok(text),
        }
    }

    /// An amount of sats: a whole number above zero.
    pub fn sats(&self, key: &str) -> Result<u64, String> {
        let bad = || format!("{key} must be a whole number of sats above zero");
        let number = match self.0.get(key) {
            Some(Value::Number(n)) => n.as_f64().filter(|n| n.fract() == 0.0).map(|n| n as u64),
            Some(Value::String(text)) => text.trim().parse().ok(),
            _ => None,
        };
        number.filter(|n| *n > 0).ok_or_else(bad)
    }
}
