//! The arguments of admin actions.

use hypereffect::{Action, Map, Value};

/// An action's payload, over the fields of the draft it names with
/// `draft` (the signal `d.<draft>`). Fields come as JSON values or as
/// the strings inputs hold: absent means unchanged, and `null` or empty
/// unsets what is optional.
pub struct Args(pub Map<String, Value>);

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
                    .signal(&format!("d.{}", draft.as_str()?))?
                    .as_object()
                    .cloned()
            })
            .unwrap_or_default();
        args.extend(payload);
        Args(args)
    }

    /// Whether the payload named the draft `draft`.
    pub fn draft(action: &Action) -> Option<&str> {
        action.payload.as_ref()?.get("draft")?.as_str()
    }

    pub fn text(&self, key: &str) -> Result<Option<String>, String> {
        Ok(match self.0.get(key) {
            None => None,
            Some(Value::Null) => Some(String::new()),
            Some(Value::String(text)) => Some(text.trim().to_string()),
            Some(Value::Number(n)) => Some(n.to_string()),
            Some(Value::Bool(b)) => Some(b.to_string()),
            Some(_) => return Err(format!("{key}: expected text")),
        })
    }

    pub fn required(&self, key: &str) -> Result<String, String> {
        self.text(key)?
            .filter(|text| !text.is_empty())
            .ok_or_else(|| format!("{key} is required"))
    }

    pub fn number(&self, key: &str) -> Result<Option<Option<u64>>, String> {
        let bad = || format!("{key}: expected a whole number");
        Ok(match self.0.get(key) {
            None => None,
            Some(Value::Null) => Some(None),
            Some(Value::Number(n)) => Some(Some(match n.as_u64() {
                Some(n) => n,
                None => n
                    .as_f64()
                    .filter(|f| *f >= 0.0 && f.fract() == 0.0 && *f <= i64::MAX as f64)
                    .ok_or_else(bad)? as u64,
            })),
            Some(Value::String(text)) if text.trim().is_empty() => Some(None),
            Some(Value::String(text)) => Some(Some(text.trim().parse().map_err(|_| bad())?)),
            Some(_) => return Err(bad()),
        })
    }

    /// A boolean, or empty for unset.
    pub fn flag(&self, key: &str) -> Result<Option<Option<bool>>, String> {
        Ok(match self.0.get(key) {
            None => None,
            Some(Value::Null) => Some(None),
            Some(Value::Bool(b)) => Some(Some(*b)),
            Some(Value::String(text)) => Some(match text.trim() {
                "" => None,
                "true" | "yes" | "on" => Some(true),
                "false" | "no" | "off" => Some(false),
                _ => return Err(format!("{key}: expected true or false")),
            }),
            Some(_) => return Err(format!("{key}: expected true or false")),
        })
    }

    /// A list of strings, or one string of them separated by spaces or
    /// commas.
    pub fn list(&self, key: &str) -> Result<Option<Option<Vec<String>>>, String> {
        let items: Vec<String> = match self.0.get(key) {
            None => return Ok(None),
            Some(Value::Null) => Vec::new(),
            Some(Value::String(text)) => text
                .split(|c: char| c == ',' || c.is_whitespace())
                .filter(|item| !item.is_empty())
                .map(str::to_string)
                .collect(),
            Some(Value::Array(items)) => items
                .iter()
                .map(|item| item.as_str().map(|item| item.trim().to_string()))
                .collect::<Option<_>>()
                .ok_or_else(|| format!("{key}: expected a list of text"))?,
            Some(_) => return Err(format!("{key}: expected a list of text")),
        };
        Ok(Some((!items.is_empty()).then_some(items)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hypereffect::json;

    #[test]
    fn drafts_under_payloads() {
        let mut signals = Map::new();
        signals.insert("d".into(), json!({"f": {"a": "draft", "b": "draft"}}));
        let args = Args::of(&Action {
            name: "test".into(),
            payload: Some(json!({"draft": "f", "b": "payload"})),
            signals,
        });
        assert_eq!(args.text("a").unwrap().as_deref(), Some("draft"));
        assert_eq!(args.text("b").unwrap().as_deref(), Some("payload"));
        assert_eq!(args.text("draft").unwrap(), None);
    }
}
