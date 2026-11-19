use std::cell::RefCell;
use std::fmt;

use serde::de::{DeserializeSeed, Error, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};

use super::document::{PresetError, PresetErrorCode, PresetLimits};

pub(super) fn parse(bytes: &[u8], limits: &PresetLimits) -> Result<Value, PresetError> {
    if bytes.len() > limits.max_bytes {
        return Err(PresetError::limit("/", "input byte limit exceeded"));
    }
    let state = State {
        limits,
        nodes: RefCell::new(0),
        error: RefCell::new(None),
    };
    let mut de = serde_json::Deserializer::from_slice(bytes);
    let result = Seed {
        state: &state,
        depth: 0,
        path: String::new(),
    }
    .deserialize(&mut de)
    .and_then(|value| de.end().map(|()| value));
    result.map_err(|_| {
        state.error.into_inner().unwrap_or_else(|| {
            PresetError::new(PresetErrorCode::InvalidJson, "/", "invalid JSON or UTF-8")
        })
    })
}

struct State<'a> {
    limits: &'a PresetLimits,
    nodes: RefCell<usize>,
    error: RefCell<Option<PresetError>>,
}

struct Seed<'a> {
    state: &'a State<'a>,
    depth: usize,
    path: String,
}

impl Seed<'_> {
    fn fail<E: Error>(&self, error: PresetError) -> E {
        *self.state.error.borrow_mut() = Some(error);
        E::custom("profile JSON rejected")
    }

    fn child(&self, key: &str) -> Seed<'_> {
        Seed {
            state: self.state,
            depth: self.depth + 1,
            path: format!(
                "{}/{}",
                self.path,
                key.replace('~', "~0").replace('/', "~1")
            ),
        }
    }
}

impl<'de> DeserializeSeed<'de> for Seed<'_> {
    type Value = Value;

    fn deserialize<D: serde::Deserializer<'de>>(self, de: D) -> Result<Value, D::Error> {
        let mut nodes = self.state.nodes.borrow_mut();
        *nodes += 1;
        if *nodes > self.state.limits.max_nodes || self.depth > self.state.limits.max_depth {
            return Err(self.fail(PresetError::limit(
                &self.path,
                "JSON node or depth limit exceeded",
            )));
        }
        drop(nodes);
        de.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Seed<'_> {
    type Value = Value;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("bounded JSON")
    }
    fn visit_bool<E: Error>(self, v: bool) -> Result<Value, E> {
        Ok(v.into())
    }
    fn visit_i64<E: Error>(self, v: i64) -> Result<Value, E> {
        Ok(v.into())
    }
    fn visit_u64<E: Error>(self, v: u64) -> Result<Value, E> {
        Ok(v.into())
    }
    fn visit_f64<E: Error>(self, v: f64) -> Result<Value, E> {
        serde_json::Number::from_f64(v)
            .map(Value::Number)
            .ok_or_else(|| E::custom("non-finite number"))
    }
    fn visit_unit<E: Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_none<E: Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_str<E: Error>(self, v: &str) -> Result<Value, E> {
        if v.len() > self.state.limits.max_string_bytes {
            return Err(self.fail(PresetError::limit(&self.path, "string byte limit exceeded")));
        }
        Ok(Value::String(v.to_owned()))
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let mut values = Vec::new();
        loop {
            // Probe one extra element without allocating an unbounded container.
            let next = seq.next_element_seed(self.child(&values.len().to_string()))?;
            let Some(value) = next else { break };
            if values.len() >= self.state.limits.max_container_entries {
                return Err(self.fail(PresetError::limit(&self.path, "array entry limit exceeded")));
            }
            values.push(value);
        }
        Ok(Value::Array(values))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut values = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if key.len() > self.state.limits.max_string_bytes
                || values.len() >= self.state.limits.max_container_entries
            {
                return Err(self.fail(PresetError::limit(
                    &self.path,
                    "object entry or key limit exceeded",
                )));
            }
            if values.contains_key(&key) {
                return Err(self.fail(PresetError::new(
                    PresetErrorCode::DuplicateKey,
                    &self.child(&key).path,
                    "duplicate JSON key",
                )));
            }
            let value = map.next_value_seed(self.child(&key))?;
            values.insert(key, value);
        }
        Ok(Value::Object(values))
    }
}
