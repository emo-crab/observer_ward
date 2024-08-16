use serde::{Deserialize, Serialize};
use slinger::http::header::HeaderValue;
use std::collections::BTreeMap;
use std::fmt::{Display, Formatter};

// 无论是字符串或者字符串列表都转成集合，序列化再
pub mod string_vec_serde {
  use serde::{de, Deserialize, Deserializer, Serializer};
  use std::fmt;
  use std::marker::PhantomData;

  pub fn serialize<S: Serializer>(v: &[String], s: S) -> Result<S::Ok, S::Error> {
    let vs: Vec<String> = v.iter().map(|s| s.to_string()).collect();
    serde::Serialize::serialize(&vs.join(","), s)
  }

  pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<String>, D::Error> {
    struct StringToVec(PhantomData<Vec<String>>);
    impl<'de> de::Visitor<'de> for StringToVec {
      type Value = Vec<String>;
      fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("string or list of strings")
      }
      fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
      where
        E: de::Error,
      {
        let name: Vec<String> = value.split_terminator(',').map(String::from).collect();
        Ok(name)
      }
      fn visit_none<E>(self) -> Result<Self::Value, E>
      where
        E: de::Error,
      {
        Ok(Vec::new())
      }
      fn visit_unit<E>(self) -> Result<Self::Value, E>
      where
        E: de::Error,
      {
        self.visit_none()
      }
      fn visit_seq<S>(self, visitor: S) -> Result<Self::Value, S::Error>
      where
        S: de::SeqAccess<'de>,
      {
        Deserialize::deserialize(de::value::SeqAccessDeserializer::new(visitor))
      }
    }
    d.deserialize_any(StringToVec(PhantomData))
  }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(untagged)]
pub enum Value {
  #[default]
  Null,
  Bool(bool),
  Num(u32),
  String(String),
  List(Vec<Value>),
  Map(BTreeMap<String, Value>),
}

impl Value {
  pub fn to_vec(&self) -> Vec<String> {
    match self {
      Value::Null => {
        vec![]
      }
      Value::Bool(b) => {
        vec![b.to_string()]
      }
      Value::Num(n) => {
        vec![n.to_string()]
      }
      Value::String(s) => {
        vec![s.to_string()]
      }
      Value::List(list) => list.iter().flat_map(|l| l.to_vec()).collect(),
      Value::Map(_) => {
        vec![]
      }
    }
  }
}

impl Display for Value {
  fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
    let s = match self {
      Value::Null | Value::List(_) | Value::Map(_) => String::new(),
      Value::Bool(bool) => bool.to_string(),
      Value::Num(num) => num.to_string(),
      Value::String(s) => s.to_string(),
    };
    f.write_str(&s)
  }
}

impl From<&Value> for HeaderValue {
  fn from(val: &Value) -> Self {
    let s = match val {
      Value::Null => String::new(),
      Value::Bool(b) => b.to_string(),
      Value::Num(n) => n.to_string(),
      Value::String(s) => s.to_string(),
      Value::List(l) => {
        format!("{:?}", l)
      }
      Value::Map(m) => {
        format!("{:?}", m)
      }
    };
    HeaderValue::from_str(&s).unwrap_or(HeaderValue::from_static(""))
  }
}

pub fn is_default<T: Default + PartialEq>(t: &T) -> bool {
  t == &T::default()
}
