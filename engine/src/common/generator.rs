use crate::serde_format::Value;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, VecDeque};
use std::ops::Index;

// description: |
//   Attack is the type of payload combinations to perform.
//
//   batteringram is inserts the same payload into all defined payload positions at once, pitchfork combines multiple payload sets and clusterbomb generates
//   permutations and combinations for all payloads.
// values:
//   - "batteringram"
//   - "pitchfork"
//   - "clusterbomb"
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum AttackType {
  // 单个payload
  BatteringRam,
  // 多个长度相同的payload平行对应
  PitchFork,
  // 多个payload计算笛卡尔积
  ClusterBomb,
}

#[derive(Debug, Clone, Default)]
pub struct PayloadIterator {
  payload_iterator: VecDeque<BTreeMap<String, String>>,
}

impl IntoIterator for PayloadIterator {
  type Item = BTreeMap<String, String>;
  type IntoIter = <VecDeque<BTreeMap<String, String>> as IntoIterator>::IntoIter;

  fn into_iter(self) -> Self::IntoIter {
    self.payload_iterator.into_iter()
  }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub struct PayloadAttack {
  pub attack: AttackType,
  pub payloads: BTreeMap<String, Value>,
}

impl From<&PayloadAttack> for PayloadIterator {
  fn from(value: &PayloadAttack) -> Self {
    let mut payload_iterator = VecDeque::new();
    match value.attack {
      AttackType::BatteringRam => {
        if let Some((k, v)) = value.payloads.iter().next() {
          for i in v.to_vec() {
            payload_iterator.push_back(BTreeMap::from_iter([(k.clone(), i)]));
          }
        }
      }
      AttackType::PitchFork => {
        let mut payload_map: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for (n, v) in value.payloads.iter() {
          payload_map.insert(n.to_string(), v.to_vec());
        }
        // payload的最小长度
        let min_length = payload_map
          .values()
          .min_by(|x, y| x.len().cmp(&y.len()))
          .unwrap_or(&vec![])
          .len();
        for index in 0..min_length {
          let mut hm = BTreeMap::new();
          for (n, vs) in payload_map.iter() {
            hm.insert(n.to_string(), vs.index(index).to_string());
          }
          payload_iterator.push_back(hm);
        }
      }
      AttackType::ClusterBomb => {
        let mut payload_vec: Vec<Vec<BTreeMap<String, String>>> = Vec::new();
        for (n, nvv) in value.payloads.iter() {
          let mut payload: Vec<BTreeMap<String, String>> = Vec::new();
          for nv in nvv.to_vec() {
            payload.push(BTreeMap::from_iter([(n.to_string(), nv)]));
          }
          payload_vec.push(payload);
        }
        while payload_vec.len() > 1 {
          let xv = payload_vec.pop().unwrap_or_default();
          let yv = payload_vec.pop().unwrap_or_default();
          let mut xy = Vec::new();
          for x in xv.into_iter() {
            let mut hm = x.clone();
            for y in yv.iter() {
              hm.extend(y.clone());
              xy.push(hm.clone());
            }
          }
          payload_vec.push(xy);
        }
        payload_iterator = payload_vec.into_iter().flatten().collect();
      }
    }
    PayloadIterator { payload_iterator }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn payload() {
    let mut payload = BTreeMap::new();
    payload.insert(
      "username".to_string(),
      Value::List(vec![
        Value::String("admin".to_string()),
        Value::String("user".to_string()),
      ]),
    );
    payload.insert(
      "password".to_string(),
      Value::List(vec![
        Value::String("pwd".to_string()),
        Value::String("password".to_string()),
        Value::Num(123456),
      ]),
    );
    payload.insert(
      "token".to_string(),
      Value::List(vec![
        Value::String("token".to_string()),
        Value::String("etc".to_string()),
      ]),
    );
    let payload_attack = PayloadAttack {
      attack: AttackType::ClusterBomb,
      payloads: payload,
    };
    for p in PayloadIterator::from(&payload_attack) {
      println!("{:?}", p);
    }
  }
}
