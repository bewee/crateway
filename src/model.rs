/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct Thing {
    pub id: String,
}

impl Thing {
    pub fn from_id_and_json(
        id: &str,
        mut description: serde_json::Value,
    ) -> Result<Self, &'static str> {
        if let Value::Object(ref mut map) = description {
            map.insert("id".to_owned(), Value::String(id.to_owned()));
        }
        Ok(serde_json::from_value(description).map_err(|_| "Parse Thing")?)
    }
}