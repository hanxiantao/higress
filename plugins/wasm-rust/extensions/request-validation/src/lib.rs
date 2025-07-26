// Copyright (c) 2025 Alibaba Group Holding Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use higress_wasm_rust::log::Log;
use higress_wasm_rust::plugin_wrapper::{HttpContextWrapper, RootContextWrapper};
use higress_wasm_rust::rule_matcher::{on_configure, RuleMatcher, SharedRuleMatcher};
use jsonschema::{Draft, Validator};
use multimap::MultiMap;
use proxy_wasm::traits::{Context, HttpContext, RootContext};
use proxy_wasm::types::{Bytes, ContextType, DataAction, HeaderAction, LogLevel};
use serde::Deserialize;
use serde_json::Value;
use std::cell::RefCell;
use std::ops::DerefMut;
use std::rc::Rc;

proxy_wasm::main! {{
    proxy_wasm::set_log_level(LogLevel::Trace);
    proxy_wasm::set_root_context(|_| Box::new(RequestValidationRoot::new()));
}}

const PLUGIN_NAME: &str = "request-validation";
const DEFAULT_REJECTED_CODE: u32 = 403;

#[derive(Default, Debug, Clone, Deserialize)]
#[serde(default)]
pub struct RequestValidationConfig {
    #[serde(default)]
    pub header_schema: String,
    #[serde(default)]
    pub body_schema: String,
    #[serde(default)]
    pub enable_swagger: bool,
    #[serde(default)]
    pub enable_oas3: bool,
    #[serde(default = "default_rejected_code")]
    pub rejected_code: u32,
    #[serde(default)]
    pub rejected_msg: String,

    // 运行时字段
    #[serde(skip)]
    pub enable_header_schema: bool,
    #[serde(skip)]
    pub enable_body_schema: bool,
    #[serde(skip)]
    pub draft: Draft,
    #[serde(skip)]
    pub header_validator: Option<Rc<Validator>>,
    #[serde(skip)]
    pub body_validator: Option<Rc<Validator>>,
}

fn default_rejected_code() -> u32 {
    DEFAULT_REJECTED_CODE
}

struct RequestValidationRoot {
    log: Log,
    rule_matcher: SharedRuleMatcher<RequestValidationConfig>,
}

struct RequestValidation {
    log: Log,
    config: Option<Rc<RequestValidationConfig>>,
}

impl RequestValidationRoot {
    fn new() -> Self {
        RequestValidationRoot {
            log: Log::new(PLUGIN_NAME.to_string()),
            rule_matcher: Rc::new(RefCell::new(RuleMatcher::default())),
        }
    }
}

impl Context for RequestValidationRoot {}
impl RootContext for RequestValidationRoot {
    fn on_configure(&mut self, plugin_configuration_size: usize) -> bool {
        on_configure(
            self,
            plugin_configuration_size,
            self.rule_matcher.borrow_mut().deref_mut(),
            &self.log,
        )
    }

    fn create_http_context(&self, context_id: u32) -> Option<Box<dyn HttpContext>> {
        self.create_http_context_use_wrapper(context_id)
    }

    fn get_type(&self) -> Option<ContextType> {
        Some(ContextType::HttpContext)
    }
}

impl RootContextWrapper<RequestValidationConfig> for RequestValidationRoot {
    fn rule_matcher(&self) -> &SharedRuleMatcher<RequestValidationConfig> {
        &self.rule_matcher
    }

    fn create_http_context_wrapper(
        &self,
        _context_id: u32,
    ) -> Option<Box<dyn HttpContextWrapper<RequestValidationConfig>>> {
        Some(Box::new(RequestValidation {
            config: None,
            log: Log::new(PLUGIN_NAME.to_string()),
        }))
    }
}

impl Context for RequestValidation {}
impl HttpContext for RequestValidation {}

impl HttpContextWrapper<RequestValidationConfig> for RequestValidation {
    fn on_config(&mut self, config: Rc<RequestValidationConfig>) {
        let mut config = (*config).clone();
        config.enable_header_schema = false;
        config.enable_body_schema = false;

        if config.enable_swagger && config.enable_oas3 {
            self.log
                .error("enable_swagger and enable_oas3 cannot both be true");
            return;
        }

        config.draft = if config.enable_swagger {
            Draft::Draft4
        } else if config.enable_oas3 {
            Draft::Draft7
        } else {
            Draft::Draft7
        };

        if !config.header_schema.is_empty() {
            match compile_validator(&config.header_schema, config.draft, &self.log) {
                Ok(validator) => {
                    config.header_validator = Some(validator);
                    config.enable_header_schema = true;
                }
                Err(()) => return,
            }
        }

        if !config.body_schema.is_empty() {
            match compile_validator(&config.body_schema, config.draft, &self.log) {
                Ok(validator) => {
                    config.body_validator = Some(validator);
                    config.enable_body_schema = true;
                }
                Err(()) => return,
            }
        }

        if config.rejected_code != 0 && !(100..600).contains(&config.rejected_code) {
            self.log
                .warn("rejected_code must be between 100 and 599, using default");
            config.rejected_code = DEFAULT_REJECTED_CODE;
        }

        self.config = Some(Rc::new(config));
    }

    fn on_http_request_complete_headers(
        &mut self,
        headers: &MultiMap<String, String>,
    ) -> HeaderAction {
        let config = match &self.config {
            Some(c) if c.enable_header_schema => c,
            _ => return HeaderAction::Continue,
        };

        let headers_json: Value = headers
            .iter_all()
            .map(|(k, v)| (k.clone(), Value::String(v[0].clone())))
            .collect();

        if let Some(validator) = &config.header_validator {
            if let Err(errors) = validator.validate(&headers_json) {
                let error_msg = format!("{}", errors);
                self.log
                    .error(&format!("Header validation failed: {}", error_msg));
                return HeaderAction::StopIteration;
            }
        }

        HeaderAction::Continue
    }

    fn on_http_request_complete_body(&mut self, req_body: &Bytes) -> DataAction {
        let config = match &self.config {
            Some(c) if c.enable_body_schema => c,
            _ => return DataAction::Continue,
        };

        let body_json = match serde_json::from_slice(req_body) {
            Ok(json) => json,
            Err(e) => {
                self.log
                    .error(&format!("Failed to parse request body: {}", e));
                return DataAction::StopIterationAndBuffer;
            }
        };

        if let Some(validator) = &config.body_validator {
            if let Err(errors) = validator.validate(&body_json) {
                let error_msg = format!("{}", errors);
                self.log
                    .error(&format!("Body validation failed: {}", error_msg));
                return DataAction::StopIterationAndBuffer;
            }
        }

        DataAction::Continue
    }

    fn cache_request_body(&self) -> bool {
        self.config.as_ref().map_or(false, |c| c.enable_body_schema)
    }
}

fn compile_validator(schema: &str, draft: Draft, log: &Log) -> Result<Rc<Validator>, ()> {
    let schema_value = match serde_json::from_str(schema) {
        Ok(v) => v,
        Err(e) => {
            log.error(&format!("Failed to parse schema: {}", e));
            return Err(());
        }
    };

    match Validator::options().with_draft(draft).build(&schema_value) {
        Ok(v) => Ok(Rc::new(v)),
        Err(e) => {
            log.error(&format!("Failed to compile schema: {}", e));
            Err(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize_config() {
        let json = r#"
        {
            "header_schema": "{\"type\": \"object\"}",
            "body_schema": "{\"type\": \"object\"}",
            "enable_swagger": false,
            "enable_oas3": true,
            "rejected_code": 403,
            "rejected_msg": "Forbidden"
        }"#;

        let config: RequestValidationConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.rejected_code, 403);
    }
}
