use higress_wasm_rust::cluster_wrapper::{DnsCluster, StaticIpCluster};
use higress_wasm_rust::log::Log;
use higress_wasm_rust::plugin_wrapper::{HttpContextWrapper, RootContextWrapper};
use higress_wasm_rust::redis_wrapper::{RedisClient, RedisClientBuilder, RedisClientConfig};
use higress_wasm_rust::rule_matcher::{on_configure, RuleMatcher, SharedRuleMatcher};
use http::Method;
use multimap::MultiMap;
use proxy_wasm::traits::{Context, HttpContext, RootContext};
use proxy_wasm::types::{Bytes, ContextType, DataAction, HeaderAction, LogLevel};

use redis::Value;
use serde::Deserialize;
use serde_json::json;
use std::cell::RefCell;
use std::ops::DerefMut;
use std::rc::{Rc, Weak};
use std::time::Duration;

proxy_wasm::main! {{
    proxy_wasm::set_log_level(LogLevel::Trace);
    proxy_wasm::set_root_context(|_|Box::new(ProxyCacheRoot::new()));
}}

const PLUGIN_NAME: &str = "proxy-cache";

struct ProxyCacheRoot {
    log: Log,
    rule_matcher: SharedRuleMatcher<ProxyCacheConfig>,
}

struct ProxyCache {
    log: Log,
    config: Option<Rc<ProxyCacheConfig>>,
    redis_client: Option<Rc<RedisClient>>,
    should_cache_response: bool,
}

fn default_cache_key() -> Vec<String> {
    vec!["$host".to_string(), "$request_uri".to_string()]
}

fn default_cache_methods() -> Vec<String> {
    vec![
        "GET".to_string(),
        "POST".to_string(),
        "PUT".to_string(),
        "DELETE".to_string(),
    ]
}

fn default_cache_http_status() -> Vec<u32> {
    vec![200]
}

fn default_cache_ttl() -> u32 {
    300
}

#[derive(Default, Debug, Deserialize, Clone)]
struct ProxyCacheConfig {
    #[serde(default = "default_cache_key")]
    cache_key: Vec<String>,
    #[serde(default = "default_cache_methods")]
    cache_method: Vec<String>,
    #[serde(default = "default_cache_http_status")]
    cache_http_status: Vec<u32>,
    #[serde(default = "default_cache_ttl")]
    cache_ttl: u32,
    redis_client_config: Option<RedisConfig>,
}

fn default_redis_service_port() -> u16 {
    80
}

fn default_redis_timetou() -> u64 {
    1000
}

#[derive(Default, Debug, Deserialize, Clone)]
struct RedisConfig {
    service_name: String,
    #[serde(default = "default_redis_service_port")]
    service_port: u16,
    username: String,
    password: String,
    #[serde(default = "default_redis_timetou")]
    timeout: u64,
}

impl ProxyCacheRoot {
    fn new() -> Self {
        let log = Log::new(PLUGIN_NAME.to_string());
        log.info("ProxyCacheRoot::new");

        ProxyCacheRoot {
            log,
            rule_matcher: Rc::new(RefCell::new(RuleMatcher::default())),
        }
    }
}

impl Context for ProxyCacheRoot {}

impl RootContext for ProxyCacheRoot {
    fn on_configure(&mut self, plugin_configuration_size: usize) -> bool {
        let ret = on_configure(
            self,
            plugin_configuration_size,
            self.rule_matcher.borrow_mut().deref_mut(),
            &self.log,
        );
        ret
    }
    fn create_http_context(&self, context_id: u32) -> Option<Box<dyn HttpContext>> {
        self.create_http_context_use_wrapper(context_id)
    }
    fn get_type(&self) -> Option<ContextType> {
        Some(ContextType::HttpContext)
    }
}

impl RootContextWrapper<ProxyCacheConfig> for ProxyCacheRoot {
    fn rule_matcher(&self) -> &SharedRuleMatcher<ProxyCacheConfig> {
        &self.rule_matcher
    }

    fn create_http_context_wrapper(
        &self,
        _context_id: u32,
    ) -> Option<Box<dyn HttpContextWrapper<ProxyCacheConfig>>> {
        Some(Box::new(ProxyCache {
            log: Log::new(PLUGIN_NAME.to_string()),
            config: None,
            redis_client: None,
            should_cache_response: false,
        }))
    }
}

impl Context for ProxyCache {}
impl HttpContext for ProxyCache {}
impl HttpContextWrapper<ProxyCacheConfig> for ProxyCache {
    fn on_config(&mut self, config: Rc<ProxyCacheConfig>) {
        println!("config:{:?}", config);
        self.config = Some(config.clone());
    }
    fn on_http_request_complete_headers(
        &mut self,
        headers: &MultiMap<String, String>,
    ) -> HeaderAction {
        HeaderAction::Continue
    }
    fn on_http_response_complete_headers(
        &mut self,
        headers: &MultiMap<String, String>,
    ) -> HeaderAction {
        let config = self.config.as_ref().unwrap();

        // 获取状态码
        let status_code_value = match headers.get(":status") {
            Some(code) => code,
            None => {
                self.log.warn("get response status code failed");
                return HeaderAction::Continue;
            }
        };
        // 解析状态码并决定是否缓存
        let should_cache = match status_code_value.parse::<u32>() {
            Ok(status_code) => config.cache_http_status.contains(&status_code),
            Err(_) => {
                self.log
                    .error(&format!("failed to parse status: {}", status_code_value));
                false
            }
        };

        self.should_cache_response = should_cache;
        HeaderAction::Continue
    }
    fn cache_response_body(&self) -> bool {
        // 是否缓存 response body
        true
    }
    fn on_http_response_complete_body(&mut self, res_body: &Bytes) -> DataAction {
        let res_body_string = String::from_utf8(res_body.clone()).unwrap_or("".to_string());
        self.log.info(&format!(
            "on_http_response_complete_body {}",
            res_body_string
        ));
        self.log.info(&format!(
            "should_cache_response {}",
            self.should_cache_response
        ));
        DataAction::Continue
    }
}

// fn generate_cache_key(cache_key: &Vec<String>, headers: &MultiMap<String, String>) -> String {

// }
