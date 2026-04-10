#![forbid(unsafe_code)]

pub mod auth;
pub mod rendezvous_client;
pub mod store;
pub mod sync;
pub mod watcher;

pub fn greet(name: Option<&str>) -> String {
    match name {
        Some(n) => format!("hello {}", n),
        None => "hello world".to_string(),
    }
}

pub fn fizzbuzz(n: i32) -> String {
    match (n % 3, n % 5) {
        (0, 0) => "fizzbuzz".to_string(),
        (0, _) => "fizz".to_string(),
        (_, 0) => "buzz".to_string(),
        _ => n.to_string(),
    }
}
