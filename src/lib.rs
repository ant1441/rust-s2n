#![allow(dead_code)]
#![cfg_attr(feature="clippy", feature(plugin))]
#![cfg_attr(feature="clippy", plugin(clippy))]

extern crate failure;
#[macro_use]
extern crate failure_derive;

use std::sync::{Once, ONCE_INIT};

mod s2n;
mod config;
mod connection;
mod types;

pub use connection::Connection;
pub use config::Config;
pub use types::*;

static START: Once = ONCE_INIT;

fn init() {
    START.call_once(|| unsafe {
                        s2n::s2n_init();
                    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        init();
    }
}
