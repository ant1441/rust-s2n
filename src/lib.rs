#![allow(dead_code)]

extern crate failure;
#[macro_use] extern crate failure_derive;

use std::sync::{Once, ONCE_INIT};

mod config;
mod s2n;

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
