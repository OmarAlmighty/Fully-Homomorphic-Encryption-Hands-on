use tfhe::boolean::ciphertext::Ciphertext;
use tfhe::boolean::prelude::ServerKey;
use tfhe::boolean::server_key::RefreshEngine;

pub struct pitch_trim_module;

impl pitch_trim_module {
    pub fn pitch_trim(sk: &ServerKey, ctxt: &mut [Ciphertext]) -> Vec<Ciphertext> {
        let mut fresh: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); ctxt.len()];
        for c in ctxt {
            let f = sk.bootstrap(c);
            fresh.push(f);
        }
        fresh
    }

    pub fn pitch_trim_bit(sk: &ServerKey, ctxt: &Ciphertext) -> Ciphertext {
        let mut fresh: Ciphertext = sk.bootstrap(ctxt);
        fresh
    }
}