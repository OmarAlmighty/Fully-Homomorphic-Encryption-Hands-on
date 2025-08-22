//! # Description
//! This module includes the implementation of the circuits (functional units) that
//! the processor can perform on encrypted data. The gates operation are not bootstrapped.
//! Bootstrapping can be performed manually be by invoking `pitch_trim()` function.
//!
//! # Available Circuits
//! and, or, xor, not, nand, nor, xnor
//!
//! The following piece of code shows how to generate keys and run a small Boolean circuit
//! homomorphically.
//!

use std::time::Instant;
use tfhe::boolean::gen_keys;
use tfhe::boolean::prelude::*;
use tfhe::boolean::server_key::PitchTrimSystem;

/// Compute the encrypted AND gate on the `Ciphertext` vectors `a` and `b`. The result is stored in
/// `result` vector.
///
/// `PARAMETERS`.
/// * `sk`: &ServerKey - The key which the server will use to perform the computation.
/// * `a`: &[Ciphertext] - The first operand, a vector of ciphertexts, each element encrypting a single bit.
/// * `b`: &[Ciphertext] - The second operand, a vector of ciphertexts, each element encrypting a single bit.
/// * `result`: &mut [Ciphertext] - A vector holding the result of the operation.
///
fn e_and(sk: &ServerKey, a: &[Ciphertext], b: &[Ciphertext], result: &mut [Ciphertext]) {
    for i in 0..a.len() {
        result[i] = sk.and(&a[i], &b[i]);
    }

    #[cfg(debug_assertions)]
    {
        println!("DEBUG: `e_and` -> len(a)={}, len(b)={}", a.len(), b.len());
    }
}

/// Compute the encrypted OR gate on the `Ciphertext` vectors `a` and `b`. The result is stored in
/// `result` vector.
///
/// `PARAMETERS`.
/// * `sk`: &ServerKey - The key which the server will use to perform the computation.
/// * `a`: &[Ciphertext] - The first operand, a vector of ciphertexts, each element encrypting a single bit.
/// * `b`: &[Ciphertext] - The second operand, a vector of ciphertexts, each element encrypting a single bit.
/// * `result`: &mut [Ciphertext] - A vector holding the result of the operation.
///
fn e_or(sk: &ServerKey, a: &[Ciphertext], b: &[Ciphertext], result: &mut [Ciphertext]) {
    for i in 0..a.len() {
        result[i] = sk.or(&a[i], &b[i]);
    }

    #[cfg(debug_assertions)]
    {
        println!("DEBUG: `e_or` -> len(a)={}, len(b)={}", a.len(), b.len());
    }
}

/// Compute the encrypted XOR gate on the `Ciphertext` vectors `a` and `b`. The result is stored in
/// `result` vector.
///
/// `PARAMETERS`.
/// * `sk`: &ServerKey - The key which the server will use to perform the computation.
/// * `a`: &[Ciphertext] - The first operand, a vector of ciphertexts, each element encrypting a single bit.
/// * `b`: &[Ciphertext] - The second operand, a vector of ciphertexts, each element encrypting a single bit.
/// * `result`: &mut [Ciphertext] - A vector holding the result of the operation.
///
fn e_xor(sk: &ServerKey, a: &[Ciphertext], b: &[Ciphertext], result: &mut [Ciphertext]) {
    for i in 0..a.len() {
        result[i] = sk.xor(&a[i], &b[i]);
    }

    #[cfg(debug_assertions)]
    {
        println!("DEBUG: `e_xor` -> len(a)={}, len(b)={}", a.len(), b.len());
    }
}

/// Compute the encrypted NAND gate on the `Ciphertext` vectors `a` and `b`. The result is stored in
/// `result` vector.
///
/// `PARAMETERS`.
/// * `sk`: &ServerKey - The key which the server will use to perform the computation.
/// * `a`: &[Ciphertext] - The first operand, a vector of ciphertexts, each element encrypting a single bit.
/// * `b`: &[Ciphertext] - The second operand, a vector of ciphertexts, each element encrypting a single bit.
/// * `result`: &mut [Ciphertext] - A vector holding the result of the operation.
///
fn e_nand(sk: &ServerKey, a: &[Ciphertext], b: &[Ciphertext], result: &mut [Ciphertext]) {
    for i in 0..a.len() {
        result[i] = sk.nand(&a[i], &b[i]);
    }

    #[cfg(debug_assertions)]
    {
        println!("DEBUG: `e_nand` -> len(a)={}, len(b)={}", a.len(), b.len());
    }
}

/// Compute the encrypted NOR gate on the `Ciphertext` vectors `a` and `b`. The result is stored in
/// `result` vector.
///
/// `PARAMETERS`.
/// * `sk`: &ServerKey - The key which the server will use to perform the computation.
/// * `a`: &[Ciphertext] - The first operand, a vector of ciphertexts, each element encrypting a single bit.
/// * `b`: &[Ciphertext] - The second operand, a vector of ciphertexts, each element encrypting a single bit.
/// * `result`: &mut [Ciphertext] - A vector holding the result of the operation.
///
fn e_nor(sk: &ServerKey, a: &[Ciphertext], b: &[Ciphertext], result: &mut [Ciphertext]) {
    for i in 0..a.len() {
        result[i] = sk.nor(&a[i], &b[i]);
    }

    #[cfg(debug_assertions)]
    {
        println!("DEBUG: `e_nor` -> len(a)={}, len(b)={}", a.len(), b.len());
    }
}

/// Compute the encrypted XNOR gate on the `Ciphertext` vectors `a` and `b`. The result is stored in
/// `result` vector.
///
/// `PARAMETERS`.
/// * `sk`: &ServerKey - The key which the server will use to perform the computation.
/// * `a`: &[Ciphertext] - The first operand, a vector of ciphertexts, each element encrypting a single bit.
/// * `b`: &[Ciphertext] - The second operand, a vector of ciphertexts, each element encrypting a single bit.
/// * `result`: &mut [Ciphertext] - A vector holding the result of the operation.
///
fn e_xnor(sk: &ServerKey, a: &[Ciphertext], b: &[Ciphertext], result: &mut [Ciphertext]) {
    for i in 0..a.len() {
        result[i] = sk.xnor(&a[i], &b[i]);
    }

    #[cfg(debug_assertions)]
    {
        println!("DEBUG: `e_xnor` -> len(a)={}, len(b)={}", a.len(), b.len());
    }
}

/// Compute the encrypted NOT gate on the `Ciphertext` vector `a`. The result is stored in
/// `result` vector.
///
/// `PARAMETERS`.
/// * `sk`: &ServerKey - The key which the server will use to perform the computation.
/// * `a`: &[Ciphertext] - A vector of ciphertexts, each element encrypting a single bit.
/// * `result`: &mut [Ciphertext] - A vector holding the result of the operation.
///
fn e_not(sk: &ServerKey, a: &[Ciphertext], result: &mut [Ciphertext]) {
    for i in 0..a.len() {
        result[i] = sk.not(&a[i]);
    }

    #[cfg(debug_assertions)]
    {
        println!("DEBUG: `e_not` -> len(a)={}", a.len());
    }
}
