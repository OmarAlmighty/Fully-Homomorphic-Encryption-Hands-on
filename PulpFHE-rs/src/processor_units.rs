#![allow(warnings)]
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
use tfhe::boolean::server_key::RefreshEngine;

pub trait Processor {
    /// Compute the encrypted AND gate on the `Ciphertext` vectors `a` and `b`. The result is stored in
    /// `result` vector.
    ///
    /// `PARAMETERS`.
    /// * `sk`: &ServerKey - The key which the server will use to perform the computation.
    /// * `a`: &[Ciphertext] - The first operand, a vector of ciphertexts, each element encrypting a single bit.
    /// * `b`: &[Ciphertext] - The second operand, a vector of ciphertexts, each element encrypting a single bit.
    /// * `result`: &mut [Ciphertext] - A vector holding the result of the operation.
    ///
    fn e_and(&self, sk: &ServerKey, a: &[Ciphertext], b: &[Ciphertext], result: &mut [Ciphertext]);

    fn e_and_bit(&self, sk: &ServerKey, a: &Ciphertext, b: &Ciphertext) -> Ciphertext;

    fn e_and_range(
        &self,
        sk: &ServerKey,
        a: &[Ciphertext],
        b: &[Ciphertext],
        result: &mut [Ciphertext],
        index_low: usize,
        index_high: usize,
    );

    /// Compute the encrypted OR gate on the `Ciphertext` vectors `a` and `b`. The result is stored in
    /// `result` vector.
    ///
    /// `PARAMETERS`.
    /// * `sk`: &ServerKey - The key which the server will use to perform the computation.
    /// * `a`: &[Ciphertext] - The first operand, a vector of ciphertexts, each element encrypting a single bit.
    /// * `b`: &[Ciphertext] - The second operand, a vector of ciphertexts, each element encrypting a single bit.
    /// * `result`: &mut [Ciphertext] - A vector holding the result of the operation.
    ///
    fn e_or(&self, sk: &ServerKey, a: &[Ciphertext], b: &[Ciphertext], result: &mut [Ciphertext]);

    fn e_or_bit(&self, sk: &ServerKey, a: &Ciphertext, b: &Ciphertext) -> Ciphertext;

    fn e_or_range(
        &self,
        sk: &ServerKey,
        a: &[Ciphertext],
        b: &[Ciphertext],
        result: &mut [Ciphertext],
        index_low: usize,
        index_high: usize,
    );

    /// Compute the encrypted XOR gate on the `Ciphertext` vectors `a` and `b`. The result is stored in
    /// `result` vector.
    ///
    /// `PARAMETERS`.
    /// * `sk`: &ServerKey - The key which the server will use to perform the computation.
    /// * `a`: &[Ciphertext] - The first operand, a vector of ciphertexts, each element encrypting a single bit.
    /// * `b`: &[Ciphertext] - The second operand, a vector of ciphertexts, each element encrypting a single bit.
    /// * `result`: &mut [Ciphertext] - A vector holding the result of the operation.
    ///
    fn e_xor(&self, sk: &ServerKey, a: &[Ciphertext], b: &[Ciphertext], result: &mut [Ciphertext]);
    fn e_xor_bit(&self, sk: &ServerKey, a: &Ciphertext, b: &Ciphertext) -> Ciphertext;
    fn e_xor_range(
        &self,
        sk: &ServerKey,
        a: &[Ciphertext],
        b: &[Ciphertext],
        result: &mut [Ciphertext],
        index_low: usize,
        index_high: usize,
    );

    /// Compute the encrypted NAND gate on the `Ciphertext` vectors `a` and `b`. The result is stored in
    /// `result` vector.
    ///
    /// `PARAMETERS`.
    /// * `sk`: &ServerKey - The key which the server will use to perform the computation.
    /// * `a`: &[Ciphertext] - The first operand, a vector of ciphertexts, each element encrypting a single bit.
    /// * `b`: &[Ciphertext] - The second operand, a vector of ciphertexts, each element encrypting a single bit.
    /// * `result`: &mut [Ciphertext] - A vector holding the result of the operation.
    ///
    fn e_nand(&self, sk: &ServerKey, a: &[Ciphertext], b: &[Ciphertext], result: &mut [Ciphertext]);
    fn e_nand_bit(&self, sk: &ServerKey, a: &Ciphertext, b: &Ciphertext) -> Ciphertext;
    fn e_nand_range(
        &self,
        sk: &ServerKey,
        a: &[Ciphertext],
        b: &[Ciphertext],
        result: &mut [Ciphertext],
        index_low: usize,
        index_high: usize,
    );

    /// Compute the encrypted NOR gate on the `Ciphertext` vectors `a` and `b`. The result is stored in
    /// `result` vector.
    ///
    /// `PARAMETERS`.
    /// * `sk`: &ServerKey - The key which the server will use to perform the computation.
    /// * `a`: &[Ciphertext] - The first operand, a vector of ciphertexts, each element encrypting a single bit.
    /// * `b`: &[Ciphertext] - The second operand, a vector of ciphertexts, each element encrypting a single bit.
    /// * `result`: &mut [Ciphertext] - A vector holding the result of the operation.
    ///
    fn e_nor(&self, sk: &ServerKey, a: &[Ciphertext], b: &[Ciphertext], result: &mut [Ciphertext]);
    fn e_nor_bit(&self, sk: &ServerKey, a: &Ciphertext, b: &Ciphertext) -> Ciphertext;
    fn e_nor_range(
        &self,
        sk: &ServerKey,
        a: &[Ciphertext],
        b: &[Ciphertext],
        result: &mut [Ciphertext],
        index_low: usize,
        index_high: usize,
    );

    /// Compute the encrypted XNOR gate on the `Ciphertext` vectors `a` and `b`. The result is stored in
    /// `result` vector.
    ///
    /// `PARAMETERS`.
    /// * `sk`: &ServerKey - The key which the server will use to perform the computation.
    /// * `a`: &[Ciphertext] - The first operand, a vector of ciphertexts, each element encrypting a single bit.
    /// * `b`: &[Ciphertext] - The second operand, a vector of ciphertexts, each element encrypting a single bit.
    /// * `result`: &mut [Ciphertext] - A vector holding the result of the operation.
    ///
    fn e_xnor(&self, sk: &ServerKey, a: &[Ciphertext], b: &[Ciphertext], result: &mut [Ciphertext]);
    fn e_xnor_bit(&self, sk: &ServerKey, a: &Ciphertext, b: &Ciphertext) -> Ciphertext;
    fn e_xnor_range(
        &self,
        sk: &ServerKey,
        a: &[Ciphertext],
        b: &[Ciphertext],
        result: &mut [Ciphertext],
        index_low: usize,
        index_high: usize,
    );

    /// Compute the encrypted NOT gate on the `Ciphertext` vector `a`. The result is stored in
    /// `result` vector.
    ///
    /// `PARAMETERS`.
    /// * `sk`: &ServerKey - The key which the server will use to perform the computation.
    /// * `a`: &[Ciphertext] - A vector of ciphertexts, each element encrypting a single bit.
    /// * `result`: &mut [Ciphertext] - A vector holding the result of the operation.
    ///
    fn e_not(&self, sk: &ServerKey, a: &[Ciphertext], result: &mut [Ciphertext]);

    fn e_not_bit(&self, sk: &ServerKey, a: &Ciphertext) -> Ciphertext;
    fn e_not_range(
        &self,
        sk: &ServerKey,
        a: &[Ciphertext],
        result: &mut [Ciphertext],
        index_low: usize,
        index_high: usize,
    );

    fn e_shl(&self, sk: &ServerKey, a: &[Ciphertext], shift_amt: usize, result: &mut [Ciphertext]);

    fn e_shr(&self, sk: &ServerKey, a: &[Ciphertext], shift_amt: usize, result: &mut [Ciphertext]);

    fn e_rot_r(&self, sk: &ServerKey, a: &[Ciphertext], rot_amt: usize, result: &mut [Ciphertext]);
    fn e_rot_l(&self, sk: &ServerKey, a: &[Ciphertext], rot_amt: usize, result: &mut [Ciphertext]);

    fn e_mux(
        &self,
        sk: &ServerKey,
        selector: &[Ciphertext],
        ct_then: &[Ciphertext],
        ct_else: &[Ciphertext],
        result: &mut [Ciphertext],
    );
    fn e_mux_bit(
        &self,
        sk: &ServerKey,
        selector: &Ciphertext,
        ct_then: &Ciphertext,
        ct_else: &Ciphertext,
    ) -> Ciphertext;
    fn e_mux_range(
        &self,
        sk: &ServerKey,
        selector: &[Ciphertext],
        ct_then: &[Ciphertext],
        ct_else: &[Ciphertext],
        result: &mut [Ciphertext],
        index_low: usize,
        index_high: usize,
    );

    fn comparator(
        &self,
        sk: &ServerKey,
        a: &[Ciphertext],
        b: &[Ciphertext],
        select: u8,
        result: &mut [Ciphertext],
    );

    fn compare_bit(
        &self,
        sk: &ServerKey,
        a: &Ciphertext,
        b: &Ciphertext,
        lsb_carry: &Ciphertext,
    ) -> Ciphertext;

    fn subtracter(
        &self,
        sk: &ServerKey,
        a: &[Ciphertext],
        b: &[Ciphertext],
        result: &mut [Ciphertext],
    );

    fn adder(&self, sk: &ServerKey, a: &[Ciphertext], b: &[Ciphertext], result: &mut [Ciphertext]);

    fn half_adder(
        &self,
        sk: &ServerKey,
        a: &Ciphertext,
        b: &Ciphertext,
        carry: &mut Ciphertext,
        result: &mut Ciphertext,
    );

    fn carry_save_adder(
        &self,
        sk: &ServerKey,
        a: &Ciphertext,
        b: &Ciphertext,
        cin: &Ciphertext,
        carry: &mut Ciphertext,
        result: &mut Ciphertext,
    );

    fn add_supplement(
        &self,
        sk: &ServerKey,
        a: &[Ciphertext],
        b: &[Ciphertext],
        size: usize,
        result: &mut [Ciphertext],
    );

    fn multiplier(
        &self,
        sk: &ServerKey,
        a: &[Ciphertext],
        b: &[Ciphertext],
        result: &mut [Ciphertext],
    );
    fn blake3(
        &self,
        sk: &ServerKey,
        msg: Vec<&[Ciphertext]>,
        v: Vec<&[Ciphertext]>,
        result: &mut Vec<&mut [Ciphertext]>,
    );

    fn max(&self, sk: &ServerKey, a: &Vec<&[Ciphertext]>, result: &mut [Ciphertext]);

    fn min(&self, sk: &ServerKey, a: &Vec<&[Ciphertext]>, result: &mut [Ciphertext]);

    fn relu(&self, sk: &ServerKey, a: &[Ciphertext], result: &mut [Ciphertext]);

    fn div(&self, sk: &ServerKey, a: &[Ciphertext], b: &[Ciphertext], result: &mut [Ciphertext]);

    fn modulo(&self, sk: &ServerKey, a: &[Ciphertext], b: &[Ciphertext], result: &mut [Ciphertext]);

    fn mean(&self, sk: &ServerKey, a: &Vec<&[Ciphertext]>, count: usize, result: &mut [Ciphertext]);

    fn e_sqrt(&self, sk: &ServerKey, a: &[Ciphertext], result: &mut [Ciphertext]);

    fn variance(&self, sk: &ServerKey, a: &Vec<&[Ciphertext]>, count: usize, result: &mut [Ciphertext]);

    fn standard_deviation(
        &self,
        sk: &ServerKey,
        a: &Vec<&[Ciphertext]>,
        count: usize,
        result: &mut [Ciphertext],
    );
    
    fn copy_to_from(&self, target: &mut [Ciphertext], source: &[Ciphertext]);
    
    fn pitch_trim(&self, sk: &ServerKey, ctxt: &mut[Ciphertext]) -> Vec<Ciphertext>;
    fn pitch_trim_bit(&self, sk: &ServerKey, ctxt: &Ciphertext) -> Ciphertext;
}