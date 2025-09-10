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

use tfhe::boolean::prelude::*;

pub trait ProcessorGate {
    /// Compute the encrypted AND gate on the `Ciphertext` vectors `a` and `b`. The result is stored in
    ///  the ` result ` vector.
    ///
    /// `PARAMETERS`.
    /// * `sk`: &ServerKey - The key which the server will use to perform the computation.
    /// * `a`: &[Ciphertext] - The first operand, a vector of ciphertexts, each element encrypting a single bit.
    /// * `b`: &[Ciphertext] - The second operand, a vector of ciphertexts, each element encrypting a single bit.
    /// * `result`: &mut [Ciphertext] - A vector holding the result of the operation.
    ///
    fn e_and(&self, sk: &ServerKey, a: &[Ciphertext], b: &[Ciphertext], result: &mut [Ciphertext]);

    /// Compute the encrypted AND gate on single bit ciphertexts `a` and `b`.
    ///
    /// # Parameters
    /// * `sk`: &ServerKey - The key which the server will use to perform the computation
    /// * `a`: &Ciphertext - The first operand encrypting a single bit
    /// * `b`: &Ciphertext - The second operand encrypting a single bit
    ///
    /// # Returns
    /// * `Ciphertext` - The result of AND operation on the input bits
    fn e_and_bit(&self, sk: &ServerKey, a: &Ciphertext, b: &Ciphertext) -> Ciphertext;

    /// Compute the encrypted AND gate on a range of bits from ciphertext vectors `a` and `b`.
    ///
    /// # Parameters
    /// * `sk`: &ServerKey - The key which the server will use to perform the computation
    /// * `a`: &[Ciphertext] - The first operand vector
    /// * `b`: &[Ciphertext] - The second operand vector
    /// * `result`: &mut [Ciphertext] - Vector to store the result
    /// * `index_low`: usize - Starting index of the range
    /// * `index_high`: usize - Ending index of the range
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
    ///  the ` result ` vector.
    ///
    /// `PARAMETERS`.
    /// * `sk`: &ServerKey - The key which the server will use to perform the computation.
    /// * `a`: &[Ciphertext] - The first operand, a vector of ciphertexts, each element encrypting a single bit.
    /// * `b`: &[Ciphertext] - The second operand, a vector of ciphertexts, each element encrypting a single bit.
    /// * `result`: &mut [Ciphertext] - A vector holding the result of the operation.
    ///
    fn e_or(&self, sk: &ServerKey, a: &[Ciphertext], b: &[Ciphertext], result: &mut [Ciphertext]);

    /// Compute the encrypted OR gate on single bit ciphertexts `a` and `b`.
    ///
    /// # Parameters
    /// * `sk`: &ServerKey - The key which the server will use to perform the computation
    /// * `a`: &Ciphertext - The first operand encrypting a single bit
    /// * `b`: &Ciphertext - The second operand encrypting a single bit
    ///
    /// # Returns
    /// * `Ciphertext` - The result of OR operation on the input bits
    fn e_or_bit(&self, sk: &ServerKey, a: &Ciphertext, b: &Ciphertext) -> Ciphertext;

    /// Compute the encrypted OR gate on a range of bits from ciphertext vectors `a` and `b`.
    ///
    /// # Parameters
    /// * `sk`: &ServerKey - The key which the server will use to perform the computation
    /// * `a`: &[Ciphertext] - The first operand vector
    /// * `b`: &[Ciphertext] - The second operand vector
    /// * `result`: &mut [Ciphertext] - Vector to store the result
    /// * `index_low`: usize - Starting index of the range
    /// * `index_high`: usize - Ending index of the range
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
    ///  the ` result ` vector.
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
    ///  the ` result ` vector.
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
    ///  the ` result ` vector.
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
    ///  the ` result ` vector.
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
    ///  the ` result ` vector.
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

    /// Multiplexer (MUX) operation that selects between two encrypted arrays based on a selector bit.
    ///
    /// # Parameters
    /// * `sk`: &ServerKey - The server key for homomorphic operations
    /// * `selector`: &Ciphertext - The encrypted selector bit
    /// * `ct_then`: &[Ciphertext] - The array to select if selector is 1
    /// * `ct_else`: &[Ciphertext] - The array to select if selector is 0
    /// * `result`: &mut [Ciphertext] - The destination array for the selected value
    fn e_mux(
        &self,
        sk: &ServerKey,
        selector: &Ciphertext,
        ct_then: &[Ciphertext],
        ct_else: &[Ciphertext],
        result: &mut [Ciphertext],
    );

    /// Single bit multiplexer operation that selects between two encrypted bits.
    ///
    /// # Parameters
    /// * `sk`: &ServerKey - The server key for homomorphic operations
    /// * `selector`: &Ciphertext - The encrypted selector bit
    /// * `ct_then`: &Ciphertext - The bit to select if selector is 1
    /// * `ct_else`: &Ciphertext - The bit to select if selector is 0
    ///
    /// # Returns
    /// * Ciphertext - The selected encrypted bit
    fn e_mux_bit(
        &self,
        sk: &ServerKey,
        selector: &Ciphertext,
        ct_then: &Ciphertext,
        ct_else: &Ciphertext,
    ) -> Ciphertext;

    /// Multiplexer operation on a range of bits from the input arrays.
    ///
    /// # Parameters
    /// * `sk`: &ServerKey - The server key for homomorphic operations  
    /// * `selector`: &[Ciphertext] - The selector bits
    /// * `ct_then`: &[Ciphertext] - The array to select from if selector is 1
    /// * `ct_else`: &[Ciphertext] - The array to select from if selector is 0
    /// * `result`: &mut [Ciphertext] - The destination array for selected values
    /// * `index_low`: usize - The starting index of the range
    /// * `index_high`: usize - The ending index of the range
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
    
}