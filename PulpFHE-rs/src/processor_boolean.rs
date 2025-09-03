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

use crate::processor_units::Processor;
use std::process::exit;
use tfhe::boolean::gen_keys;
use tfhe::boolean::prelude::*;
use tfhe::boolean::server_key::RefreshEngine;

#[cfg(test)]
mod test_processor_boolean_8;

pub struct ProcessorBoolean;

impl ProcessorBoolean {
    /// A helper function for performing division and modulo operations.
    fn e_shl_p(&self, a: &[Ciphertext], LSB: &Ciphertext, result: &mut [Ciphertext]) {
        for i in 1..a.len() {
            result[i] = a[i - 1].clone()
        }
        result[0] = LSB.clone();
    }

    /// Tracking functions

    fn ptxt_and(&self, a: &[bool], b: &[bool], result: &mut [bool]) {
        let size: usize = a.len();

        for i in 0..size {
            result[i] = a[i] & b[i];
        }
    }
    fn ptxt_or(&self, a: &[bool], b: &[bool], result: &mut [bool]) {
        let size: usize = a.len();

        for i in 0..size {
            result[i] = a[i] | b[i];
        }
    }

    fn ptxt_xor(&self, a: &[bool], b: &[bool], result: &mut [bool]) {
        let size: usize = a.len();

        for i in 0..size {
            result[i] = a[i] ^ b[i];
        }
    }
    fn ptxt_not(&self, a: &[bool], result: &mut [bool]) {
        let size: usize = a.len();

        for i in 0..size {
            result[i] = !a[i];
        }
    }

    fn ptxt_nand(&self, a: &[bool], b: &[bool], result: &mut [bool]) {
        let size: usize = a.len();

        for i in 0..size {
            result[i] = !(a[i] & b[i]);
        }
    }
    fn ptxt_nor(&self, a: &[bool], b: &[bool], result: &mut [bool]) {
        let size: usize = a.len();

        for i in 0..size {
            result[i] = !(a[i] | b[i]);
        }
    }

    fn ptxt_xnor(&self, a: &[bool], b: &[bool], result: &mut [bool]) {
        let size: usize = a.len();

        for i in 0..size {
            result[i] = !(a[i] ^ b[i]);
        }
    }

    fn ptxt_and_bit(&self, a: bool, b: bool) -> bool {
        let result = a & b;
        result
    }

    fn ptxt_or_bit(&self, a: bool, b: bool) -> bool {
        let result = a | b;
        result
    }

    fn ptxt_not_bit(&self, a: bool) -> bool {
        let result = !a;
        result
    }

    fn ptxt_xor_bit(&self, a: bool, b: bool) -> bool {
        let result = a ^ b;
        result
    }

    fn ptxt_nand_bit(&self, a: bool, b: bool) -> bool {
        let result = !(a & b);
        result
    }

    fn ptxt_nor_bit(&self, a: bool, b: bool) -> bool {
        let result = !(a | b);
        result
    }

    fn ptxt_xnor_bit(&self, a: bool, b: bool) -> bool {
        let result = !(a ^ b);
        result
    }

    fn ptxt_and_range(
        &self,
        a: &[bool],
        b: &[bool],
        result: &mut [bool],
        index_low: usize,
        index_high: usize,
    ) {
        for i in index_low..index_high {
            result[i] = (a[i] & b[i]);
        }
    }

    fn ptxt_or_range(
        &self,
        a: &[bool],
        b: &[bool],
        result: &mut [bool],
        index_low: usize,
        index_high: usize,
    ) {
        for i in index_low..index_high {
            result[i] = a[i] | b[i];
        }
    }

    fn ptxt_xor_range(
        &self,
        a: &[bool],
        b: &[bool],
        result: &mut [bool],
        index_low: usize,
        index_high: usize,
    ) {
        for i in index_low..index_high {
            result[i] = a[i] ^ b[i];
        }
    }

    fn ptxt_not_range(&self, a: &[bool], result: &mut [bool], index_low: usize, index_high: usize) {
        for i in index_low..index_high {
            result[i] = !a[i];
        }
    }

    fn ptxt_nand_range(
        &self,
        a: &[bool],
        b: &[bool],
        result: &mut [bool],
        index_low: usize,
        index_high: usize,
    ) {
        for i in index_low..index_high {
            result[i] = !(a[i] & b[i]);
        }
    }

    fn ptxt_nor_range(
        &self,
        a: &[bool],
        b: &[bool],
        result: &mut [bool],
        index_low: usize,
        index_high: usize,
    ) {
        for i in index_low..index_high {
            result[i] = !(a[i] | b[i]);
        }
    }

    fn ptxt_xnor_range(
        &self,
        a: &[bool],
        b: &[bool],
        result: &mut [bool],
        index_low: usize,
        index_high: usize,
    ) {
        for i in index_low..index_high {
            result[i] = !(a[i] ^ b[i]);
        }
    }

    fn ptxt_shl(&self, a: &[bool], shift_amt: usize, result: &mut [bool]) {
        let len = a.len();
        let shift = shift_amt % len;

        if shift == 0 {
            return;
        }

        let temp: Vec<bool> = a[..shift].to_vec();
        for i in 0..(len - shift) {
            result[i] = a[i + shift];
        }
        for i in 0..shift {
            result[len - shift + i] = temp[i];
        }
    }

    fn ptxt_shr(&self, a: &[bool], shift_amt: usize, result: &mut [bool]) {
        let len = a.len();
        let shift = shift_amt % len;

        if shift == 0 {
            return;
        }

        let temp: Vec<bool> = a[len - shift..].to_vec();
        for i in (0..len - shift).rev() {
            result[i + shift] = a[i];
        }
        for i in 0..shift {
            result[i] = temp[i];
        }
    }

    fn ptxt_rotr(&self, a: &[bool], rot_amt: usize, result: &mut [bool]) {
        let size = a.len();
        if size == 0 || rot_amt == 0 {
            result.copy_from_slice(a);
            return;
        }

        let rot_amt = rot_amt % size;
        result.copy_from_slice(a);
        result.rotate_right(rot_amt);
    }

    fn ptxt_rotl(&self, a: &[bool], rot_amt: usize, result: &mut [bool]) {
        let size = a.len();
        if size == 0 || rot_amt == 0 {
            result.copy_from_slice(a);
            return;
        }

        let rot_amt = rot_amt % size;
        result.copy_from_slice(a);
        result.rotate_left(rot_amt);
    }

    fn ptxt_mux(&self, selector: &bool, a: &[bool], b: &[bool], result: &mut [bool]) {
        let size = a.len();
        for i in 0..size {
            result[i] = if *selector { a[i] } else { b[i] };
        }
    }

    fn ptxt_mux_range(
        &self,
        selector: bool,
        a: &[bool],
        b: &[bool],
        result: &mut [bool],
        index_low: usize,
        index_high: usize,
    ) {
        for i in index_low..index_high {
            result[i] = if selector { a[i] } else { b[i] };
        }
    }

    fn ptxt_mux_bit(&self, selector: bool, a: bool, b: bool) -> bool {
        let result = if selector { a } else { b };
        result
    }

    fn ptxt_adder(&self, a: &[bool], b: &[bool], result: &mut [bool]) {
        let size: usize = a.len();
        let mut carry = false;

        for i in 0..size {
            // Calculate sum and new carry for each bit position
            let temp_sum = a[i] ^ b[i] ^ carry;
            carry = (a[i] & b[i]) | (carry & (a[i] ^ b[i]));
            result[i] = temp_sum;
        }
    }

    fn ptxt_subtracter(&self, a: &[bool], b: &[bool], result: &mut [bool]) {
        let size: usize = a.len();

        self.print_ptxt_vector(a, "a");
        self.print_ptxt_vector(b, "b");
        let mut borrow: Vec<bool> = vec![false; size];
        let mut temp_0: Vec<bool> = vec![false; size];
        let mut temp_1: Vec<bool> = vec![false; size];
        let mut temp_2: Vec<bool> = vec![false; size];

        // Run half subtracter
        result[0] = self.ptxt_xor_bit(a[0], b[0]);
        temp_0[0] = self.ptxt_not_bit(a[0]);
        borrow[0] = self.ptxt_and_bit(temp_0[0], b[0]);

        self.ptxt_xor_range(a, b, &mut temp_0, 1, size);
        self.ptxt_not_range(a, &mut temp_1, 1, size);

        for i in 1..size {
            // Calculate the difference
            result[i] = self.ptxt_xor_bit(temp_0[i], borrow[i - 1]);
            if i != size - 1 {
                temp_2[i] = self.ptxt_and_bit(temp_1[i], b[i]);
                temp_0[i] = self.ptxt_not_bit(temp_0[i]);
                temp_1[i] = self.ptxt_and_bit(borrow[i - 1], temp_0[i]);
                borrow[i] = self.ptxt_or_bit(temp_2[i], temp_1[i]);
            }
        }
        self.print_ptxt_vector(&result, "result");
    }

    fn print_ptxt_vector(&self, a: &[bool], var_name: &str) {
        let size: usize = a.len();
        print!("[{}] = ", var_name);
        for i in 0..size {
            print!("{}", a[i] as u8);
        }
        println!("");
    }
    fn ptxt_vector_to_number(&self, a: &[bool]) -> u64 {
        let size: usize = a.len();
        let mut result: u64 = 0;
        for i in 0..size {
            result = result << 1;
            result = result | if a[i] { 1 } else { 0 };
        }
        result
    }

    fn ptxt_add_supplement(&self, a: &[bool], b: &[bool], size: usize, result: &mut [bool]) {
        if size == 0 {
            return;
        }
        let mut carry: Vec<bool> = vec![false; size + 1];
        let mut temp: Vec<bool> = vec![false; size];
        carry[0] = false;

        self.ptxt_xor_range(a, b, &mut temp, 0, size);

        for i in 0..size - 1 {
            // Compute carry
            carry[i + 1] = if temp[i] { carry[i] } else { a[i] };
        }

        // Compute sum
        self.ptxt_xor_range(&carry, &temp, result, 0, size);
    }

    fn ptxt_multiplier(&self, a: &[bool], b: &[bool], result: &mut [bool]) {
        let size: usize = a.len();
        let mut tmp_array: Vec<bool> = vec![false; size];
        let mut sum: Vec<bool> = vec![false; size];
        let mut temp_sum: Vec<bool> = vec![false; size];
        for i in 0..size {
            for j in 0..size - i {
                tmp_array[j] = self.ptxt_and_bit(a[i], b[j]);
            }
            self.ptxt_add_supplement(&tmp_array, &sum[i..], size - i, &mut temp_sum[i..]);
            sum.clone_from_slice(&temp_sum);
        }
        result.clone_from_slice(&sum);
    }

    /// ## Full Adder
    /// Computes the sum of three encrypted bits (a, b, carry_in)
    /// and returns the sum bit and the carry_out bit.
    fn full_adder(
        &self,
        sk: &ServerKey,
        a: &Ciphertext,
        b: &Ciphertext,
        carry_in: &Ciphertext,
    ) -> (Ciphertext, Ciphertext) {
        let xor_a_b = self.pitch_trim_bit(sk, &sk.xor(a, b));
        let sum = self.pitch_trim_bit(sk, &sk.xor(&xor_a_b, carry_in));

        let and_a_b = self.pitch_trim_bit(sk, &sk.and(a, b));
        let and_carry_xor = self.pitch_trim_bit(sk, &sk.and(carry_in, &xor_a_b));
        let carry_out = self.pitch_trim_bit(sk, &sk.or(&and_a_b, &and_carry_xor));

        (sum, carry_out)
    }

    /// ## 16-bit Ripple-Carry Adder
    /// Adds two 16-bit ciphertext vectors (`b` into `acc`).
    fn add_vec(&self, sk: &ServerKey, acc: &mut [Ciphertext], b: &[Ciphertext]) {
        assert_eq!(
            acc.len(),
            b.len(),
            "Vectors for addition must have the same length."
        );
        let mut carry = Ciphertext::Trivial(false); // Initial carry is 0
        for i in 0..acc.len() {
            // Clone acc[i] to satisfy the borrow checker
            let (sum, new_carry) = self.full_adder(sk, &acc[i].clone(), &b[i], &carry);
            acc[i] = sum;
            carry = new_carry;
        }
    }

    /// ## 16-bit Ripple-Carry Subtractor
    /// Subtracts a 16-bit ciphertext vector from another (`acc -= b`).
    /// Implemented as `acc + NOT(b) + 1`.
    fn sub_vec(&self, sk: &ServerKey, acc: &mut [Ciphertext], b: &[Ciphertext]) {
        assert_eq!(
            acc.len(),
            b.len(),
            "Vectors for subtraction must have the same length."
        );
        let b_not: Vec<Ciphertext> = b.iter().map(|bit| sk.not(bit)).collect();
        let mut carry = Ciphertext::Trivial(true); // Initial carry is 1 for 2's complement
        for i in 0..acc.len() {
            let (sum, new_carry) = self.full_adder(sk, &acc[i].clone(), &b_not[i], &carry);
            acc[i] = sum;
            carry = new_carry;
        }
    }

    /// ## 8x8 Signed Multiplier
    ///
    /// Multiplies two 8-bit signed integers `a` and `b`, encrypted bit-by-bit.
    /// The input vectors are expected to be in little-endian format (LSB at index 0).
    /// The 16-bit result is stored in the `result` slice.
    fn new_multiplier(
        &self,
        sk: &ServerKey,
        a: &[Ciphertext],
        b: &[Ciphertext],
        result: &mut [Ciphertext],
    ) {
        const INPUT_BITS: usize = 8;
        const OUTPUT_BITS: usize = 16;

        assert_eq!(a.len(), INPUT_BITS, "Input 'a' must be 8 bits.");
        assert_eq!(b.len(), INPUT_BITS, "Input 'b' must be 8 bits.");
        assert_eq!(result.len(), OUTPUT_BITS, "Result buffer must be 16 bits.");

        // 1. Initialize result to all zeros
        for bit in result.iter_mut() {
            *bit = Ciphertext::Trivial(false);
        }

        let mut term = vec![Ciphertext::Trivial(false); OUTPUT_BITS];

        // 2. Add the first 7 (INPUT_BITS - 1) partial products
        for i in 0..(INPUT_BITS - 1) {
            // Reset the temporary term vector to zero
            term.iter_mut()
                .for_each(|bit| *bit = Ciphertext::Trivial(false));

            // Calculate the partial product (a * b_i) and place it at the shifted position
            for j in 0..INPUT_BITS {
                term[j + i] = self.pitch_trim_bit(sk, &sk.and(&a[j], &b[i]));
            }

            // Sign-extend this partial product to 16 bits
            let sign_bit = self.pitch_trim_bit(sk, &sk.and(&a[INPUT_BITS - 1], &b[i]));
            for k in (INPUT_BITS + i)..OUTPUT_BITS {
                term[k] = sign_bit.clone();
            }

            // Add the sign-extended and shifted term to the result
            self.add_vec(sk, result, &term);
        }

        // 3. Subtract the last partial product (for the sign bit b_7)
        term.iter_mut()
            .for_each(|bit| *bit = Ciphertext::Trivial(false));

        let i = INPUT_BITS - 1; // i = 7

        // Calculate the partial product (a * b_7) and place it at the shifted position
        for j in 0..INPUT_BITS {
            term[j + i] = self.pitch_trim_bit(sk, &sk.and(&a[j], &b[i]));
        }

        // Sign-extend the last partial product
        let sign_bit = self.pitch_trim_bit(sk, &sk.and(&a[INPUT_BITS - 1], &b[i]));
        for k in (INPUT_BITS + i)..OUTPUT_BITS {
            term[k] = sign_bit.clone();
        }

        // Subtract the final term from the result
        self.sub_vec(sk, result, &term);
    }
}
impl Processor for ProcessorBoolean {
    fn e_and(&self, sk: &ServerKey, a: &[Ciphertext], b: &[Ciphertext], result: &mut [Ciphertext]) {
        let size: usize = a.len();

        for i in 0..size {
            result[i] = self.pitch_trim_bit(sk, &sk.and(&a[i], &b[i]));
        }

        // #[cfg(debug_assertions)]
        // {
        //     println!("DEBUG: `e_and` -> len(a)={}, len(b)={}", size, b.len());
        // }
    }

    fn e_and_bit(&self, sk: &ServerKey, a: &Ciphertext, b: &Ciphertext) -> Ciphertext {
        let result: Ciphertext = self.pitch_trim_bit(sk, &sk.and(a, b));

        // #[cfg(debug_assertions)]
        // {
        //     println!("DEBUG: `e_and_bit`");
        // }
        result
    }

    fn e_and_range(
        &self,
        sk: &ServerKey,
        a: &[Ciphertext],
        b: &[Ciphertext],
        result: &mut [Ciphertext],
        index_low: usize,
        index_high: usize,
    ) {
        assert!(
            index_low < index_high,
            "index_low = {}, index_high = {}",
            index_low,
            index_high
        );

        for i in index_low..index_high {
            result[i] = self.pitch_trim_bit(sk, &sk.and(&a[i], &b[i]));
        }

        // #[cfg(debug_assertions)]
        // {
        //     println!(
        //         "DEBUG: `e_and_range` -> len(a)={}, len(b)={}, index_low={}, index_high={}",
        //         a.len(),
        //         b.len(),
        //         index_low,
        //         index_high
        //     );
        // }
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
    fn e_or(&self, sk: &ServerKey, a: &[Ciphertext], b: &[Ciphertext], result: &mut [Ciphertext]) {
        let size: usize = a.len();
        for i in 0..size {
            result[i] = self.pitch_trim_bit(sk, &sk.or(&a[i], &b[i]));
        }

        // #[cfg(debug_assertions)]
        // {
        //     println!("DEBUG: `e_or` -> len(a)={}, len(b)={}", size, b.len());
        // }
    }

    fn e_or_bit(&self, sk: &ServerKey, a: &Ciphertext, b: &Ciphertext) -> Ciphertext {
        let result: Ciphertext = self.pitch_trim_bit(sk, &sk.or(a, b));

        // #[cfg(debug_assertions)]
        // {
        //     println!("DEBUG: `e_or_bit`");
        // }
        result
    }

    fn e_or_range(
        &self,
        sk: &ServerKey,
        a: &[Ciphertext],
        b: &[Ciphertext],
        result: &mut [Ciphertext],
        index_low: usize,
        index_high: usize,
    ) {
        assert!(
            index_low < index_high,
            "index_low = {}, index_high = {}",
            index_low,
            index_high
        );

        for i in index_low..index_high {
            result[i] = self.pitch_trim_bit(sk, &sk.or(&a[i], &b[i]));
        }

        // #[cfg(debug_assertions)]
        // {
        //     println!(
        //         "DEBUG: `e_or_range` -> len(a)={}, len(b)={}, index_low={}, index_high={}",
        //         a.len(),
        //         b.len(),
        //         index_low,
        //         index_high
        //     );
        // }
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
    fn e_xor(&self, sk: &ServerKey, a: &[Ciphertext], b: &[Ciphertext], result: &mut [Ciphertext]) {
        let size: usize = a.len();
        for i in 0..size {
            result[i] = self.pitch_trim_bit(sk, &sk.xor(&a[i], &b[i]));
            result[i] = self.pitch_trim_bit(sk, &sk.xor(&a[i], &b[i]));
        }

        // #[cfg(debug_assertions)]
        // {
        //     println!("DEBUG: `e_xor` -> len(a)={}, len(b)={}", size, b.len());
        // }
    }

    fn e_xor_bit(&self, sk: &ServerKey, a: &Ciphertext, b: &Ciphertext) -> Ciphertext {
        let result: Ciphertext = self.pitch_trim_bit(sk, &sk.xor(a, b));

        // #[cfg(debug_assertions)]
        // {
        //     println!("DEBUG: `e_xor_bit`");
        // }
        result
    }

    fn e_xor_range(
        &self,
        sk: &ServerKey,
        a: &[Ciphertext],
        b: &[Ciphertext],
        result: &mut [Ciphertext],
        index_low: usize,
        index_high: usize,
    ) {
        assert!(
            index_low < index_high,
            "index_low = {}, index_high = {}",
            index_low,
            index_high
        );

        for i in index_low..index_high {
            result[i] = self.pitch_trim_bit(sk, &sk.xor(&a[i], &b[i]));
        }

        // #[cfg(debug_assertions)]
        // {
        //     println!(
        //         "DEBUG: `e_xor_range` -> len(a)={}, len(b)={}, index_low={}, index_high={}",
        //         a.len(),
        //         b.len(),
        //         index_low,
        //         index_high
        //     );
        // }
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
    fn e_nand(
        &self,
        sk: &ServerKey,
        a: &[Ciphertext],
        b: &[Ciphertext],
        result: &mut [Ciphertext],
    ) {
        let size: usize = a.len();
        for i in 0..size {
            result[i] = self.pitch_trim_bit(sk, &sk.nand(&a[i], &b[i]));
        }

        // #[cfg(debug_assertions)]
        // {
        //     println!("DEBUG: `e_nand` -> len(a)={}, len(b)={}", size, b.len());
        // }
    }

    fn e_nand_bit(&self, sk: &ServerKey, a: &Ciphertext, b: &Ciphertext) -> Ciphertext {
        let result: Ciphertext = self.pitch_trim_bit(sk, &sk.nand(a, b));

        // #[cfg(debug_assertions)]
        // {
        //     println!("DEBUG: `e_nand_bit`");
        // }
        result
    }

    fn e_nand_range(
        &self,
        sk: &ServerKey,
        a: &[Ciphertext],
        b: &[Ciphertext],
        result: &mut [Ciphertext],
        index_low: usize,
        index_high: usize,
    ) {
        assert!(
            index_low < index_high,
            "index_low = {}, index_high = {}",
            index_low,
            index_high
        );

        for i in index_low..index_high {
            result[i] = self.pitch_trim_bit(sk, &sk.nand(&a[i], &b[i]));
        }

        // #[cfg(debug_assertions)]
        // {
        //     println!(
        //         "DEBUG: `e_nand_range` -> len(a)={}, len(b)={}, index_low={}, index_high={}",
        //         a.len(),
        //         b.len(),
        //         index_low,
        //         index_high
        //     );
        // }
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
    fn e_nor(&self, sk: &ServerKey, a: &[Ciphertext], b: &[Ciphertext], result: &mut [Ciphertext]) {
        let size: usize = a.len();
        for i in 0..size {
            result[i] = self.pitch_trim_bit(sk, &sk.nor(&a[i], &b[i]));
        }

        // #[cfg(debug_assertions)]
        // {
        //     println!("DEBUG: `e_nor` -> len(a)={}, len(b)={}", size, b.len());
        // }
    }

    fn e_nor_bit(&self, sk: &ServerKey, a: &Ciphertext, b: &Ciphertext) -> Ciphertext {
        let result: Ciphertext = sk.nor(a, b);

        // #[cfg(debug_assertions)]
        // {
        //     println!("DEBUG: `e_nor_bit`");
        // }
        result
    }

    fn e_nor_range(
        &self,
        sk: &ServerKey,
        a: &[Ciphertext],
        b: &[Ciphertext],
        result: &mut [Ciphertext],
        index_low: usize,
        index_high: usize,
    ) {
        assert!(
            index_low < index_high,
            "index_low = {}, index_high = {}",
            index_low,
            index_high
        );

        for i in index_low..index_high {
            result[i] = self.pitch_trim_bit(sk, &sk.nor(&a[i], &b[i]));
        }

        // #[cfg(debug_assertions)]
        // {
        //     println!(
        //         "DEBUG: `e_nor_range` -> len(a)={}, len(b)={}, index_low={}, index_high={}",
        //         a.len(),
        //         b.len(),
        //         index_low,
        //         index_high
        //     );
        // }
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
    fn e_xnor(
        &self,
        sk: &ServerKey,
        a: &[Ciphertext],
        b: &[Ciphertext],
        result: &mut [Ciphertext],
    ) {
        let size: usize = a.len();
        for i in 0..size {
            result[i] = self.pitch_trim_bit(sk, &sk.xnor(&a[i], &b[i]));
        }

        // #[cfg(debug_assertions)]
        // {
        //     println!("DEBUG: `e_xnor` -> len(a)={}, len(b)={}", size, b.len());
        // }
    }

    fn e_xnor_bit(&self, sk: &ServerKey, a: &Ciphertext, b: &Ciphertext) -> Ciphertext {
        let result: Ciphertext = self.pitch_trim_bit(sk, &sk.xnor(a, b));

        // #[cfg(debug_assertions)]
        // {
        //     println!("DEBUG: `e_xnor_bit`");
        // }
        result
    }

    fn e_xnor_range(
        &self,
        sk: &ServerKey,
        a: &[Ciphertext],
        b: &[Ciphertext],
        result: &mut [Ciphertext],
        index_low: usize,
        index_high: usize,
    ) {
        assert!(
            index_low < index_high,
            "index_low = {}, index_high = {}",
            index_low,
            index_high
        );

        for i in index_low..index_high {
            result[i] = self.pitch_trim_bit(sk, &sk.xnor(&a[i], &b[i]));
        }

        // #[cfg(debug_assertions)]
        // {
        //     println!(
        //         "DEBUG: `e_xnor_range` -> len(a)={}, len(b)={}, index_low={}, index_high={}",
        //         a.len(),
        //         b.len(),
        //         index_low,
        //         index_high
        //     );
        // }
    }

    /// Compute the encrypted NOT gate on the `Ciphertext` vector `a`. The result is stored in
    /// `result` vector.
    ///
    /// `PARAMETERS`.
    /// * `sk`: &ServerKey - The key which the server will use to perform the computation.
    /// * `a`: &[Ciphertext] - A vector of ciphertexts, each element encrypting a single bit.
    /// * `result`: &mut [Ciphertext] - A vector holding the result of the operation.
    ///
    fn e_not(&self, sk: &ServerKey, a: &[Ciphertext], result: &mut [Ciphertext]) {
        let size: usize = a.len();
        for i in 0..size {
            result[i] = sk.not(&a[i]);
        }

        // #[cfg(debug_assertions)]
        // {
        //     println!("DEBUG: `e_not` -> len(a)={}", size);
        // }
    }

    fn e_not_bit(&self, sk: &ServerKey, a: &Ciphertext) -> Ciphertext {
        let result: Ciphertext = sk.not(a);

        // #[cfg(debug_assertions)]
        // {
        //     println!("DEBUG: `e_not_bit`");
        // }
        result
    }

    fn e_not_range(
        &self,
        sk: &ServerKey,
        a: &[Ciphertext],
        result: &mut [Ciphertext],
        index_low: usize,
        index_high: usize,
    ) {
        assert!(
            index_low < index_high,
            "index_low = {}, index_high = {}",
            index_low,
            index_high
        );

        for i in index_low..index_high {
            result[i] = sk.not(&a[i]);
        }

        // #[cfg(debug_assertions)]
        // {
        //     println!(
        //         "DEBUG: `e_not_range` -> len(a)={}, index_low={}, index_high={}",
        //         a.len(),
        //         index_low,
        //         index_high
        //     );
        // }
    }

    fn e_shl(&self, a: &[Ciphertext], shift_amt: usize, result: &mut [Ciphertext]) {
        // Arithmetic shift left (same as logical shift left)
        let mut a = a.to_vec();
        a.reverse();
        let mut tmp = a[shift_amt..].to_vec();
        tmp.extend(vec![Ciphertext::Trivial(false); shift_amt]);
        tmp.reverse();
        self.copy_to_from(result, &tmp);

        // let len = a.len();
        // let shift = shift_amt % len; // Normalize shift if n > len
        //
        // if shift == 0 {
        //     return;
        // }
        // let mut a = a.to_vec();
        // a.reverse();
        // // Temporary buffer to store the first `shift` elements
        // let mut temp: Vec<Ciphertext> = a[..shift].to_vec();
        //
        // // Shift remaining elements to the left
        // for i in 0..(len - shift) {
        //     result[i].clone_from(&a[i + shift]);
        // }
        //
        // // Move the saved elements to the end
        // for i in 0..shift {
        //     result[len - shift + i].clone_from(&temp[i]);
        // }
        // result.reverse();
    }

    fn e_shr(&self, a: &[Ciphertext], shift_amt: usize, result: &mut [Ciphertext]) {
        if a.is_empty() {
            self.copy_to_from(result, a);
            return;
        }
        let mut a = a.to_vec();
        a.reverse();
        let mut shifted = vec![a[0].clone(); shift_amt]; // extend sign bit
        shifted.extend_from_slice(&a[..a.len().saturating_sub(shift_amt)]);
        shifted.reverse();
        self.copy_to_from(result, &shifted);

        // let len = a.len();
        // let shift = shift_amt % len; // Normalize shift if n > len
        //
        // if shift == 0 {
        //     return;
        // }
        //
        // let mut a = a.to_vec();
        // a.reverse();
        //
        //
        // // Temporary buffer to store the last `shift` elements
        // let temp: Vec<Ciphertext> = a[..len - shift].to_vec();
        //
        // // Shift elements to the right
        // for i in (0..len - shift) {
        //     result[i + shift].clone_from(&a[i]);
        // }
        //
        // // Move the saved elements to the front
        // for i in 0..shift {
        //     result[i].clone_from(&temp[i]);
        // }
        // result.reverse();
    }

    fn e_rotr(&self, a: &[Ciphertext], rot_amt: usize, result: &mut [Ciphertext]) {
        let mut tmp = a.to_vec();
        // The reverse of the operation because of the binary encoding is LSB...MSB
        tmp.rotate_left(rot_amt % a.len());
        self.copy_to_from(result, &tmp);
        // let size: usize = a.len();
        // let mut temp: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); size];
        //
        // for (r, q) in result.iter_mut().zip(a.iter()) {
        //     r.clone_from(q);
        // }
        //
        // for i in 0..rot_amt {
        //     let lsb: Ciphertext = result[0].clone();
        //     for j in 0..size - 1 {
        //         temp[j].clone_from(&result[j + 1]);
        //     }
        //     temp[size - 1].clone_from(&lsb);
        //
        //     for (r, q) in result.iter_mut().zip(temp.iter()) {
        //         r.clone_from(q);
        //     }
        // }
        // let size = a.len();
        // if size == 0 || rot_amt == 0 {
        //     // Copy input to result for empty arrays or no rotation
        //     for (r, q) in result.iter_mut().zip(a.iter()) {
        //         r.clone_from(q);
        //     }
        //     return;
        // }
        //
        // // Normalize rotation amount to avoid unnecessary iterations
        // let rot_amt = rot_amt % size;
        //
        // // Copy input to the result first
        // for (r, q) in result.iter_mut().zip(a.iter()) {
        //     r.clone_from(q);
        // }
        //
        // // Perform the left rotation in-place
        // result.rotate_right(rot_amt);
    }

    fn e_rotl(&self, a: &[Ciphertext], rot_amt: usize, result: &mut [Ciphertext]) {
        let mut tmp = a.to_vec();
        // The reverse of the operation because of the binary encoding is LSB...MSB
        tmp.rotate_right(rot_amt % a.len());
        self.copy_to_from(result, &tmp);

        // let size: usize = a.len();
        // // let mut temp: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); size];
        // //
        // // for (r, q) in result.iter_mut().zip(a.iter()) {
        // //     r.clone_from(q);
        // // }
        // //
        // // for i in 0..rot_amt {
        // //     let msb: Ciphertext = result[size - 1].clone();
        // //     for j in 1..size {
        // //         temp[j].clone_from(&result[j - 1]);
        // //     }
        // //     temp[0].clone_from(&msb);
        // //
        // //     for (r, q) in result.iter_mut().zip(temp.iter()) {
        // //         r.clone_from(q);
        // //     }
        // // }
        // let size = a.len();
        // if size == 0 || rot_amt == 0 {
        //     // Copy input to result for empty arrays or no rotation
        //     for (r, q) in result.iter_mut().zip(a.iter()) {
        //         r.clone_from(q);
        //     }
        //     return;
        // }
        //
        // // Normalize rotation amount to avoid unnecessary iterations
        // let rot_amt = rot_amt % size;
        //
        // // Copy input to the result first
        // for (r, q) in result.iter_mut().zip(a.iter()) {
        //     r.clone_from(q);
        // }
        //
        // // Perform the left rotation in-place
    }

    fn e_mux(
        &self,
        sk: &ServerKey,
        selector: &Ciphertext,
        ct_then: &[Ciphertext],
        ct_else: &[Ciphertext],
        result: &mut [Ciphertext],
    ) {
        for i in 0..ct_then.len() {
            result[i] = sk.mux(&selector, &ct_then[i], &ct_else[i]);
        }
    }

    fn e_mux_bit(
        &self,
        sk: &ServerKey,
        selector: &Ciphertext,
        ct_then: &Ciphertext,
        ct_else: &Ciphertext,
    ) -> Ciphertext {
        let result: Ciphertext = sk.mux(selector, ct_then, ct_else);
        result
    }

    fn e_mux_range(
        &self,
        sk: &ServerKey,
        selector: &[Ciphertext],
        ct_then: &[Ciphertext],
        ct_else: &[Ciphertext],
        result: &mut [Ciphertext],
        index_low: usize,
        index_high: usize,
    ) {
        for i in index_low..index_high {
            result[i] = sk.mux(&selector[i], &ct_then[i], &ct_else[i]);
        }
    }

    fn comparator(
        &self,
        sk: &ServerKey,
        a: &[Ciphertext],
        b: &[Ciphertext],
        select: u8,
    ) -> Ciphertext {
        let size: usize = a.len();

        let mut not_a: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); size];
        self.e_not(sk, a, &mut not_a);

        let mut not_b: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); size];
        self.e_not(sk, b, &mut not_b);

        let mut temp: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); 10];
        let mut greater_than: Ciphertext = sk.trivial_encrypt(false);
        let mut less_than: Ciphertext = sk.trivial_encrypt(false);
        let mut equal: Ciphertext = sk.trivial_encrypt(true);
        for i in (0..size).rev() {
            temp[0] = self.e_not_bit(sk, &greater_than);
            temp[1] = self.e_nand_bit(sk, &a[i], &not_b[0]);
            temp[2] = self.e_nand_bit(sk, &temp[1], &equal);
            temp[3] = self.e_not_bit(sk, &temp[2]);
            greater_than = self.e_nand_bit(sk, &temp[0], &temp[3]);
            temp[8] = self.e_not_bit(sk, &less_than);
            greater_than = self.e_and_bit(sk, &temp[8], &greater_than);

            // compute less than path
            temp[4] = self.e_not_bit(sk, &less_than);
            temp[5] = self.e_nand_bit(sk, &not_a[0], &b[i]);
            temp[6] = self.e_nand_bit(sk, &temp[5], &equal);
            temp[7] = self.e_not_bit(sk, &temp[6]);
            less_than = self.e_nand_bit(sk, &temp[7], &temp[4]);
            temp[9] = self.e_not_bit(sk, &greater_than);
            less_than = self.e_and_bit(sk, &temp[9], &less_than);

            // compute equality path
            equal = self.e_nor_bit(sk, &greater_than, &less_than);
        }

        let mut result: Ciphertext = Ciphertext::Trivial(false);
        // select desired output
        if select == 0 {
            // ecmpeq
            result.clone_from(&equal);
        } else if select == 1 {
            // ecmpl
            result.clone_from(&less_than);
        } else if select == 2 {
            // ecmpg
            result.clone_from(&greater_than);
        } else if select == 3 {
            // ecmpgeq
            result = self.e_or_bit(sk, &equal, &greater_than);
        } else if select == 4 {
            // ecmpleq
            result = self.e_or_bit(sk, &equal, &less_than);
        } else if select == 5 {
            // ecmpneq
            result = self.e_not_bit(sk, &equal);
        }

        result
    }

    fn compare_bit(
        &self,
        sk: &ServerKey,
        a: &Ciphertext,
        b: &Ciphertext,
        lsb_carry: &Ciphertext,
    ) -> Ciphertext {
        let tmp = self.e_xnor_bit(sk, a, b);
        let result: Ciphertext = self.e_mux_bit(sk, &tmp, lsb_carry, a);
        result
    }

    fn subtracter(
        &self,
        sk: &ServerKey,
        a: &[Ciphertext],
        b: &[Ciphertext],
        result: &mut [Ciphertext],
    ) {
        let size: usize = a.len();

        let mut borrow: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); size];
        let mut temp_0: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); size];
        let mut temp_1: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); size];
        let mut temp_2: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); size];

        // Run half subtracter
        result[0] = self.e_xor_bit(sk, &a[0], &b[0]);
        temp_0[0] = self.e_not_bit(sk, &a[0]);
        borrow[0] = self.e_and_bit(sk, &temp_0[0], &b[0]);

        self.e_xor_range(sk, &a, &b, &mut temp_0, 1, size);
        self.e_not_range(sk, &a, &mut temp_1, 1, size);

        for i in 1..size {
            // Calculate the difference
            result[i] = self.e_xor_bit(sk, &temp_0[i], &borrow[i - 1]);

            if i != size - 1 {
                temp_2[i] = self.e_and_bit(sk, &temp_1[i], &b[i]);
                temp_0[i] = self.e_not_bit(sk, &temp_0[i]);
                temp_1[i] = self.e_and_bit(sk, &borrow[i - 1], &temp_0[i]);
                borrow[i] = self.e_or_bit(sk, &temp_2[i], &temp_1[i]);
            }
        }
    }
    //
    // fn adder(&self, sk: &ServerKey, a: &[Ciphertext], b: &[Ciphertext], result: &mut [Ciphertext]) {
    //     let size: usize = a.len();
    //
    //     let mut carry: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); size + 1];
    //     let mut temp: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); size];
    //
    //     self.e_xor(sk, &a, &b, &mut temp);
    //
    //     for i in 0..size {
    //         result[i] = self.e_xor_bit(sk, &carry[i], &temp[i]);
    //         if i != size - 1 {
    //             carry[i + 1] = self.e_mux_bit(sk, &temp[i], &carry[i], &a[i]);
    //         }
    //     }
    // }
    fn adder(&self, sk: &ServerKey, a: &[Ciphertext], b: &[Ciphertext], result: &mut [Ciphertext]) {
        // Validate input lengths
        let size = a.len();

        // Initialize temporary vectors
        let mut carry: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); size + 1]; // Includes carry-out
        let mut temp: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); size];
        let mut a_and_b: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); size];

        // Compute a XOR b for all bits
        self.e_xor(sk, a, b, &mut temp);
        self.e_and(sk, a, b, &mut a_and_b);
        // Ripple-carry adder logic
        for i in 0..size {
            // Sum bit: result[i] = a[i] XOR b[i] XOR carry[i]
            result[i] = self.e_xor_bit(sk, &carry[i], &temp[i]);

            if i != size - 1 {
                // Carry bit: carry[i+1] = (a[i] AND b[i]) OR (a[i] AND carry[i]) OR (b[i] AND carry[i])
                let a_and_carry = self.e_and_bit(sk, &a[i], &carry[i]);
                let b_and_carry = self.e_and_bit(sk, &b[i], &carry[i]);
                let temp_carry = self.e_or_bit(sk, &a_and_b[i], &a_and_carry);
                carry[i + 1] = self.e_or_bit(sk, &temp_carry, &b_and_carry);
            }
        }
    }
    fn sign_adder(
        &self,
        sk: &ServerKey,
        a: &[Ciphertext],
        b: &[Ciphertext],
        result: &mut [Ciphertext],
    ) {
        let size: usize = a.len();
        if size < 2 {
            // Handle edge case if necessary
            return;
        }
        let mag_size: usize = size - 1;

        let sign_a: Ciphertext = a[size - 1].clone();
        let sign_b: Ciphertext = b[size - 1].clone();

        let mut same_sign = self.e_xor_bit(sk, &sign_a, &sign_b);

        let mag_a = &a[0..mag_size];
        let mag_b = &b[0..mag_size];

        // Compute add_mag: magnitude addition with initial carry 0
        let mut add_mag: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); mag_size];
        let mut temp: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); mag_size];
        self.e_xor(sk, mag_a, mag_b, &mut temp);
        let mut carry: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); mag_size + 1];
        carry[0] = sk.trivial_encrypt(false);
        for i in 0..mag_size {
            add_mag[i] = self.e_xor_bit(sk, &carry[i], &temp[i]);
            carry[i + 1] = self.e_mux_bit(sk, &temp[i], &carry[i], &mag_a[i]);
        }

        // Compute inv_mag_b
        //let true_ct = sk.trivial_encrypt(true);
        let mut inv_mag_b: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); mag_size];
        /*for i in 0..mag_size {
            inv_mag_b[i] = self.e_xor_bit(sk, &mag_b[i], &true_ct);
        }*/
        self.e_not(sk, mag_b, &mut inv_mag_b);

        // Compute sub_mag_a_minus_b: mag_a - mag_b with initial carry 1
        //let mut sub_mag_a_minus_b: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); mag_size];
        let mut temp_sub: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); mag_size];
        self.e_xor(sk, mag_a, &inv_mag_b, &mut temp_sub);
        let mut carry_sub: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); mag_size + 1];
        carry_sub[0] = sk.trivial_encrypt(true);
        for i in 0..mag_size {
            //sub_mag_a_minus_b[i] = self.e_xor_bit(sk, &carry_sub[i], &temp_sub[i]);
            carry_sub[i + 1] = self.e_mux_bit(sk, &temp_sub[i], &carry_sub[i], &mag_a[i]);
        }
        let is_a_ge_b = carry_sub[mag_size].clone();

        // Larger and smaller
        let mut larger_mag: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); mag_size];
        let mut smaller_mag: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); mag_size];
        self.e_mux(sk, &is_a_ge_b, &mag_a, &mag_b, &mut larger_mag);
        self.e_mux(sk, &is_a_ge_b, &mag_b, &mag_a, &mut smaller_mag);

        /* for i in 0..mag_size {
            larger_mag[i] = self.e_mux_bit(sk, &is_a_ge_b, &mag_a[i], &mag_b[i]);
            smaller_mag[i] = self.e_mux_bit(sk, &is_a_ge_b, &mag_b[i], &mag_a[i]);
        }*/
        let mut larger_sign = self.e_mux_bit(sk, &is_a_ge_b, &sign_a, &sign_b);

        // Compute inv_smaller
        let mut inv_smaller: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); mag_size];
        self.e_not(sk, &smaller_mag, &mut inv_smaller);
        /*for i in 0..mag_size {
            inv_smaller[i] = self.e_xor_bit(sk, &smaller_mag[i], &true_ct);
        }*/

        // Compute sub_mag: larger_mag - smaller_mag with initial carry 1
        let mut sub_mag: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); mag_size];
        let mut temp_diff: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); mag_size];
        self.e_xor(sk, &larger_mag, &inv_smaller, &mut temp_diff);
        let mut carry_diff: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); mag_size + 1];
        carry_diff[0] = sk.trivial_encrypt(true);
        for i in 0..mag_size {
            sub_mag[i] = self.e_xor_bit(sk, &carry_diff[i], &temp_diff[i]);
            carry_diff[i + 1] = self.e_mux_bit(sk, &temp_diff[i], &carry_diff[i], &larger_mag[i]);
        }

        // Final result_mag and result_sign
        let mut result_mag: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); mag_size];
        self.e_mux(sk, &same_sign, &sub_mag, &add_mag, &mut result_mag);
        /*for i in 0..mag_size {
            result_mag[i] = self.e_mux_bit(sk, &same_sign, &sub_mag[i], &add_mag[i]);
        }*/
        let result_sign = self.e_mux_bit(sk, &same_sign, &larger_sign, &sign_a);

        // Set result
        for i in 0..mag_size {
            result[i] = result_mag[i].clone();
        }
        result[size - 1] = result_sign;
    }

    fn half_adder(
        &self,
        sk: &ServerKey,
        a: &Ciphertext,
        b: &Ciphertext,
        carry: &mut Ciphertext,
        result: &mut Ciphertext,
    ) {
        *result = self.e_xor_bit(sk, &a, &b);
        *carry = self.e_and_bit(sk, &a, &b);
    }

    fn carry_save_adder(
        &self,
        sk: &ServerKey,
        a: &Ciphertext,
        b: &Ciphertext,
        cin: &Ciphertext,
        carry: &mut Ciphertext,
        result: &mut Ciphertext,
    ) {
        let mut tmp: Ciphertext = self.e_xor_bit(sk, a, b);
        *result = self.e_xor_bit(sk, &tmp, cin);

        let t0: Ciphertext = self.e_and_bit(sk, a, b);
        let t1: Ciphertext = self.e_and_bit(sk, cin, b);
        let t2: Ciphertext = self.e_and_bit(sk, a, cin);

        tmp = self.e_or_bit(sk, &t0, &t1);
        *carry = self.e_or_bit(sk, &tmp, &t2);
    }

    fn add_supplement(
        &self,
        sk: &ServerKey,
        a: &[Ciphertext],
        b: &[Ciphertext],
        size: usize,
        result: &mut [Ciphertext],
    ) {
        if size == 0 {
            return;
        }
        let mut carry: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); size + 1];
        let mut temp: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); size];

        self.e_xor_range(sk, a, b, &mut temp, 0, size);
        let mut a_and_b: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); size];
        let mut tmp_c = sk.trivial_encrypt(false);
        self.e_and_range(sk, &a, &b, &mut a_and_b, 0, size);

        for i in 0..size {
            tmp_c = self.e_and_bit(sk, &temp[i], &carry[i]);
            // Compute carry
            carry[i + 1] = self.e_or_bit(sk, &a_and_b[i], &tmp_c)
        }

        self.e_xor_range(sk, &carry, &temp, result, 0, size);
    }

    fn multiplier(
        &self,
        sk: &ServerKey,
        a: &[Ciphertext],
        b: &[Ciphertext],
        result: &mut [Ciphertext],
    ) {
        let size: usize = a.len();
        let mut tmp_array: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); size];
        let mut sum: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); size];
        let mut temp_sum: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); size];
        for i in 0..size {
            for j in 0..size - i {
                tmp_array[j] = self.e_and_bit(sk, &a[i], &b[j]);
            }
            self.add_supplement(sk, &mut tmp_array, &sum[i..], size - i, &mut temp_sum[i..]);
            self.copy_to_from(&mut sum, &temp_sum);
        }

        self.copy_to_from(result, &sum);
    }

    fn blake3(
        &self,
        sk: &ServerKey,
        msg: Vec<&[Ciphertext]>,
        v: Vec<&[Ciphertext]>,
        result: &mut Vec<&mut [Ciphertext]>,
    ) {
        let size: usize = msg[0].len();
        let mut a: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); size];
        let mut b: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); size];
        let mut c: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); size];
        let mut d: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); size];
        let mut m0: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); size];
        let mut m1: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); size];

        let mut tmp_a: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); size];
        let mut tmp_b: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); size];
        let mut tmp_c: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); size];
        let mut tmp_d: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); size];

        // Unpack the inputs
        self.copy_to_from(&mut a, v[0]);
        self.copy_to_from(&mut b, v[1]);
        self.copy_to_from(&mut c, v[2]);
        self.copy_to_from(&mut d, v[3]);
        self.copy_to_from(&mut m0, msg[0]);
        self.copy_to_from(&mut m1, msg[1]);

        // Step 1: a = a + b + m0
        // Step 1.1: a = a + b
        self.adder(sk, &a, &b, &mut tmp_a);
        // Step 1.2: a = a + m0
        self.adder(sk, &tmp_a, &m0, &mut a);

        // Step 2: d = (d XOR a ) >>> 16
        // Step 2.1: d = d XOR a
        self.e_xor(sk, &d, &a, &mut tmp_d);
        self.e_rotr(&tmp_d, 16, &mut d);

        // Step 3: c = c + d
        tmp_c.clone_from(&c);
        self.adder(sk, &tmp_c, &d, &mut c);

        // Step 4: b = (b XOR c) >>> 12
        // Step 4.1: b = b XOR c
        self.e_xor(sk, &b, &c, &mut tmp_b);
        // Step 4.2: b = b >>> 12
        self.e_rotr(&tmp_b, 12, &mut b);

        // Step 5: a = a + b + m1
        // Step 5.1: a = a + b
        self.adder(sk, &a, &b, &mut tmp_a);
        // Step 5.2: a = a + m1
        self.adder(sk, &tmp_a, &m1, &mut a);

        // Step 6: d = (d XOR a ) >>> 8
        // Step 6.1: d = d XOR a
        self.e_xor(sk, &d, &a, &mut tmp_d);
        // Step 6.2: d = d >>> 8
        self.e_rotr(&tmp_d, 8, &mut d);

        // Step 7: c = c + d
        tmp_c.clone_from(&c);
        self.adder(sk, &tmp_c, &d, &mut c);

        // Step 8: b = (b XOR c) >>> 12
        // Step 8.1: b = b XOR c
        self.e_xor(sk, &b, &c, &mut tmp_b);
        // Step 8.2: b = b >>> 7
        self.e_rotr(&tmp_b, 7, &mut b);

        self.copy_to_from(result[0], &a);
        self.copy_to_from(result[1], &b);
        self.copy_to_from(result[2], &c);
        self.copy_to_from(result[3], &d);
    }

    fn max(&self, sk: &ServerKey, a: &Vec<&[Ciphertext]>, result: &mut [Ciphertext]) {
        //does not handle negative numbers
        let size = a[0].len();
        let mut max: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); size];
        let mut selector: Ciphertext = sk.trivial_encrypt(false);
        let mut current: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); size];

        self.copy_to_from(&mut max, &a[0]);

        for indx in 0..a.len() {
            self.copy_to_from(&mut current, &a[indx]);

            // tmps[0] is the result of the comparison: 0 if a is larger, 1 if b is larger
            // select the max and copy it to the result
            for i in 0..size {
                selector = self.compare_bit(sk, &max[i], &current[i], &selector);
            }
            self.e_mux(sk, &selector, &max, &current, result);

            if indx != size - 1 {
                self.copy_to_from(&mut max, result);
            }
        }
    }

    fn min(&self, sk: &ServerKey, a: &Vec<&[Ciphertext]>, result: &mut [Ciphertext]) {
        let size = a[0].len();
        let mut min: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); size];
        let mut selector: Ciphertext = sk.trivial_encrypt(false);
        let mut current: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); size];

        self.copy_to_from(&mut min, a[0]);

        for indx in 0..a.len() {
            self.copy_to_from(&mut current, &a[indx]);

            // tmps[0] is the result of the comparison: 0 if a is larger, 1 if b is larger
            // select the max and copy it to the result
            for i in 0..size {
                selector = self.compare_bit(sk, &min[i], &current[i], &selector);
            }

            self.e_mux(sk, &selector, &current, &min, result);

            if indx != size - 1 {
                self.copy_to_from(&mut min, result);
            }
        }
    }

    fn relu(&self, sk: &ServerKey, a: &[Ciphertext], result: &mut [Ciphertext]) {
        let size = a.len();
        let sign = &a[size - 1];
        let zero = vec![Ciphertext::Trivial(false); size];
        self.e_mux(sk, &sign, &zero, &a, result);
    }

    /*    fn divider(
        &self,
        sk: &ServerKey,
        a: &[Ciphertext],
        b: &[Ciphertext],
        result: &mut [Ciphertext],
    ) {
        let size = a.len();
        //  Q is the dividend, copy the bits from a to Q
        let mut Q: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); size];
        // A is the remainder, initialize to 0
        let mut A: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); size];
        // M is the divisor, copy the bits from b to M
        let mut M: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); size];

        let mut MSB: Ciphertext = sk.trivial_encrypt(false);
        let zero: Ciphertext = sk.trivial_encrypt(false);
        let mut A_msb: Ciphertext = sk.trivial_encrypt(false);
        let mut not_A_msb: Ciphertext = sk.trivial_encrypt(false);
        let mut A_tmp: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); size];
        let mut Q_tmp: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); size];
        let mut A_m: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); size];

        self.copy_to_from(&mut Q, &a);
        self.copy_to_from(&mut M, &b);

        for i in 0..size {
            // Left shift Q, and replace the LSB with 0
            self.e_shl_p(&Q, &zero, &mut Q_tmp);

            // Store the MSB
            MSB = Q[size - 1].clone();

            // Update Q after shifting
            self.copy_to_from(&mut Q, &Q_tmp);

            // Left shift A and replace the LSB with MSB from the previous step
            self.e_shl_p(&A, &MSB, &mut A_tmp);

            // Compute A = A-M
            self.subtracter(sk, &A_tmp, &M, &mut A);

            // Get the MSB of A
            A_msb = A[size - 1].clone();

            // Compute Not(MSB of A)
            not_A_msb = self.e_not_bit(sk, &A_msb);
            // Replace the LSB of Q with NOT(MSB of A)
            Q[0] = not_A_msb.clone();
            if i != size - 1 {
                // Compute A = A + M
                self.adder(sk, &A, &M, &mut A_m);

                // If MSB of A is 1, use A + M result, else keep A unchanged
                self.e_mux(sk, &A_msb, &A_m, &A, &mut A_tmp);
                self.copy_to_from(&mut A, &A_tmp);
            }
        }

        self.copy_to_from(result, &Q);
    }*/

    // For negatives?
    fn divider(
        &self,
        sk: &ServerKey,
        a: &[Ciphertext],
        b: &[Ciphertext],
        result: &mut [Ciphertext],
    ) {
        let size = a.len();
        //  Q is the dividend, copy the bits from a to Q
        let mut Q: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); size];
        // A is the remainder, initialize to 0
        let mut A: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); size];
        // M is the divisor, copy the bits from b to M
        let mut M: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); size];

        let mut MSB: Ciphertext = sk.trivial_encrypt(false);
        let zero: Ciphertext = sk.trivial_encrypt(false);
        let mut A_msb: Ciphertext = sk.trivial_encrypt(false);
        let mut not_A_msb: Ciphertext = sk.trivial_encrypt(false);
        let mut A_tmp: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); size];
        let mut Q_tmp: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); size];
        let mut A_m: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); size];
        let mut M_tmp: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); size];

        let sign_bit = self.e_xor_bit(sk, &a[size - 1], &b[size - 1]);
        let mut inv_res: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); size];
        let mut inv_res_tmp: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); size];
        let mut ones: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); size];
        ones[0] = sk.trivial_encrypt(true);

        // self.copy_to_from(&mut Q, &a);
        // self.copy_to_from(&mut M, &b);

        // Compute the two's complement of Q
        self.e_not(sk, &a, &mut Q);
        self.adder(sk, &Q, &ones, &mut Q_tmp);
        self.e_mux(sk, &a[size - 1], &Q_tmp, &a, &mut Q);

        // Compute the two's complement of M
        self.e_not(sk, &b, &mut M);
        self.adder(sk, &M, &ones, &mut M_tmp);
        self.e_mux(sk, &b[size - 1], &M_tmp, &b, &mut M);

        for i in 0..size {
            // Left shift Q, and replace the LSB with 0
            self.e_shl_p(&Q, &zero, &mut Q_tmp);

            // Store the MSB
            MSB = Q[size - 1].clone();

            // Update Q after shifting
            self.copy_to_from(&mut Q, &Q_tmp);

            // Left shift A and replace the LSB with MSB from the previous step
            self.e_shl_p(&A, &MSB, &mut A_tmp);

            // Compute A = A-M
            self.subtracter(sk, &A_tmp, &M, &mut A);

            // Get the MSB of A
            A_msb = A[size - 1].clone();

            // Compute Not(MSB of A)
            not_A_msb = self.e_not_bit(sk, &A_msb);

            // Replace the LSB of Q with NOT(MSB of A)
            Q[0] = not_A_msb.clone();
            if i != size - 1 {
                // Compute A = A + M
                self.adder(sk, &A, &M, &mut A_m);

                // If MSB of A is 1, use A + M result, else keep A unchanged
                self.e_mux(sk, &A_msb, &A_m, &A, &mut A_tmp);
                self.copy_to_from(&mut A, &A_tmp);
            }
        }

        // Perform the two's complement
        self.e_not(sk, &Q, &mut inv_res);
        self.adder(sk, &inv_res, &ones, &mut inv_res_tmp);
        self.e_mux(sk, &sign_bit, &inv_res_tmp, &Q, result);
        // self.copy_to_from(result, &Q);
    }

    fn modulo(
        &self,
        sk: &ServerKey,
        a: &[Ciphertext],
        b: &[Ciphertext],
        result: &mut [Ciphertext],
    ) {
        let size = a.len();
        //  Q is the dividend, copy the bits from a to Q
        let mut Q: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); size];
        // A is the remainder, initialize to 0
        let mut A: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); size];
        // M is the divisor, copy the bits from b to M
        let mut M: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); size];

        let mut MSB: Ciphertext = sk.trivial_encrypt(false);
        let zero: Ciphertext = sk.trivial_encrypt(false);
        let mut A_msb: Ciphertext = sk.trivial_encrypt(false);
        let mut not_A_msb: Ciphertext = sk.trivial_encrypt(false);
        let mut A_tmp: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); size];
        let mut Q_tmp: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); size];
        let mut A_m: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); size];

        let sign_bit = self.e_xor_bit(sk, &a[size - 1], &b[size - 1]);
        let mut inv_res: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); size];
        let mut inv_res_tmp: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); size];
        let mut ones: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); size];
        ones[0] = sk.trivial_encrypt(true);

        self.copy_to_from(&mut Q, &a);
        self.copy_to_from(&mut M, &b);

        for i in 0..size {
            // Left shift Q, and replace the LSB with 0
            self.e_shl_p(&Q, &zero, &mut Q_tmp);

            // Store the MSB
            MSB = Q[size - 1].clone();

            // Update Q after shifting
            self.copy_to_from(&mut Q, &Q_tmp);

            // Left shift A and replace the LSB with MSB from the previous step
            self.e_shl_p(&A, &MSB, &mut A_tmp);

            // Compute A = A-M
            self.subtracter(sk, &A_tmp, &M, &mut A);

            // Get the MSB of A
            A_msb = A[size - 1].clone();

            // Compute Not(MSB of A)
            not_A_msb = self.e_not_bit(sk, &A_msb);

            // Replace the LSB of Q with NOT(MSB of A)
            Q[0] = not_A_msb.clone();

            // Compute A = A + M
            self.adder(sk, &A, &M, &mut A_m);

            // If MSB of A is 1, use A + M result, else keep A unchanged
            self.e_mux(sk, &A_msb, &A_m, &A, &mut A_tmp);
            self.copy_to_from(&mut A, &A_tmp);
        }

        // Perform the two's complement
        self.e_not(sk, &A, &mut inv_res);
        self.adder(sk, &inv_res, &ones, &mut inv_res_tmp);
        self.e_mux(sk, &sign_bit, &inv_res_tmp, &A, result);
        self.copy_to_from(result, &A);
    }

    fn mean(
        &self,
        sk: &ServerKey,
        a: &Vec<&[Ciphertext]>,
        count: usize,
        result: &mut [Ciphertext],
    ) {
        let size: usize = a[0].len();
        let mut sum: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); size];
        let mut tmp_sum: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); size];
        self.copy_to_from(&mut sum, a[0]);

        for i in 1..count {
            self.adder(sk, &sum, a[i], &mut tmp_sum);
            self.copy_to_from(&mut sum, &tmp_sum);
        }

        // Trivially encrypt the bits of count
        let mut bits: Vec<bool> = Vec::new();
        for i in (0..a[0].len()) {
            let bit = ((count >> i) & 1) != 0;
            bits.push(bit);
        }
        let c_count: Vec<_> = bits.iter().map(|&bit| sk.trivial_encrypt(bit)).collect();

        self.divider(sk, &sum, &c_count, result);
    }

    fn sqrt(&self, sk: &ServerKey, a: &[Ciphertext], result: &mut [Ciphertext]) {
        let size: usize = a.len();

        let mut x: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); size];
        let mut y: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); size];
        let mut x_y: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); size];
        let mut x_2: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); size];
        let mut two: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); size];

        let mut n_iters: u8 = 0;
        if size == 8 {
            n_iters = 5;
        } else if size == 16 {
            n_iters = 10;
        } else if size == 32 {
            n_iters = 20;
        } else {
            eprintln!("An error occurred at `e_sqrt`, the supported data sizes 8, 16, and 32");
            exit(1);
        }
        self.copy_to_from(&mut x, &a);

        y[0] = sk.trivial_encrypt(true);
        for i in 1..size {
            y[i] = sk.trivial_encrypt(false);
        }
        for i in 0..size {
            if i == 1 {
                two[i] = sk.trivial_encrypt(true);
            } else {
                two[i] = sk.trivial_encrypt(false);
            }
        }

        for i in 0..n_iters {
            self.adder(sk, &x, &y, &mut x_y);
            self.divider(sk, &x_y, &two, &mut x);

            if i != n_iters - 1 {
                self.divider(sk, &a, &x, &mut y);
            }
        }
        self.copy_to_from(result, &x);
    }

    fn variance(
        &self,
        sk: &ServerKey,
        a: &Vec<&[Ciphertext]>,
        count: usize,
        result: &mut [Ciphertext],
    ) {
        let size: usize = a[0].len();
        let mut m: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); size];
        self.mean(sk, a, count, &mut m);

        let mut subs_squars: Vec<Vec<Ciphertext>> = Vec::with_capacity(count);
        let mut squars: Vec<Vec<Ciphertext>> = Vec::with_capacity(count);
        let mut subs: Vec<Vec<Ciphertext>> = Vec::with_capacity(count);
        let mut sum: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); size];
        let mut tmp_sum: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); size];

        for _ in 0..count {
            let sub: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); size];
            let sqr: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); size];
            subs.push(sub);
            squars.push(sqr);
        }

        for i in 0..count {
            self.subtracter(sk, a[i], &m, &mut subs[i]);
        }

        for i in 0..count {
            self.multiplier(sk, &subs[i], &subs[i], &mut squars[i]);
            subs_squars.push(squars[i].clone());
        }

        self.copy_to_from(&mut sum, &subs_squars[0]);

        // sum the values
        for i in 1..count {
            self.adder(sk, &sum, &subs_squars[i], &mut tmp_sum);
            self.copy_to_from(&mut sum, &tmp_sum);
        }

        // Trivially encrypt the bits of count
        let mut bits: Vec<bool> = Vec::new();
        for i in (0..a[0].len()) {
            let bit = ((count >> i) & 1) != 0;
            bits.push(bit);
        }
        let c_count: Vec<_> = bits.iter().map(|&bit| sk.trivial_encrypt(bit)).collect();
        self.divider(sk, &sum, &c_count, result);
    }

    fn standard_deviation(
        &self,
        sk: &ServerKey,
        a: &Vec<&[Ciphertext]>,
        count: usize,
        result: &mut [Ciphertext],
    ) {
        let mut var: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); a[0].len()];
        self.variance(sk, a, count, &mut var);
        self.sqrt(sk, &var, result);
    }

    fn copy_to_from(&self, target: &mut [Ciphertext], source: &[Ciphertext]) {
        for (r, q) in target.iter_mut().zip(source.iter()) {
            r.clone_from(q);
        }
    }

    fn pitch_trim(&self, sk: &ServerKey, ctxt: &mut [Ciphertext]) -> Vec<Ciphertext> {
        let mut fresh: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); ctxt.len()];
        for c in ctxt {
            let f = sk.bootstrap(c);
            fresh.push(f);
        }
        fresh
    }

    fn pitch_trim_bit(&self, sk: &ServerKey, ctxt: &Ciphertext) -> Ciphertext {
        let mut fresh: Ciphertext = sk.bootstrap(ctxt);
        fresh
    }
}
