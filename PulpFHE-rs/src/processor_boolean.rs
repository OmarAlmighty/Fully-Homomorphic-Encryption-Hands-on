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

use std::ffi::c_int;
use crate::processor_units::Processor;
use std::time::Instant;
use tfhe::boolean::gen_keys;
use tfhe::boolean::prelude::*;
use tfhe::boolean::server_key::RefreshEngine;

pub struct ProcessorBoolean;
impl Processor for ProcessorBoolean {
    fn e_and(&self, sk: &ServerKey, a: &[Ciphertext], b: &[Ciphertext], result: &mut [Ciphertext]) {
        let size: usize = a.len();

        for i in 0..size {
            result[i] = sk.and(&a[i], &b[i]);
        }

        #[cfg(debug_assertions)]
        {
            println!("DEBUG: `e_and` -> len(a)={}, len(b)={}", size, b.len());
        }
    }

    fn e_and_bit(&self, sk: &ServerKey, a: &Ciphertext, b: &Ciphertext) -> Ciphertext {
        let result: Ciphertext = sk.and(a, b);

        #[cfg(debug_assertions)]
        {
            println!("DEBUG: `e_and_bit`");
        }
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
            result[i] = sk.and(&a[i], &b[i]);
        }

        #[cfg(debug_assertions)]
        {
            println!(
                "DEBUG: `e_and_range` -> len(a)={}, len(b)={}, index_low={}, index_high={}",
                a.len(),
                b.len(),
                index_low,
                index_high
            );
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
    fn e_or(&self, sk: &ServerKey, a: &[Ciphertext], b: &[Ciphertext], result: &mut [Ciphertext]) {
        let size: usize = a.len();
        for i in 0..size {
            result[i] = sk.or(&a[i], &b[i]);
        }

        #[cfg(debug_assertions)]
        {
            println!("DEBUG: `e_or` -> len(a)={}, len(b)={}", size, b.len());
        }
    }

    fn e_or_bit(&self, sk: &ServerKey, a: &Ciphertext, b: &Ciphertext) -> Ciphertext {
        let result: Ciphertext = sk.or(a, b);

        #[cfg(debug_assertions)]
        {
            println!("DEBUG: `e_xor_bit`");
        }
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
            result[i] = sk.or(&a[i], &b[i]);
        }

        #[cfg(debug_assertions)]
        {
            println!(
                "DEBUG: `e_or_range` -> len(a)={}, len(b)={}, index_low={}, index_high={}",
                a.len(),
                b.len(),
                index_low,
                index_high
            );
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
    fn e_xor(&self, sk: &ServerKey, a: &[Ciphertext], b: &[Ciphertext], result: &mut [Ciphertext]) {
        let size: usize = a.len();
        for i in 0..size {
            result[i] = sk.xor(&a[i], &b[i]);
        }

        #[cfg(debug_assertions)]
        {
            println!("DEBUG: `e_xor` -> len(a)={}, len(b)={}", size, b.len());
        }
    }

    fn e_xor_bit(&self, sk: &ServerKey, a: &Ciphertext, b: &Ciphertext) -> Ciphertext {
        let result: Ciphertext = sk.xor(a, b);

        #[cfg(debug_assertions)]
        {
            println!("DEBUG: `e_xor_bit`");
        }
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
            result[i] = sk.xor(&a[i], &b[i]);
        }

        #[cfg(debug_assertions)]
        {
            println!(
                "DEBUG: `e_xor_range` -> len(a)={}, len(b)={}, index_low={}, index_high={}",
                a.len(),
                b.len(),
                index_low,
                index_high
            );
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
    fn e_nand(
        &self,
        sk: &ServerKey,
        a: &[Ciphertext],
        b: &[Ciphertext],
        result: &mut [Ciphertext],
    ) {
        let size: usize = a.len();
        for i in 0..size {
            result[i] = sk.nand(&a[i], &b[i]);
        }

        #[cfg(debug_assertions)]
        {
            println!("DEBUG: `e_nand` -> len(a)={}, len(b)={}", size, b.len());
        }
    }

    fn e_nand_bit(&self, sk: &ServerKey, a: &Ciphertext, b: &Ciphertext) -> Ciphertext {
        let result: Ciphertext = sk.nand(a, b);

        #[cfg(debug_assertions)]
        {
            println!("DEBUG: `e_nand_bit`");
        }
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
            result[i] = sk.nand(&a[i], &b[i]);
        }

        #[cfg(debug_assertions)]
        {
            println!(
                "DEBUG: `e_nand_range` -> len(a)={}, len(b)={}, index_low={}, index_high={}",
                a.len(),
                b.len(),
                index_low,
                index_high
            );
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
    fn e_nor(&self, sk: &ServerKey, a: &[Ciphertext], b: &[Ciphertext], result: &mut [Ciphertext]) {
        let size: usize = a.len();
        for i in 0..size {
            result[i] = sk.nor(&a[i], &b[i]);
        }

        #[cfg(debug_assertions)]
        {
            println!("DEBUG: `e_nor` -> len(a)={}, len(b)={}", size, b.len());
        }
    }

    fn e_nor_bit(&self, sk: &ServerKey, a: &Ciphertext, b: &Ciphertext) -> Ciphertext {
        let result: Ciphertext = sk.nor(a, b);

        #[cfg(debug_assertions)]
        {
            println!("DEBUG: `e_nor_bit`");
        }
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
            result[i] = sk.nor(&a[i], &b[i]);
        }

        #[cfg(debug_assertions)]
        {
            println!(
                "DEBUG: `e_nor_range` -> len(a)={}, len(b)={}, index_low={}, index_high={}",
                a.len(),
                b.len(),
                index_low,
                index_high
            );
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
    fn e_xnor(
        &self,
        sk: &ServerKey,
        a: &[Ciphertext],
        b: &[Ciphertext],
        result: &mut [Ciphertext],
    ) {
        let size: usize = a.len();
        for i in 0..size {
            result[i] = sk.xnor(&a[i], &b[i]);
        }

        #[cfg(debug_assertions)]
        {
            println!("DEBUG: `e_xnor` -> len(a)={}, len(b)={}", size, b.len());
        }
    }

    fn e_xnor_bit(&self, sk: &ServerKey, a: &Ciphertext, b: &Ciphertext) -> Ciphertext {
        let result: Ciphertext = sk.xnor(a, b);

        #[cfg(debug_assertions)]
        {
            println!("DEBUG: `e_xnor_bit`");
        }
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
            result[i] = sk.xnor(&a[i], &b[i]);
        }

        #[cfg(debug_assertions)]
        {
            println!(
                "DEBUG: `e_xnor_range` -> len(a)={}, len(b)={}, index_low={}, index_high={}",
                a.len(),
                b.len(),
                index_low,
                index_high
            );
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
    fn e_not(&self, sk: &ServerKey, a: &[Ciphertext], result: &mut [Ciphertext]) {
        let size: usize = a.len();
        for i in 0..size {
            result[i] = sk.not(&a[i]);
        }

        #[cfg(debug_assertions)]
        {
            println!("DEBUG: `e_not` -> len(a)={}", size);
        }
    }

    fn e_not_bit(&self, sk: &ServerKey, a: &Ciphertext) -> Ciphertext {
        let result: Ciphertext = sk.not(a);

        #[cfg(debug_assertions)]
        {
            println!("DEBUG: `e_not_bit`");
        }
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

        #[cfg(debug_assertions)]
        {
            println!(
                "DEBUG: `e_not_range` -> len(a)={}, index_low={}, index_high={}",
                a.len(),
                index_low,
                index_high
            );
        }
    }

    fn e_shl(&self, sk: &ServerKey, a: &[Ciphertext], shift_amt: usize, result: &mut [Ciphertext]) {
        let len = a.len();
        let shift = shift_amt % len; // Normalize shift if n > len

        if shift == 0 {
            return;
        }

        // Temporary buffer to store the first `shift` elements
        let temp: Vec<Ciphertext> = a[..shift].to_vec();

        // Shift remaining elements to the left
        for i in 0..(len - shift) {
            result[i].clone_from(&a[i + shift]);
        }

        // Move the saved elements to the end
        for i in 0..shift {
            result[len - shift + i].clone_from(&temp[i]);
        }
    }

    fn e_shr(&self, sk: &ServerKey, a: &[Ciphertext], shift_amt: usize, result: &mut [Ciphertext]) {
        let len = a.len();
        let shift = shift_amt % len; // Normalize shift if n > len

        if shift == 0 {
            return;
        }

        // Temporary buffer to store the last `shift` elements
        let temp: Vec<Ciphertext> = a[len - shift..].to_vec();

        // Shift elements to the right
        for i in (0..len - shift).rev() {
            result[i + shift].clone_from(&a[i]);
        }

        // Move the saved elements to the front
        for i in 0..shift {
            result[i].clone_from(&temp[i]);
        }
    }

    fn e_rot_r(&self, sk: &ServerKey, a: &[Ciphertext], rot_amt: usize, result: &mut [Ciphertext]) {
        let size: usize = a.len();
        let mut temp: Vec<Ciphertext> = Vec::with_capacity(size);

        result.iter().clone_from(&a.iter().clone());

        for i in 0..rot_amt {
            let lsb: Ciphertext = result[0].clone();
            for j in 0..size - 1 {
                temp[j].clone_from(&result[j + 1]);
            }
            temp[size - 1].clone_from(&lsb);

            result.iter().clone_from(&temp.iter().clone());
        }
    }

    fn e_rot_l(&self, sk: &ServerKey, a: &[Ciphertext], rot_amt: usize, result: &mut [Ciphertext]) {
        let size: usize = a.len();
        let mut temp: Vec<Ciphertext> = Vec::with_capacity(size);

        result.iter().clone_from(&a.iter().clone());

        for i in 0..rot_amt {
            let msb: Ciphertext = result[size - 1].clone();
            for j in 1..size {
                temp[j].clone_from(&result[j - 1]);
            }
            temp[0].clone_from(&msb);

            result.iter().clone_from(&temp.iter().clone());
        }
    }

    fn e_mux(
        &self,
        sk: &ServerKey,
        selector: &[Ciphertext],
        ct_then: &[Ciphertext],
        ct_else: &[Ciphertext],
        result: &mut [Ciphertext],
    ) {
        for i in 0..ct_then.len() {
            result[i] = sk.mux(&selector[i], &ct_then[i], &ct_else[i]);
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
        result: &mut [Ciphertext],
    ) {
        let size: usize = a.len();

        let mut not_a: Vec<Ciphertext> = Vec::new();
        self.e_not(sk, a, &mut not_a);

        let mut not_b: Vec<Ciphertext> = Vec::new();
        self.e_not(sk, b, &mut not_b);

        let mut temp: Vec<Ciphertext> = Vec::with_capacity(10);
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

        // select desired output
        if (select == 0) {
            // ecmpeq
            result[0].clone_from(&equal);
        } else if (select == 1) {
            // ecmpl
            result[0].clone_from(&less_than);
        } else if (select == 2) {
            // ecmpg
            result[0].clone_from(&greater_than);
        } else if (select == 3) {
            // ecmpgeq
            result[0] = self.e_or_bit(sk, &equal, &greater_than);
        } else if (select == 4) {
            // ecmpleq
            result[0] = self.e_or_bit(sk, &equal, &less_than);
        } else if (select == 5) {
            // ecmpneq
            result[0] = self.e_not_bit(sk, &equal);
        }

        for i in 1..size {
            result[i] = sk.trivial_encrypt(false);
        }
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

        let mut borrow: Vec<Ciphertext> = Vec::new();
        let mut temp_0: Vec<Ciphertext> = Vec::new();
        let mut temp_1: Vec<Ciphertext> = Vec::new();
        let mut temp_2: Vec<Ciphertext> = Vec::new();

        // Run half subtracter
        result[0] = self.e_xor_bit(sk, &a[0], &b[9]);
        temp_0[0] = self.e_not_bit(sk, &a[0]);
        borrow[0] = self.e_and_bit(sk, &temp_0[0], &b[0]);

        self.e_xor_range(sk, &a, &b, &mut temp_0, 1, size);
        self.e_not_range(sk, &a, &mut temp_1, 1, size);

        for i in 1..size {
            // Calculate the difference
            result[i] = self.e_xor_bit(sk, &temp_0[i], &borrow[i - 1]);

            if (i != size - 1) {
                temp_2[i] = self.e_and_bit(sk, &temp_1[i], &b[i]);
                temp_0[i] = self.e_not_bit(sk, &temp_0[i]);
                temp_1[i] = self.e_and_bit(sk, &borrow[i - 1], &temp_0[i]);
                borrow[i] = self.e_or_bit(sk, &temp_2[i], &temp_1[i]);
            }
        }
    }

    fn adder(&self, sk: &ServerKey, a: &[Ciphertext], b: &[Ciphertext], result: &mut [Ciphertext]) {
        let size: usize = a.len();

        let mut carry: Vec<Ciphertext> = Vec::with_capacity(size + 1);
        let mut temp: Vec<Ciphertext> = Vec::with_capacity(size);

        //initialize the first carry to 0
        carry[0] = sk.trivial_encrypt(false);

        self.e_xor(sk, a, b, &mut temp);

        for i in 0..size {
            result[i] = self.e_xor_bit(sk, &carry[i], &temp[i]);
            carry[i + 1] = self.e_mux_bit(sk, &temp[i], &carry[i], &a[i]);
        }
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
        let mut carry: Vec<Ciphertext> = Vec::with_capacity(size + 1);
        let mut temp: Vec<Ciphertext> = Vec::with_capacity(size);
        carry[0] = sk.trivial_encrypt(false);

        self.e_xor(sk, a, b, &mut temp);

        for i in 0..size - 1 {
            // Compute carry
            carry[i + 1] = self.e_mux_bit(sk, &temp[i], &carry[i], &a[i]);
        }

        // Compute sum
        self.e_xor(sk, &carry, &temp, result);
    }

    fn multiplier(
        &self,
        sk: &ServerKey,
        a: &[Ciphertext],
        b: &[Ciphertext],
        result: &mut [Ciphertext],
    ) {
        let size: usize = a.len();
        let mut tmp_array: Vec<Ciphertext> = Vec::with_capacity(size);
        let mut sum: Vec<Ciphertext> = Vec::with_capacity(size);
        let mut temp_sum: Vec<Ciphertext> = Vec::with_capacity(size);
        for i in 0..size {
            for j in 0..size - 1 {
                tmp_array[j] = self.e_and_bit(sk, &a[i], &b[j]);
            }
            temp_sum.clone_from(&sum);
            self.add_supplement(sk, &mut tmp_array, &sum[i..], size - i, &mut temp_sum[i..]);
            sum.clone_from(&temp_sum);
        }

        result.iter().clone_from(&sum.iter());
    }

    fn blake3(
        &self,
        sk: &ServerKey,
        msg: Vec<&[Ciphertext]>,
        v: Vec<&[Ciphertext]>,
        result: &mut Vec<&mut [Ciphertext]>,
    ) {
        let size: usize = msg[0].len();
        let mut a: Vec<Ciphertext> = Vec::with_capacity(size);
        let mut b: Vec<Ciphertext> = Vec::with_capacity(size);
        let mut c: Vec<Ciphertext> = Vec::with_capacity(size);
        let mut d: Vec<Ciphertext> = Vec::with_capacity(size);
        let mut m0: Vec<Ciphertext> = Vec::with_capacity(size);
        let mut m1: Vec<Ciphertext> = Vec::with_capacity(size);

        let mut tmp_a: Vec<Ciphertext> = Vec::with_capacity(size);
        let mut tmp_b: Vec<Ciphertext> = Vec::with_capacity(size);
        let mut tmp_c: Vec<Ciphertext> = Vec::with_capacity(size);
        let mut tmp_d: Vec<Ciphertext> = Vec::with_capacity(size);

        // Unpack the input
        a.clone_from(&v[0].to_vec());
        b.clone_from(&v[1].to_vec());
        c.clone_from(&v[2].to_vec());
        d.clone_from(&v[3].to_vec());
        m0.clone_from(&msg[0].to_vec());
        m1.clone_from(&msg[1].to_vec());

        // Step 1: a = a + b + m0
        // Step 1.1: a = a + b
        self.adder(sk, &a, &b, &mut tmp_a);
        // Step 1.2: a = a + m0
        self.adder(sk, &tmp_a, &m0, &mut a);

        // Step 2: d = (d XOR a ) >>> 16
        // Step 2.1: d = d XOR a
        self.e_xor(sk, &d, &a, &mut tmp_d);
        self.e_rot_r(sk, &tmp_d, 16, &mut d);

        // Step 3: c = c + d
        tmp_c.clone_from(&c);
        self.adder(sk, &tmp_c, &d, &mut c);

        // Step 4: b = (b XOR c) >>> 12
        // Step 4.1: b = b XOR c
        self.e_xor(sk, &b, &c, &mut tmp_b);
        // Step 4.2: b = b >>> 12
        self.e_rot_r(sk, &tmp_b, 12, &mut b);

        // Step 5: a = a + b + m1
        // Step 5.1: a = a + b
        self.adder(sk, &a, &b, &mut tmp_a);
        // Step 5.2: a = a + m1
        self.adder(sk, &tmp_a, &m1, &mut a);

        // Step 6: d = (d XOR a ) >>> 8
        // Step 6.1: d = d XOR a
        self.e_xor(sk, &d, &a, &mut tmp_d);
        // Step 6.2: d = d >>> 8
        self.e_rot_r(sk, &tmp_d, 8, &mut d);

        // Step 7: c = c + d
        tmp_c.clone_from(&c);
        self.adder(sk, &tmp_c, &d, &mut c);

        // Step 8: b = (b XOR c) >>> 12
        // Step 8.1: b = b XOR c
        self.e_xor(sk, &b, &c, &mut tmp_b);
        // Step 8.2: b = b >>> 7
        self.e_rot_r(sk, &tmp_b, 7, &mut b);
        
        result[0].iter().clone_from(&mut a.iter());
        result[1].iter().clone_from(&mut b.iter());
        result[2].iter().clone_from(&mut c.iter());
        result[3].iter().clone_from(&mut d.iter());
        
    }

    fn max(&self, sk: &ServerKey, a: &[Ciphertext], b: &[Ciphertext], result: &mut [Ciphertext]) {
        todo!()
    }

    fn min(&self, sk: &ServerKey, a: &[Ciphertext], b: &[Ciphertext], result: &mut [Ciphertext]) {
        todo!()
    }

    fn relu(&self, sk: &ServerKey, a: &[Ciphertext], result: &mut [Ciphertext]) {
        todo!()
    }

    fn div(&self, sk: &ServerKey, a: &[Ciphertext], b: &[Ciphertext], result: &mut [Ciphertext]) {
        todo!()
    }

    fn modulo(
        &self,
        sk: &ServerKey,
        a: &[Ciphertext],
        b: &[Ciphertext],
        result: &mut [Ciphertext],
    ) {
        todo!()
    }

    fn mean(&self, sk: &ServerKey, a: &[Ciphertext], count: usize, result: &mut [Ciphertext]) {
        todo!()
    }

    fn e_sqrt(&self, sk: &ServerKey, a: &[Ciphertext], result: &mut [Ciphertext]) {
        todo!()
    }

    fn variance(&self, sk: &ServerKey, a: &[Ciphertext], count: usize, result: &mut [Ciphertext]) {
        todo!()
    }

    fn standard_deviation(
        &self,
        sk: &ServerKey,
        a: &[Ciphertext],
        count: usize,
        result: &mut [Ciphertext],
    ) {
        todo!()
    }
}
