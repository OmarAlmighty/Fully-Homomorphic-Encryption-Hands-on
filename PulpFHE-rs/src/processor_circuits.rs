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

pub trait ProcessorCircuits {
    /// Performs a left bitwise shift operation on an encrypted value.
    ///
    /// The `e_shl` function takes an encrypted array (`a`) represented as a slice of `Ciphertext`
    /// and performs a left shift by `shift_amt` number of bits. The result of the operation
    /// is stored in the provided mutable slice `result`. The size of `result` must be
    /// enough to hold the shifted ciphertexts. Encryption-specific keys (`ServerKey`)
    /// are used to perform the operation safely in the cryptographic context.
    ///
    /// # Parameters
    /// - `self`: The instance of the object that provides context for the operation.
    /// - `a`: A slice of `Ciphertext` representing the encrypted input value(s)
    ///   that will be shifted.
    /// - `shift_amt`: A `usize` value representing the number of bits to shift to the left.
    /// - `result`: A mutable slice of `Ciphertext` where the result of the left shift
    ///   operation will be stored.
    ///
    /// # Requirements
    /// - The size of the `result` slice must be equal to or larger than the size of the input slice `a`.
    ///   Failure to provide a sufficient-sized result slice may cause runtime issues.
    /// - The `Ciphertext` values must be valid and consistent with the encryption context
    ///   provided by the `ServerKey`.
    ///
    /// # Examples
    /// ```rust
    /// // Assuming `key` is a valid ServerKey and `cipher_a` is a vector of Ciphertext
    /// // encrypted values.
    /// let sk = &key;
    /// let cipher_a = vec![...]; // Encrypted input
    /// let mut result = vec![...]; // Encrypted output location
    /// let shift_amount = 3; // Specify the shift amount
    ///
    /// e_shl(sk, &cipher_a, shift_amount, &mut result);
    ///
    /// // The `result` vector now holds the left-shifted encrypted values.
    /// ```
    fn e_shl(&self, a: &[Ciphertext], shift_amt: usize, result: &mut [Ciphertext]);

    /// Performs a right bitwise shift operation on an encrypted value.
    ///
    /// # Parameters
    /// * `a`: &[Ciphertext] - The input encrypted array to be shifted
    /// * `shift_amt`: usize - The number of bits to shift right
    /// * `result`: &mut [Ciphertext] - The destination array for the shifted result
    fn e_shr(&self, a: &[Ciphertext], shift_amt: usize, result: &mut [Ciphertext]);

    /// Performs a right rotation (circular shift) on an encrypted value.
    ///
    /// # Parameters
    /// * `a`: &[Ciphertext] - The input encrypted array to be rotated
    /// * `rot_amt`: usize - The number of positions to rotate right
    /// * `result`: &mut [Ciphertext] - The destination array for the rotated result
    fn e_rotr(&self, a: &[Ciphertext], rot_amt: usize, result: &mut [Ciphertext]);

    /// Performs a left rotation (circular shift) on an encrypted value.
    ///
    /// # Parameters  
    /// * `a`: &[Ciphertext] - The input encrypted array to be rotated
    /// * `rot_amt`: usize - The number of positions to rotate left
    /// * `result`: &mut [Ciphertext] - The destination array for the rotated result
    fn e_rotl(&self, a: &[Ciphertext], rot_amt: usize, result: &mut [Ciphertext]);


    /// Compares two encrypted arrays and returns an encrypted bit indicating the result.
    ///
    /// # Parameters
    /// * `sk`: &ServerKey - The server key for homomorphic operations
    /// * `a`: &[Ciphertext] - First array to compare
    /// * `b`: &[Ciphertext] - Second array to compare  
    /// * `select`: u8 - Comparison type selector (e.g. equal, less than, etc.)
    ///
    /// # Returns
    /// * Ciphertext - Encrypted bit representing comparison result
    fn comparator(
        &self,
        sk: &ServerKey,
        a: &[Ciphertext],
        b: &[Ciphertext],
        select: u8,
    ) -> Ciphertext;

    /// Compares two encrypted bits considering a carry bit from previous comparison.
    ///
    /// # Parameters
    /// * `sk`: &ServerKey - The server key for homomorphic operations
    /// * `a`: &Ciphertext - First bit to compare
    /// * `b`: &Ciphertext - Second bit to compare
    /// * `lsb_carry`: &Ciphertext - Carry bit from previous comparison
    ///
    /// # Returns  
    /// * Ciphertext - Encrypted bit representing comparison result
    fn compare_bit(
        &self,
        sk: &ServerKey,
        a: &Ciphertext,
        b: &Ciphertext,
        lsb_carry: &Ciphertext,
    ) -> Ciphertext;

    /// Performs subtraction between two encrypted arrays.
    ///
    /// # Parameters
    /// * `sk`: &ServerKey - The server key for homomorphic operations
    /// * `a`: &[Ciphertext] - First operand array (minuend)
    /// * `b`: &[Ciphertext] - Second operand array (subtrahend)
    /// * `result`: &mut [Ciphertext] - Destination array for difference
    fn subtracter(
        &self,
        sk: &ServerKey,
        a: &[Ciphertext],
        b: &[Ciphertext],
        result: &mut [Ciphertext],
    );

    /// Performs addition between two encrypted arrays.
    ///
    /// # Parameters
    /// * `sk`: &ServerKey - The server key for homomorphic operations
    /// * `a`: &[Ciphertext] - First operand array
    /// * `b`: &[Ciphertext] - Second operand array
    /// * `result`: &mut [Ciphertext] - Destination array for sum
    fn adder(&self, sk: &ServerKey, a: &[Ciphertext], b: &[Ciphertext], result: &mut [Ciphertext]);

    /// Performs signed addition between two encrypted arrays.
    ///
    /// # Parameters
    /// * `sk`: &ServerKey - The server key for homomorphic operations
    /// * `a`: &[Ciphertext] - First operand array (signed)
    /// * `b`: &[Ciphertext] - Second operand array (signed)
    /// * `result`: &mut [Ciphertext] - Destination array for signed sum
    fn sign_adder(
        &self,
        sk: &ServerKey,
        a: &[Ciphertext],
        b: &[Ciphertext],
        result: &mut [Ciphertext],
    );

    /// Performs a half adder operation on two encrypted bits.
    ///
    /// # Parameters
    /// * `sk`: &ServerKey - The server key for homomorphic operations
    /// * `a`: &Ciphertext - First input bit
    /// * `b`: &Ciphertext - Second input bit
    /// * `carry`: &mut Ciphertext - Output carry bit
    /// * `result`: &mut Ciphertext - Output sum bit
    fn half_adder(
        &self,
        sk: &ServerKey,
        a: &Ciphertext,
        b: &Ciphertext,
        carry: &mut Ciphertext,
        result: &mut Ciphertext,
    );

    /// Performs a carry-save adder operation on three encrypted bits.
    ///
    /// # Parameters
    /// * `sk`: &ServerKey - The server key for homomorphic operations
    /// * `a`: &Ciphertext - First input bit
    /// * `b`: &Ciphertext - Second input bit
    /// * `cin`: &Ciphertext - Input carry bit
    /// * `carry`: &mut Ciphertext - Output carry bit
    /// * `result`: &mut Ciphertext - Output sum bit
    fn carry_save_adder(
        &self,
        sk: &ServerKey,
        a: &Ciphertext,
        b: &Ciphertext,
        cin: &Ciphertext,
        carry: &mut Ciphertext,
        result: &mut Ciphertext,
    );

    /// Adds supplementary values during arithmetic operations.
    ///
    /// # Parameters
    /// * `sk`: &ServerKey - The server key for homomorphic operations
    /// * `a`: &[Ciphertext] - First operand array
    /// * `b`: &[Ciphertext] - Second operand array
    /// * `size`: usize - Size of operation
    /// * `result`: &mut [Ciphertext] - Destination array
    fn add_supplement(
        &self,
        sk: &ServerKey,
        a: &[Ciphertext],
        b: &[Ciphertext],
        size: usize,
        result: &mut [Ciphertext],
    );

    /// Performs multiplication between two encrypted arrays.
    ///
    /// # Parameters
    /// * `sk`: &ServerKey - The server key for homomorphic operations
    /// * `a`: &[Ciphertext] - First operand array
    /// * `b`: &[Ciphertext] - Second operand array
    /// * `result`: &mut [Ciphertext] - Destination array for product
    fn multiplier(
        &self,
        sk: &ServerKey,
        a: &[Ciphertext],
        b: &[Ciphertext],
        result: &mut [Ciphertext],
    );

    /// Performs the BLAKE3 hash function on encrypted data.
    ///
    /// # Parameters
    /// * `sk`: &ServerKey - The server key for homomorphic operations
    /// * `msg`: Vec<&[Ciphertext]> - Input message blocks
    /// * `v`: Vec<&[Ciphertext]> - Initial hash values
    /// * `result`: &mut Vec<&mut [Ciphertext]> - Resulting hash values
    fn blake3(
        &self,
        sk: &ServerKey,
        msg: Vec<&[Ciphertext]>,
        v: Vec<&[Ciphertext]>,
        result: &mut Vec<&mut [Ciphertext]>,
    );

    /// Finds the maximum value among encrypted arrays.
    ///
    /// # Parameters
    /// * `sk`: &ServerKey - The server key for homomorphic operations
    /// * `a`: &Vec<&[Ciphertext]> - Vector of input arrays
    /// * `result`: &mut [Ciphertext] - Destination array for maximum value
    fn max(&self, sk: &ServerKey, a: &Vec<&[Ciphertext]>, result: &mut [Ciphertext]);

    /// Finds the minimum value among encrypted arrays.
    ///
    /// # Parameters
    /// * `sk`: &ServerKey - The server key for homomorphic operations
    /// * `a`: &Vec<&[Ciphertext]> - Vector of input arrays
    /// * `result`: &mut [Ciphertext] - Destination array for minimum value
    fn min(&self, sk: &ServerKey, a: &Vec<&[Ciphertext]>, result: &mut [Ciphertext]);

    /// Applies ReLU (Rectified Linear Unit) function on encrypted array.
    ///
    /// # Parameters
    /// * `sk`: &ServerKey - The server key for homomorphic operations
    /// * `a`: &[Ciphertext] - Input array
    /// * `result`: &mut [Ciphertext] - Destination array after ReLU
    fn relu(&self, sk: &ServerKey, a: &[Ciphertext], result: &mut [Ciphertext]);

    /// Performs division between two encrypted arrays.
    ///
    /// # Parameters
    /// * `sk`: &ServerKey - The server key for homomorphic operations
    /// * `a`: &[Ciphertext] - Dividend array
    /// * `b`: &[Ciphertext] - Divisor array
    /// * `result`: &mut [Ciphertext] - Destination array for quotient
    fn divider(
        &self,
        sk: &ServerKey,
        a: &[Ciphertext],
        b: &[Ciphertext],
        result: &mut [Ciphertext],
    );

    /// Computes modulo operation between two encrypted arrays.
    ///
    /// # Parameters
    /// * `sk`: &ServerKey - The server key for homomorphic operations
    /// * `a`: &[Ciphertext] - Dividend array
    /// * `b`: &[Ciphertext] - Modulus array
    /// * `result`: &mut [Ciphertext] - Destination array for remainder
    fn modulo(&self, sk: &ServerKey, a: &[Ciphertext], b: &[Ciphertext], result: &mut [Ciphertext]);

    /// Computes arithmetic mean of encrypted arrays.
    ///
    /// # Parameters
    /// * `sk`: &ServerKey - The server key for homomorphic operations
    /// * `a`: &Vec<&[Ciphertext]> - Vector of input arrays
    /// * `count`: usize - Number of elements
    /// * `result`: &mut [Ciphertext] - Destination array for mean
    fn mean(&self, sk: &ServerKey, a: &Vec<&[Ciphertext]>, count: usize, result: &mut [Ciphertext]);

    /// Computes square root of encrypted array.
    ///
    /// # Parameters
    /// * `sk`: &ServerKey - The server key for homomorphic operations
    /// * `a`: &[Ciphertext] - Input array
    /// * `result`: &mut [Ciphertext] - Destination array for square root
    fn sqrt(&self, sk: &ServerKey, a: &[Ciphertext], result: &mut [Ciphertext]);

    /// Computes variance of encrypted arrays.
    ///
    /// # Parameters
    /// * `sk`: &ServerKey - The server key for homomorphic operations
    /// * `a`: &Vec<&[Ciphertext]> - Vector of input arrays
    /// * `count`: usize - Number of elements
    /// * `result`: &mut [Ciphertext] - Destination array for variance
    fn variance(
        &self,
        sk: &ServerKey,
        a: &Vec<&[Ciphertext]>,
        count: usize,
        result: &mut [Ciphertext],
    );

    /// Computes standard deviation of encrypted arrays.
    ///
    /// # Parameters
    /// * `sk`: &ServerKey - The server key for homomorphic operations
    /// * `a`: &Vec<&[Ciphertext]> - Vector of input arrays
    /// * `count`: usize - Number of elements
    /// * `result`: &mut [Ciphertext] - Destination array for standard deviation
    fn standard_deviation(
        &self,
        sk: &ServerKey,
        a: &Vec<&[Ciphertext]>,
        count: usize,
        result: &mut [Ciphertext],
    );

    fn copy_to_from(&self, target: &mut [Ciphertext], source: &[Ciphertext]);

}
