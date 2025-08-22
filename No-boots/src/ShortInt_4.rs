use std::time::Instant;
use tfhe::shortint::prelude::*;
use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;

fn full_adder(
    sk: &ServerKey,
    a: &Ciphertext ,
    b: &Ciphertext ,
    carry_in: &Ciphertext,
) -> (Ciphertext, Ciphertext) {
    // sum = a ^ b ^ carry_in
    let a_xor_b = sk.bitxor(a, b);

    let sum = sk.bitxor(&a_xor_b, carry_in);

    // carry_out = (a & b) | (a & carry_in) | (b & carry_in)
    let a_and_b = sk.bitand(a, b);

    let a_and_cin = sk.bitand(a, carry_in);

    let b_and_cin = sk.bitand(b, carry_in);

    let temp = sk.bitor(&a_and_b, &a_and_cin);

    let carry_out = sk.bitor(&temp, &b_and_cin);

    (sum, carry_out)
}

/// Adds two binary numbers represented as vectors of encrypted bits
fn add_encrypted(sk: &ServerKey, a: &mut [Ciphertext], b: &mut [Ciphertext]) -> Vec<Ciphertext> {
    let mut result = Vec::new();
    // The initial carry must be a trivial encryption of 0.
    let mut carry = sk.create_trivial(0);
    println!("{}", a.len());
    println!("{}", b.len());
    for i in 0..a.len() {
        let mut bit_a = &mut a[i];
        let mut bit_b = &mut b[i];
        // Compute the full sum: a + b + carry_in
        let mut temp_sum = sk.unchecked_add(&mut bit_a, &mut bit_b);
        // let lut = sk.generate_lookup_table(|x| x);
        // let mut bootstrapped = sk.apply_lookup_table(&temp_sum, &lut);
        // Declare `sum` as mutable.
        let mut sum = sk.unchecked_add(&mut temp_sum, &mut carry);

        //  Pass a mutable reference to `carry_extract`.
        // This updates `sum` to the 2-bit result and returns the new carry.
        let new_carry = sk.carry_extract(&mut sum);

        result.push(sum);
        carry = new_carry;

    }

    // Append the final carry to handle potential overflow.
    result.push(carry);
    result
}
fn multiply_encrypted(sk: &ServerKey, a: &mut [Ciphertext], b: &mut [Ciphertext]) -> Vec<Ciphertext> {
 // produces incorrect results for 32 bits, I think it needs bootstrapping :-)
    let n = a.len(); // Number of 2-bit chunks in each input
    let mut result = vec![sk.create_trivial(0); n * 2]; // Initialize result with 2n chunks

    // Generate and accumulate partial products
    for i in 0..n {
        let mut partial_product = vec![sk.create_trivial(0); result.len()];
        for j in 0..n {
            // Compute partial product: a[j] * b[i]
            let product = sk.unchecked_mul_lsb(&mut a[j], &mut b[i]);
            // Place the product in the correct position (shifted by i + j chunks)
            if i + j < n * 2 {
                partial_product[i + j] = product;
            }
        }
        // Add partial product to result
        result = add_encrypted(sk, &mut result, &mut partial_product);
    }

    result
}
pub fn main() {
    // Generate the client key and the server key:
    let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);

    let message_bits = cks.parameters().message_modulus().0.ilog2() as usize;
    println!("message bits: {message_bits}");
    let base = cks.parameters().message_modulus().0 as u64;
    println!("base {base}");
    let carry_bits = cks.parameters().carry_modulus().0.ilog2() as usize;

    let bit_size = 32;
    let num_digits = (bit_size + message_bits - 1) / message_bits;

    // Example 4-bit values
    let val1: u128 = 120; // binary 0101, in base 4: 11
    let val2: u128 = 200; // binary 0110, in base 4: 12

    let mut digits1: Vec<Ciphertext> = Vec::with_capacity(num_digits);
    let mut ptxt1: Vec<u8> = Vec::with_capacity(num_digits);
    let mut temp = val1;
    for _ in 0..num_digits{
        digits1.push(cks.encrypt((temp % base as u128) as u64));
        ptxt1.push((temp % base as u128) as u8);
        temp /= base as u128;
    }

    let mut digits2: Vec<Ciphertext> = Vec::with_capacity(num_digits);
    let mut ptxt2: Vec<u8> = Vec::with_capacity(num_digits);
    let mut temp = val2;
    for _ in 0..num_digits{
        digits2.push(cks.encrypt((temp % base as u128) as u64));
        ptxt2.push((temp % base as u128) as u8);
        temp /= base as u128;
    }

    println!("ptxt1 {:?}", ptxt1);
    println!("ptxt2 {:?}", ptxt2);

    let start = Instant::now();
    let result_digits = multiply_encrypted(&sks, &mut digits1, &mut digits2);
    let duration = start.elapsed();

    // Decrypt result digits
    let mut result: u128 = 0;
    let mut pow: u128 = 1;
    for digit in &result_digits {
        result += cks.decrypt(digit) as u128 * pow;
        pow *= base as u128;
    }
    println!("{result}");

    println!("Duration: {:?}", duration);

    // for (i, digit) in result_digits.iter().enumerate() {
    //     let val = cks.decrypt(digit);
    //     print!("{val}, ");
    // }


    // let start = Instant::now();
    // // Generate LUTs for mod 4 and div 4
    // let lut_mod = sks.generate_lookup_table(|x| x % base);
    // let lut_div = sks.generate_lookup_table(|x| x / base);
    // // Compute all partial products' lows and carries
    // let d = num_digits;
    // let mut lows: Vec<Vec<Ciphertext>> = vec![vec![]; d];
    // let mut carries: Vec<Vec<Ciphertext>> = vec![vec![]; d];
    //
    // for i in 0..d {
    //     lows[i] = vec![sks.create_trivial(0); d];
    //     carries[i] = vec![sks.create_trivial(0); d];
    //     for j in 0..d {
    //         let mut ai = digits1[i].clone();
    //         let mut bj = digits2[j].clone();
    //         let prod = sks.smart_mul_lsb(&mut ai, &mut bj);
    //         lows[i][j] = sks.apply_lookup_table(&prod, &lut_mod);
    //         carries[i][j] = sks.apply_lookup_table(&prod, &lut_div);
    //     }
    // }
    //
    // // Compute result digits column by column
    // let mut result_digits: Vec<Ciphertext> = Vec::with_capacity(2 * d);
    // let mut carry = sks.create_trivial(0u64);
    //
    // for k in 0..2 * d {
    //     let mut sum = sks.create_trivial(0u64);
    //
    //     // Add lows where i + j == k
    //     for i in 0..d {
    //         if let Some(j) = k.checked_sub(i) {
    //             if j < d {
    //                 let mut temp = lows[i][j].clone();
    //                 sum = sks.smart_add(&mut sum, &mut temp);
    //             }
    //         }
    //     }
    //
    //     // Add carries where i + j == k - 1
    //     if k > 0 {
    //         for i in 0..d {
    //             if let Some(j) = (k - 1).checked_sub(i) {
    //                 if j < d {
    //                     let mut temp = carries[i][j].clone();
    //                     sum = sks.smart_add(&mut sum, &mut temp);
    //                 }
    //             }
    //         }
    //     }
    //
    //     // Add carry from previous column
    //     let mut carry_mut = carry.clone();
    //     sum = sks.smart_add(&mut sum, &mut carry_mut);
    //
    //     // Compute digit and next carry
    //     let digit = sks.apply_lookup_table(&sum, &lut_mod);
    //     carry = sks.apply_lookup_table(&sum, &lut_div);
    //
    //     result_digits.push(digit);
    // }
    //
    // let duration = start.elapsed();
    //
    // // Decrypt result digits
    // let mut result: u128 = 0;
    // let mut pow: u128 = 1;
    // for digit in &result_digits {
    //     result += cks.decrypt(digit) as u128 * pow;
    //     pow *= base as u128;
    // }
    //
    // println!("Time: {:?}", duration);
    //
    // let expected = val1 * val2;
    // println!("{} * {} = {} (expected {})", val1, val2, result, expected);
    // assert_eq!(result, expected % (1u128 << (2 * bit_size)));
    //
    // // Example of noise level before and after BS on one ciphertext
    // let example_ct = sks.unchecked_mul_lsb(&digits1[0], &digits2[0]);
    // println!("noise level before BS: {:?}", example_ct.noise_level());
    //
    // let lut = sks.generate_lookup_table(|x| x);
    // let bootstrapped = sks.apply_lookup_table(&example_ct, &lut);
    //
    // println!("noise level after BS: {:?}", bootstrapped.noise_level());
}