use std::time::Instant;
use tfhe::boolean::gen_keys;
use tfhe::boolean::prelude::*;
use tfhe::boolean::server_key::RefreshEngine;

fn full_adder(
    sk: &ServerKey,
    a: &Ciphertext,
    b: &Ciphertext,
    carry_in: &Ciphertext,
) -> (Ciphertext, Ciphertext) {
    // sum = a ^ b ^ carry_in
    let a_xor_b = sk.xor(a, b);
    let a_xor_b = sk.bootstrap(&a_xor_b);

    let sum = sk.xor(&a_xor_b, carry_in);
    let sum = sk.bootstrap(&sum);

    // carry_out = (a & b) | (a & carry_in) | (b & carry_in)
    let a_and_b = sk.and(a, b);
    //let a_and_b = sk.refresh_me(&a_and_b);

    let a_and_cin = sk.and(a, carry_in);
    // let a_and_cin = sk.refresh_me(&a_and_cin);

    let b_and_cin = sk.and(b, carry_in);
    // let b_and_cin = sk.refresh_me(&b_and_cin);

    let temp = sk.or(&a_and_b, &a_and_cin);
    let temp = sk.bootstrap(&temp);

    let carry_out = sk.or(&temp, &b_and_cin);
    let carry_out = sk.bootstrap(&carry_out);

    (sum, carry_out)
}

/// Adds two binary numbers represented as vectors of encrypted bits
fn add_encrypted(sk: &ServerKey, a: &[Ciphertext], b: &[Ciphertext]) -> Vec<Ciphertext> {
    let mut result = Vec::new();
    let mut carry = sk.trivial_encrypt(false); // Initial carry = 0

    for (bit_a, bit_b) in a.iter().zip(b.iter()) {
        let (sum, new_carry) = full_adder(sk, bit_a, bit_b, &carry);
        result.push(sum);
        carry = new_carry;
    }

    result.push(carry); // carry-out
    result
}

// fn tester(
//     sk: &ServerKey,
//     a: &[Ciphertext],
//     b: &[Ciphertext],
// ) -> Vec<Ciphertext> {
//     let mut result = Vec::new();
//
//     for (bit_a, bit_b) in a.iter().zip(b.iter()) {
//         let bit_res = sk.or(bit_a, bit_b);
//         let bit_res = sk.refresh_me(&bit_res);
//
//         result.push(bit_res);
//     }
//
//     result
// }

/// Multiplies two encrypted binary numbers

fn and_refresh(sk: &ServerKey, a: &Ciphertext, b: &Ciphertext) -> Ciphertext {
    let res = sk.and(a, b);
    let res = sk.bootstrap(&res);
    res
}
fn multiply_encrypted(sk: &ServerKey, b: &[Ciphertext], a: &[Ciphertext]) -> Vec<Ciphertext> {
    // dropped from 614 secs to 304 secs
    let n = a.len();
    let mut result = vec![sk.trivial_encrypt(false); 2 * n];

    for i in 0..n {
        // Multiply a by b[i], shift left by i
        let mut partial = a
            .iter()
            .map(|bit| and_refresh(sk, &b[i], &bit))
            .collect::<Vec<_>>();

        // Shift left
        for _ in 0..i {
            partial.insert(0, sk.trivial_encrypt(false));
        }

        // Pad to result length
        while partial.len() < result.len() {
            partial.push(sk.trivial_encrypt(false));
        }

        // Add partial to result
        result = add_encrypted(sk, &result, &partial);
    }

    result
}


// fn main() {
//     let (ck, sk) = gen_keys();
//     let Q = vec![sk.trivial_encrypt(false), sk.trivial_encrypt(false), sk.trivial_encrypt(true)];
//     let mut result = vec![Ciphertext::Trivial(false); Q.len()];
// 
//     for (r, q) in result.iter_mut().zip(Q.iter()) {
//         r.clone_from(q);
//     }
// 
//     for r in result{
//         let x = ck.decrypt(&r);
//         println!("{x}");
//     }
// 
// }
fn main() {
    // We generate a set of client/server keys, using the default parameters:
    let (client_key, server_key) = gen_keys();

    // 4-bit example: multiply 0b0011 (3) * 0b0101 (5)
    let a_bits = [true, true, false, false]; // 0b0011
    let b_bits = [true, false, true, false]; // 0b0101

    let ct_a: Vec<_> = a_bits.iter().map(|&bit| client_key.encrypt(bit)).collect();

    let ct_b: Vec<_> = b_bits.iter().map(|&bit| client_key.encrypt(bit)).collect();

    let start = Instant::now();
    let ct_product = add_encrypted(&server_key, &ct_a, &ct_b);
    let elapsed = start.elapsed();

    // Decrypt result
    let decrypted: Vec<_> = ct_product
        .iter()
        .map(|bit| client_key.decrypt(bit))
        .collect();

    // Convert to integer
    let result_value: u64 = decrypted
        .iter()
        .enumerate()
        .map(|(i, &bit)| (bit as u64) << i)
        .sum();

    println!("Decrypted result: {:?}", decrypted);
    println!("Product as integer: {}", result_value);
    println!("Time elapsed: {:?}", elapsed);
}
