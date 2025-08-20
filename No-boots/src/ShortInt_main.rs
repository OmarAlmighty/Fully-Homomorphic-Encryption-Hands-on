use tfhe::core_crypto::prelude::*;
use tfhe::shortint::prelude::*;

use std::time::Instant;
use tfhe::shortint::gen_keys;
use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;


pub fn main() {
    // Generate the client key and the server key:
    let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);

    // Encrypt values and add them
    let ct1 = cks.encrypt(2);
    let ct2 = cks.encrypt(4);

    let start = Instant::now();
    let res = sks.unchecked_mul_lsb(&ct1, &ct2);

    println!("noise level before BS: {:?}", res.noise_level());

    // Manually bootstrap the result
    let lut = sks.generate_lookup_table(|x| x);
    let bootstrapped = sks.apply_lookup_table(&res, &lut);

    let duration = start.elapsed();
    println!("noise level after BS: {:?}", bootstrapped.noise_level());


    // Decrypt
    let dec = cks.decrypt(&bootstrapped);
    println!("dec: {:?}", dec);
    println!("time: {:?}", duration);
}


// pub fn multiplier(
//     result: &mut [LweCiphertext<Vec<u64>>],
//     a: &[LweCiphertext<Vec<u64>>],
//     b: &[LweCiphertext<Vec<u64>>],
//     nb_bits: usize,
//     server_key: &ServerKey,
// ) {
//     // Initialize temporary arrays for partial products and sums
//     let mut tmp_array: Vec<LweCiphertext<Vec<u64>>> = vec![
//         server_key.create_trivial_zero_ciphertext(&server_key.parameters);
//         nb_bits
//     ];
//     let mut sum: Vec<LweCiphertext<Vec<u64>>> = vec![
//         server_key.create_trivial_zero_ciphertext(&server_key.parameters);
//         nb_bits
//     ];
//
//     // Initialize result to zero
//     for i in 0..nb_bits {
//         result[i] = server_key.create_trivial_zero_ciphertext(&server_key.parameters);
//     }
//
//     // Compute partial products and accumulate
//     for i in 0..nb_bits {
//         // Compute AND of a[i] and b[j] for each j
//         for j in 0..(nb_bits - i) {
//             tmp_array[j] = server_key.and(&a[i], &b[j]);
//         }
//
//         // Sum the partial products into sum[i]
//         let mut current_sum = server_key.create_trivial_zero_ciphertext(&server_key.parameters);
//         for j in 0..(nb_bits - i) {
//             current_sum = server_key.add(&current_sum, &tmp_array[j]);
//         }
//         sum[i] = current_sum;
//     }
//
//     // Copy sum to result
//     for j in 0..nb_bits {
//         result[j] = sum[j].clone();
//     }
// }