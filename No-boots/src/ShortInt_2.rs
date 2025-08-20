use std::time::Instant;
use tfhe::shortint::prelude::*;
use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;

pub fn main() {
    // Generate the client key and the server key:
    let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);

    // Example 4-bit values
    let val1: u8 = 5; // binary 0101, in base 4: 11
    let val2: u8 = 6; // binary 0110, in base 4: 12

    // Encrypt as vectors: [low, high] where low = val % 4, high = val / 4
    let low1 = (val1 % 4) as u64;
    let high1 = (val1 / 4) as u64;
    let ct_low1 = cks.encrypt(low1);
    let ct_high1 = cks.encrypt(high1);
    let vec1 = vec![ct_low1, ct_high1];

    let low2 = (val2 % 4) as u64;
    let high2 = (val2 / 4) as u64;
    let ct_low2 = cks.encrypt(low2);
    let ct_high2 = cks.encrypt(high2);
    let vec2 = vec![ct_low2, ct_high2];

    let start = Instant::now();
    // Generate LUTs for mod 4 and div 4
    let lut_mod = sks.generate_lookup_table(|x| x % 4);
    let lut_div = sks.generate_lookup_table(|x| x / 4);

    // Compute partial products
    let mut ct_a0 = vec1[0].clone();
    let mut ct_a1 = vec1[1].clone();
    let mut ct_b0 = vec2[0].clone();
    let mut ct_b1 = vec2[1].clone();

    // p = a0 * b0
    let ct_p = sks.smart_mul_lsb(&mut ct_a0, &mut ct_b0);
    let ct_p_low = sks.apply_lookup_table(&ct_p, &lut_mod);
    let ct_p_carry = sks.apply_lookup_table(&ct_p, &lut_div);

    // q = a0 * b1
    let ct_q = sks.smart_mul_lsb(&mut ct_a0, &mut ct_b1);
    let ct_q_low = sks.apply_lookup_table(&ct_q, &lut_mod);
    let ct_q_carry = sks.apply_lookup_table(&ct_q, &lut_div);

    // r = a1 * b0
    let ct_r = sks.smart_mul_lsb(&mut ct_a1, &mut ct_b0);
    let ct_r_low = sks.apply_lookup_table(&ct_r, &lut_mod);
    let ct_r_carry = sks.apply_lookup_table(&ct_r, &lut_div);

    // s = a1 * b1
    let ct_s = sks.smart_mul_lsb(&mut ct_a1, &mut ct_b1);
    let ct_s_low = sks.apply_lookup_table(&ct_s, &lut_mod);
    let ct_s_carry = sks.apply_lookup_table(&ct_s, &lut_div);

    // Column 0: d0 = p_low, carry0 = p_carry
    let ct_d0 = ct_p_low.clone();
    let mut ct_carry0 = ct_p_carry.clone();

    // Column 1: sum1 = q_low + r_low + carry0
    let mut ct_sum1 = sks.smart_add(&mut ct_q_low.clone(), &mut ct_r_low.clone());
    ct_sum1 = sks.smart_add(&mut ct_sum1, &mut ct_carry0);
    let ct_d1 = sks.apply_lookup_table(&ct_sum1, &lut_mod);
    let mut ct_carry1 = sks.apply_lookup_table(&ct_sum1, &lut_div);

    // Column 2: sum2 = q_carry + r_carry + s_low + carry1
    let mut ct_sum2 = sks.smart_add(&mut ct_q_carry.clone(), &mut ct_r_carry.clone());
    ct_sum2 = sks.smart_add(&mut ct_sum2, &mut ct_s_low.clone());
    ct_sum2 = sks.smart_add(&mut ct_sum2, &mut ct_carry1);
    let ct_d2 = sks.apply_lookup_table(&ct_sum2, &lut_mod);
    let mut ct_carry2 = sks.apply_lookup_table(&ct_sum2, &lut_div);

    // Column 3: sum3 = s_carry + carry2
    let mut ct_sum3 = sks.smart_add(&mut ct_s_carry.clone(), &mut ct_carry2);
    let ct_d3 = sks.apply_lookup_table(&ct_sum3, &lut_mod);
    // Note: if needed, carry3 = sks.apply_lookup_table(&ct_sum3, &lut_div);

    let duration = start.elapsed();

    // Result vector
    let result_vec = vec![ct_d0, ct_d1, ct_d2, ct_d3];

    // Decrypt result digits
    let d0 = cks.decrypt(&result_vec[0]);
    let d1 = cks.decrypt(&result_vec[1]);
    let d2 = cks.decrypt(&result_vec[2]);
    let d3 = cks.decrypt(&result_vec[3]);

    let result = d0 + d1 * 4 + d2 * 16 + d3 * 64;

    println!("{} * {} = {}", val1, val2, result);

    // Example of noise level before and after BS on one ciphertext
    let example_ct = sks.unchecked_mul_lsb(&vec1[0], &vec2[0]);
    println!("noise level before BS: {:?}", example_ct.noise_level());

    let lut = sks.generate_lookup_table(|x| x);
    let bootstrapped = sks.apply_lookup_table(&example_ct, &lut);

    println!("noise level after BS: {:?}", bootstrapped.noise_level());
    println!("Time: {:?}", duration);
}