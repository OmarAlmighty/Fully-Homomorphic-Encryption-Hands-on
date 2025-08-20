use tfhe::shortint::prelude::*;

fn encrypt_bits(client_key: &ClientKey, value: u8, bit_size: usize) -> Vec<Ciphertext> {
    (0..bit_size)
        .map(|i| client_key.encrypt(((value >> i) & 1) as u64))
        .collect()
}

fn decrypt_bits(client_key: &ClientKey, bits: &[Ciphertext]) -> u64 {
    bits.iter()
        .enumerate()
        .map(|(i, bit)| client_key.decrypt(bit) << i)
        .sum()
}

/// Homomorphic XOR: a + b - 2ab
fn homomorphic_xor(server_key: &ServerKey, a: &Ciphertext, b: &Ciphertext) -> Ciphertext {
    let sum = server_key.add(a, b);
    let prod = server_key.mul(a, b);
    let double_prod = server_key.scalar_mul(&prod, 2);
    server_key.sub(&sum, &double_prod)
}

/// Homomorphic full adder for a single bit
fn full_adder(
    server_key: &ServerKey,
    a: &Ciphertext,
    b: &Ciphertext,
    carry_in: &Ciphertext,
) -> (Ciphertext, Ciphertext) {
    let ab_xor = homomorphic_xor(server_key, a, b);
    let sum = homomorphic_xor(server_key, &ab_xor, carry_in);

    let ab = server_key.mul(a, b);
    let bc = server_key.mul(b, carry_in);
    let ac = server_key.mul(a, carry_in);

    let carry_out = server_key.add(&ab, &bc);
    let carry_out = server_key.add(&carry_out, &ac);

    (sum, carry_out)
}

/// Adds two encrypted bit vectors (of same size), returns result of size+1 bits
fn add_bit_vectors(
    server_key: &ServerKey,
    a: &[Ciphertext],
    b: &[Ciphertext],
) -> Vec<Ciphertext> {
    let mut result = Vec::new();
    let zero = server_key.create_trivial(0);
    let mut carry = zero.clone();

    for i in 0..a.len() {
        let (sum, new_carry) = full_adder(server_key, &a[i], &b[i], &carry);
        result.push(sum);
        carry = new_carry;
    }
    result.push(carry);
    result
}

/// Shift encrypted bits left by `shift` (adds `shift` zeros at the beginning)
fn shift_left(server_key: &ServerKey, bits: &[Ciphertext], shift: usize) -> Vec<Ciphertext> {
    let zero = server_key.create_trivial(0);
    let mut result = vec![zero; shift];
    result.extend_from_slice(bits);
    result
}

/// Multiply two encrypted bit vectors
fn bitwise_multiply(
    server_key: &ServerKey,
    a: &[Ciphertext],
    b: &[Ciphertext],
) -> Vec<Ciphertext> {
    let mut result = vec![server_key.create_trivial(0)];

    for (i, b_bit) in b.iter().enumerate() {
        // Partial product: a AND b_i
        let partial_product: Vec<Ciphertext> = a.iter().map(|a_bit| server_key.mul(a_bit, b_bit)).collect();
        let shifted = shift_left(server_key, &partial_product, i);
        result = add_bit_vectors(server_key, &result, &shifted);
    }

    result
}

fn main() {
    // Set up key and params
    let (client_key, server_key) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);

    // Inputs
    let a_val = 7u8; // 0111
    let b_val = 3u8; // 0011

    // Encrypt each bit
    let a_bits = encrypt_bits(&client_key, a_val, 4);
    let b_bits = encrypt_bits(&client_key, b_val, 4);

    // Homomorphic multiplication
    let product_bits = bitwise_multiply(&server_key, &a_bits, &b_bits);

    // Decrypt
    let result = decrypt_bits(&client_key, &product_bits);

    println!("{} * {} = {}", a_val, b_val, result);
    assert_eq!(result, (a_val as u16 * b_val as u16) as u64);
}
