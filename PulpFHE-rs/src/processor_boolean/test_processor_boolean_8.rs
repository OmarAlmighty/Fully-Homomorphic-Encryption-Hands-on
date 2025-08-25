#![allow(warnings)]
use super::*; // Imports items from the parent module

fn encode(a: i8, size: u8) -> Vec<bool> {
    // Convert to binary representation as a Vec<bool>
    let mut a_bits: Vec<bool> = Vec::new();
    for i in (0..size).rev() {
        a_bits.push((a & (1 << i)) != 0);
    }
    a_bits
}

fn decode(bits: &[bool]) -> i8 {
    let mut result: u8 = 0;

    for &bit in bits {
        result <<= 1;
        if bit {
            result |= 1;
        }
    }
    // Interpret as signed
    result as i8
}

fn encrypt(bits: Vec<bool>, client_key: &ClientKey) -> Vec<Ciphertext> {
    let ct_a: Vec<Ciphertext> = bits.iter().map(|&bit| client_key.encrypt(bit)).collect();
    ct_a
}

fn decrypt(ctxt: Vec<Ciphertext>, client_key: &ClientKey) -> Vec<bool> {
    let decrypted: Vec<_> = ctxt.iter().map(|bit| client_key.decrypt(bit)).collect();
    decrypted
}
fn encode_encrypt(a: i8, size: u8, client_key: &ClientKey) -> Vec<Ciphertext> {
    let bits: Vec<bool> = encode(a, size);
    let enc_bits: Vec<Ciphertext> = encrypt(bits, client_key);
    enc_bits
}
fn decrypt_decode(ctxt: Vec<Ciphertext>, client_key: &ClientKey, size: u8) -> i8 {
    let bits: Vec<bool> = decrypt(ctxt, client_key);
    let result: i8 = decode(&bits);
    result
}

#[test]
fn test_encrypt_decrypt() {
    let (client_key, server_key) = gen_keys();

    let server = ProcessorBoolean;

    // Define two numbers and convert them to signed 8-bit representation.
    let a: i8 = 16;
    let b: i8 = -10;

    let ct_a = encode_encrypt(a, 8, &client_key);
    let ct_b = encode_encrypt(b, 8, &client_key);
    let dec_a = decrypt_decode(ct_a, &client_key, 8);
    let dec_b = decrypt_decode(ct_b, &client_key, 8);

    println!("[*] TEST: encrypt_decrypt");
    assert_eq!(dec_a, a);
    assert_eq!(dec_b, b);
    println!("[✓] PASS: encrypt_decrypt\n");
}

#[test]
fn test_and() {
    let (client_key, server_key) = gen_keys();

    let server = ProcessorBoolean;

    // Define two numbers and convert them to signed 8-bit representation.
    let a: i8 = 16;
    let b: i8 = -10;

    let ct_a = encode_encrypt(a, 8, &client_key);
    let ct_b = encode_encrypt(b, 8, &client_key);
    let mut ct_result: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); ct_a.len()];

    server.e_and(&server_key, &ct_a, &ct_b, &mut ct_result);

    let dec_res = decrypt_decode(ct_result, &client_key, 8);
    let fn_name = "e_and";
    println!("[*] TEST: {fn_name}");
    assert_eq!(dec_res, a & b);
    println!("[✓] PASS: {fn_name}\n");
}

#[test]
fn test_or() {
    let (client_key, server_key) = gen_keys();

    let server = ProcessorBoolean;

    // Define two numbers and convert them to signed 8-bit representation.
    let a: i8 = 16;
    let b: i8 = -10;

    let ct_a = encode_encrypt(a, 8, &client_key);
    let ct_b = encode_encrypt(b, 8, &client_key);
    let mut ct_result: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); ct_a.len()];

    server.e_or(&server_key, &ct_a, &ct_b, &mut ct_result);

    let dec_res = decrypt_decode(ct_result, &client_key, 8);
    let fn_name = "e_or";
    println!("[*] TEST: {fn_name}");
    assert_eq!(dec_res, a | b);
    println!("[✓] PASS: {fn_name}\n");
}

#[test]
fn test_xor() {
    let (client_key, server_key) = gen_keys();

    let server = ProcessorBoolean;

    // Define two numbers and convert them to signed 8-bit representation.
    let a: i8 = 16;
    let b: i8 = -10;

    let ct_a = encode_encrypt(a, 8, &client_key);
    let ct_b = encode_encrypt(b, 8, &client_key);
    let mut ct_result: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); ct_a.len()];

    server.e_xor(&server_key, &ct_a, &ct_b, &mut ct_result);

    let dec_res = decrypt_decode(ct_result, &client_key, 8);
    let fn_name = "e_xor";
    println!("[*] TEST: {fn_name}");
    assert_eq!(dec_res, a ^ b);
    println!("[✓] PASS: {fn_name}\n");
}
#[test]
fn test_nand() {
    let (client_key, server_key) = gen_keys();

    let server = ProcessorBoolean;

    // Define two numbers and convert them to signed 8-bit representation.
    let a: i8 = 16;
    let b: i8 = -10;

    let ct_a = encode_encrypt(a, 8, &client_key);
    let ct_b = encode_encrypt(b, 8, &client_key);
    let mut ct_result: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); ct_a.len()];

    server.e_nand(&server_key, &ct_a, &ct_b, &mut ct_result);

    let dec_res = decrypt_decode(ct_result, &client_key, 8);
    let fn_name = "e_nand";
    println!("[*] TEST: {fn_name}");
    assert_eq!(dec_res, !(a & b));
    println!("[✓] PASS: {fn_name}\n");
}
#[test]
fn test_nor() {
    let (client_key, server_key) = gen_keys();

    let server = ProcessorBoolean;

    // Define two numbers and convert them to signed 8-bit representation.
    let a: i8 = 16;
    let b: i8 = -10;

    let ct_a = encode_encrypt(a, 8, &client_key);
    let ct_b = encode_encrypt(b, 8, &client_key);
    let mut ct_result: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); ct_a.len()];

    server.e_nor(&server_key, &ct_a, &ct_b, &mut ct_result);

    let dec_res = decrypt_decode(ct_result, &client_key, 8);
    let fn_name = "e_nor";
    println!("[*] TEST: {fn_name}");
    assert_eq!(dec_res, !(a | b));
    println!("[✓] PASS: {fn_name}\n");
}
#[test]
fn test_xnor() {
    let (client_key, server_key) = gen_keys();

    let server = ProcessorBoolean;

    // Define two numbers and convert them to signed 8-bit representation.
    let a: i8 = 16;
    let b: i8 = -10;

    let ct_a = encode_encrypt(a, 8, &client_key);
    let ct_b = encode_encrypt(b, 8, &client_key);
    let mut ct_result: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); ct_a.len()];

    server.e_xnor(&server_key, &ct_a, &ct_b, &mut ct_result);

    let dec_res = decrypt_decode(ct_result, &client_key, 8);
    let fn_name = "e_xnor";
    println!("[*] TEST: {fn_name}");
    assert_eq!(dec_res, !(a ^ b));
    println!("[✓] PASS: {fn_name}\n");
}
#[test]
fn test_not() {
    let (client_key, server_key) = gen_keys();

    let server = ProcessorBoolean;

    // Define two numbers and convert them to signed 8-bit representation.
    let a: i8 = 16;
    let b: i8 = -10;

    let ct_a = encode_encrypt(a, 8, &client_key);
    let ct_b = encode_encrypt(b, 8, &client_key);
    let mut ct_result: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); ct_a.len()];

    server.e_not(&server_key, &ct_a, &mut ct_result);

    let dec_res = decrypt_decode(ct_result, &client_key, 8);
    let fn_name = "e_not";
    println!("[*] TEST: {fn_name}");
    assert_eq!(dec_res, !a);
    println!("[✓] PASS: {fn_name}\n");
}

