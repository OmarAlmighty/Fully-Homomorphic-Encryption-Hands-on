#![allow(warnings)]
use super::*; // Imports items from the parent module
use rand::Rng;
use serial_test::serial;

fn encode(a: i32, size: u8) -> Vec<bool> {
    // Convert to binary representation as a Vec<bool>
    let mut a_bits: Vec<bool> = Vec::new();
    for i in (0..size).rev() {
        a_bits.push((a & (1 << i)) != 0);
    }
    a_bits
}

fn decode(bits: &[bool]) -> i32 {
    let mut result: u8 = 0;

    for &bit in bits {
        result <<= 1;
        if bit {
            result |= 1;
        }
    }
    // Interpret as signed
    result as i32
}

fn encrypt(bits: Vec<bool>, client_key: &ClientKey) -> Vec<Ciphertext> {
    let ct_a: Vec<Ciphertext> = bits.iter().map(|&bit| client_key.encrypt(bit)).collect();
    ct_a
}

fn decrypt(ctxt: Vec<Ciphertext>, client_key: &ClientKey) -> Vec<bool> {
    let decrypted: Vec<_> = ctxt.iter().map(|bit| client_key.decrypt(bit)).collect();
    decrypted
}
// fn encode_encrypt(a: i32, size: u8, client_key: &ClientKey) -> Vec<Ciphertext> {
//     let bits: Vec<bool> = encode(a, size);
//     let mut enc_bits: Vec<Ciphertext> = encrypt(bits, client_key);
//     enc_bits.reverse();
//     enc_bits
// }
// fn decrypt_decode(ctxt:  &[Ciphertext], client_key: &ClientKey) -> i32 {
//     let mut bits: Vec<bool> = decrypt(ctxt.to_vec(), client_key);
//     bits.reverse();
//     println!("{:?}", bits);
//     let result: i32 = decode(&bits);
//     result
// }

fn encode_encrypt(value: i32, size: usize, ck: &ClientKey) -> Vec<Ciphertext> {
    // Ensure size is at least 2 (1 for sign, at least 1 for magnitude)
    assert!(
        size >= 2,
        "Size must be at least 2 for sign-magnitude representation"
    );

    let mut result = vec![Ciphertext::Trivial(false); size];

    let mut binary_string = format!("{:08b}", value);
    let binary_string: String = binary_string
        .chars()
        .rev() // Reverse the iterator to get characters from the end
        .take(size) // Take the last 'n' characters
        .collect::<String>() // Collect them into a new String
        .chars() // Convert back to char iterator to reverse again
        .rev() // Reverse to get the correct order
        .collect(); // Collect into the final String
    let binary = binary_string.chars().map(|c| c == '1').collect();
    println!("{:?}", binary);
    encrypt(binary, ck)
    // Extract sign and magnitude
    // let sign = value < 0;
    // let magnitude = value.abs() as u32;
    //
    // // Encode magnitude bits (indices 0 to size-2)
    // for i in 0..(size - 1) {
    //     let bit = (magnitude >> i) & 1 == 1;
    //     result[i] = ck.encrypt(bit);
    // }
    //
    // // Encode sign bit (index size-1)
    // result[size - 1] = ck.encrypt(sign);
    //
    // result.reverse();
    // result
}

fn decrypt_decode(bits: &[Ciphertext], ck: &ClientKey) -> i32 {
    let size = bits.len();
    assert!(
        size >= 2,
        "Size must be at least 2 for sign-magnitude representation"
    );

    let mut bits = bits.to_vec();
    bits.reverse();
    // Decrypt sign bit (last bit)
    let sign: bool = ck.decrypt(&bits[size - 1]);

    // Decrypt magnitude bits
    let mut magnitude: u32 = 0;
    let mut binary_vector: Vec<bool> = vec![false; size];
    for i in (0..size-1).rev() {
        let bit: bool = ck.decrypt(&bits[i]);
        binary_vector.push(bit);
        //magnitude |= (bit as u32) << i;
    }
    let mut binary_string = String::new();
    for &b in &binary_vector {
        if b {
            binary_string.push('1');
        } else {
            binary_string.push('0');
        }
    }
    println!("{:?}", binary_string);
    i32::from_str_radix(binary_string.as_str(), 2).expect("REASON")

    // // Apply sign
    // if sign {
    //     -(magnitude as i32)
    // } else {
    //     magnitude as i32
    // }
}

//#[test]
//#[serial]
fn test_encrypt_decrypt() {
    let (client_key, server_key) = gen_keys();

    let server = ProcessorBoolean;

    // Define two numbers and convert them to signed 8-bit representation.
    let a: i32 = 16;
    let b: i32 = -10;

    let ct_a = encode_encrypt(a, 8, &client_key);
    let ct_b = encode_encrypt(b, 8, &client_key);
    let dec_a = decrypt_decode(&ct_a, &client_key);
    let dec_b = decrypt_decode(&ct_b, &client_key);

    println!("[*] TEST: encrypt_decrypt");
    assert_eq!(dec_a, a);
    assert_eq!(dec_b, b);
    println!("[✓] PASS: encrypt_decrypt\n");
}

// #[test]
//#[serial]
fn test_and() {
    let fn_name = "e_and";
    println!("[*] TEST: {fn_name}");
    let (client_key, server_key) = gen_keys();

    let server = ProcessorBoolean;
    let mut rng = rand::thread_rng();

    // Define two numbers and convert them to signed 8-bit representation.
    let a: i32 = rng.gen_range(-50..50);
    let b: i32 = rng.gen_range(-50..50);

    let ct_a = encode_encrypt(a, 8, &client_key);
    let ct_b = encode_encrypt(b, 8, &client_key);
    let mut ct_result: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); ct_a.len()];

    server.e_and(&server_key, &ct_a, &ct_b, &mut ct_result);

    let dec_res = decrypt_decode(&ct_result, &client_key);
    println!("\t {} {} {} = {}", a, b, fn_name, dec_res);
    assert_eq!(dec_res, a & b);
    println!("[✓] PASS: {fn_name}\n");
}

// #[test]
// #[serial]
fn test_or() {
    let fn_name = "e_or";
    println!("[*] TEST: {fn_name}");
    let (client_key, server_key) = gen_keys();

    let server = ProcessorBoolean;
    let mut rng = rand::thread_rng();

    // Define two numbers and convert them to signed 8-bit representation.
    let a: i32 = rng.gen_range(-50..50);
    let b: i32 = rng.gen_range(-50..50);

    let ct_a = encode_encrypt(a, 8, &client_key);
    let ct_b = encode_encrypt(b, 8, &client_key);
    let mut ct_result: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); ct_a.len()];

    server.e_or(&server_key, &ct_a, &ct_b, &mut ct_result);

    let dec_res = decrypt_decode(&ct_result, &client_key);
    println!("\t {} {} {} = {}", a, b, fn_name, dec_res);
    assert_eq!(dec_res, a | b);
    println!("[✓] PASS: {fn_name}\n");
}

// #[test]
// #[serial]
fn test_xor() {
    let fn_name = "e_xor";
    println!("[*] TEST: {fn_name}");
    let (client_key, server_key) = gen_keys();

    let server = ProcessorBoolean;
    let mut rng = rand::thread_rng();

    // Define two numbers and convert them to signed 8-bit representation.
    let a: i32 = rng.gen_range(-50..50);
    let b: i32 = rng.gen_range(-50..50);

    let ct_a = encode_encrypt(a, 8, &client_key);
    let ct_b = encode_encrypt(b, 8, &client_key);
    let mut ct_result: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); ct_a.len()];

    server.e_xor(&server_key, &ct_a, &ct_b, &mut ct_result);

    let dec_res = decrypt_decode(&ct_result, &client_key);
    println!("\t {} {} {} = {}", a, b, fn_name, dec_res);
    assert_eq!(dec_res, a ^ b);
    println!("[✓] PASS: {fn_name}\n");
}
// #[test]
// #[serial]
fn test_nand() {
    let fn_name = "e_nand";
    println!("[*] TEST: {fn_name}");
    let (client_key, server_key) = gen_keys();

    let server = ProcessorBoolean;
    let mut rng = rand::thread_rng();

    // Define two numbers and convert them to signed 8-bit representation.
    let a: i32 = rng.gen_range(-50..50);
    let b: i32 = rng.gen_range(-50..50);

    let ct_a = encode_encrypt(a, 8, &client_key);
    let ct_b = encode_encrypt(b, 8, &client_key);
    let mut ct_result: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); ct_a.len()];

    server.e_nand(&server_key, &ct_a, &ct_b, &mut ct_result);

    let dec_res = decrypt_decode(&ct_result, &client_key);
    println!("\t {} {} {} = {}", a, b, fn_name, dec_res);
    assert_eq!(dec_res, !(a & b));
    println!("[✓] PASS: {fn_name}\n");
}
// #[test]
// #[serial]
fn test_nor() {
    let fn_name = "e_nor";
    println!("[*] TEST: {fn_name}");
    let (client_key, server_key) = gen_keys();

    let server = ProcessorBoolean;
    let mut rng = rand::thread_rng();

    // Define two numbers and convert them to signed 8-bit representation.
    let a: i32 = rng.gen_range(-50..50);
    let b: i32 = rng.gen_range(-50..50);

    let ct_a = encode_encrypt(a, 8, &client_key);
    let ct_b = encode_encrypt(b, 8, &client_key);
    let mut ct_result: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); ct_a.len()];

    server.e_nor(&server_key, &ct_a, &ct_b, &mut ct_result);

    let dec_res = decrypt_decode(&ct_result, &client_key);
    println!("\t {} {} {} = {}", a, b, fn_name, dec_res);
    assert_eq!(dec_res, !(a | b));
    println!("[✓] PASS: {fn_name}\n");
}
// #[test]
// #[serial]
fn test_xnor() {
    let fn_name = "e_xnor";
    println!("[*] TEST: {fn_name}");
    let (client_key, server_key) = gen_keys();

    let server = ProcessorBoolean;
    let mut rng = rand::thread_rng();

    // Define two numbers and convert them to signed 8-bit representation.
    let a: i32 = rng.gen_range(-50..50);
    let b: i32 = rng.gen_range(-50..50);

    let ct_a = encode_encrypt(a, 8, &client_key);
    let ct_b = encode_encrypt(b, 8, &client_key);
    let mut ct_result: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); ct_a.len()];

    server.e_xnor(&server_key, &ct_a, &ct_b, &mut ct_result);

    let dec_res = decrypt_decode(&ct_result, &client_key);
    println!("\t {} {} {} = {}", a, b, fn_name, dec_res);
    assert_eq!(dec_res, !(a ^ b));
    println!("[✓] PASS: {fn_name}\n");
}
// #[test]
// #[serial]
fn test_not() {
    let fn_name = "e_not";
    println!("[*] TEST: {fn_name}");
    let (client_key, server_key) = gen_keys();

    let server = ProcessorBoolean;
    let mut rng = rand::thread_rng();

    // Define two numbers and convert them to signed 8-bit representation.
    let a: i32 = rng.gen_range(-50..50);

    let ct_a = encode_encrypt(a, 8, &client_key);
    let mut ct_result: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); ct_a.len()];

    server.e_not(&server_key, &ct_a, &mut ct_result);

    let dec_res = decrypt_decode(&ct_result, &client_key);
    println!("\t {} {} = {}", a, fn_name, dec_res);
    assert_eq!(dec_res, !a);
    println!("[✓] PASS: {fn_name}\n");
}

// #[test]
// #[serial]
fn test_mux() {
    let fn_name = "e_mux";
    println!("[*] TEST: {fn_name}");
    let (client_key, server_key) = gen_keys();

    let server = ProcessorBoolean;
    let mut rng = rand::thread_rng();

    // Define two numbers and convert them to signed 8-bit representation.
    let a: i32 = rng.gen_range(-50..50);
    let b: i32 = rng.gen_range(-50..50);
    let c: bool = true;

    let ct_a = encode_encrypt(a, 8, &client_key);
    let ct_b = encode_encrypt(b, 8, &client_key);
    let ct_c = client_key.encrypt(c);
    let mut ct_result: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); ct_a.len()];

    server.e_mux(&server_key, &ct_c, &ct_a, &ct_b, &mut ct_result);

    let dec_res = decrypt_decode(&ct_result, &client_key);
    println!("\t {} {} {} = {}", a, b, fn_name, dec_res);
    assert_eq!(dec_res, if c { a } else { b });
    println!("[✓] PASS: {fn_name}\n");
}

// #[test]
// #[serial]
fn test_shl() {
    let fn_name = "e_shl";
    println!("[*] TEST: {fn_name}");
    let (client_key, server_key) = gen_keys();

    let server = ProcessorBoolean;

    let mut rng = rand::thread_rng();

    // Define two numbers and convert them to signed 8-bit representation.
    let a: i32 = rng.gen_range(-50..50);
    let shift: usize = 2;

    let ct_a = encode_encrypt(a, 8, &client_key);
    let mut ct_result: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); ct_a.len()];

    server.e_shl(&ct_a, shift, &mut ct_result);

    let dec_res = decrypt_decode(&ct_result, &client_key);
    println!("\t {} {} = {}", a, fn_name, dec_res);
    assert_eq!(dec_res, a << shift);
    println!("[✓] PASS: {fn_name}\n");
}

// #[test]
// #[serial]
fn test_shr() {
    let fn_name = "e_shr";
    println!("[*] TEST: {fn_name}");
    let (client_key, server_key) = gen_keys();

    let server = ProcessorBoolean;
    let mut rng = rand::thread_rng();

    // Define two numbers and convert them to signed 8-bit representation.
    let a: i32 = rng.gen_range(-50..50);
    let shift: usize = 2;

    let ct_a = encode_encrypt(a, 8, &client_key);
    let mut ct_result: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); ct_a.len()];

    server.e_shr(&ct_a, shift, &mut ct_result);

    let dec_res = decrypt_decode(&ct_result, &client_key);
    println!("\t {} {} = {}", a, fn_name, dec_res);
    assert_eq!(dec_res, a >> shift);
    println!("[✓] PASS: {fn_name}\n");
}
// #[test]
// #[serial]
fn test_e_rotr() {
    let fn_name = "e_rotr";
    println!("[*] TEST: {fn_name}");
    let (client_key, server_key) = gen_keys();

    let server = ProcessorBoolean;

    // Define number and shift amount
    let a: i32 = 16;
    let shift: usize = 2;

    let ct_a = encode_encrypt(a, 8, &client_key);
    let mut ct_result: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); ct_a.len()];

    server.e_rotr(&ct_a, shift, &mut ct_result);

    let dec_res = decrypt_decode(&ct_result, &client_key);
    println!("\t {} {} = {}", a, fn_name, dec_res);
    assert_eq!(dec_res, a.rotate_right(shift as u32));
    println!("[✓] PASS: {fn_name}\n");
}

// #[test]
// #[serial]
fn test_e_rotl() {
    let fn_name = "e_rotl";
    println!("[*] TEST: {fn_name}");
    let (client_key, server_key) = gen_keys();

    let server = ProcessorBoolean;

    // Define number and shift amount
    let a: i32 = 16;
    let shift: usize = 2;

    let ct_a = encode_encrypt(a, 8, &client_key);
    let mut ct_result: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); ct_a.len()];

    server.e_rotl(&ct_a, shift, &mut ct_result);

    let dec_res = decrypt_decode(&ct_result, &client_key);
    println!("\t {} {} = {}", a, fn_name, dec_res);
    assert_eq!(dec_res, a.rotate_left(shift as u32));
    println!("[✓] PASS: {fn_name}\n");
}

#[test]
#[serial]
fn test_adder() {
    let fn_name = "adder";
    println!("[*] TEST: {fn_name}");
    let (client_key, server_key) = gen_keys();

    let server = ProcessorBoolean;
    let mut rng = rand::thread_rng();

    // Define two numbers and convert them to signed 8-bit representation.
    let a: i32 = rng.gen_range(0..100);
    let b: i32 = rng.gen_range(0..100);

    let ct_a = encode_encrypt(a, 8, &client_key);
    let ct_b = encode_encrypt(b, 8, &client_key);
    let mut ct_result: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); ct_a.len()];

    server.adder(&server_key, &ct_a, &ct_b, &mut ct_result);

    let dec_res = decrypt_decode(&ct_result, &client_key);
    println!("\t {} {} {} = {}", a, b, fn_name, dec_res);
    assert_eq!(dec_res, a.wrapping_add(b));
    println!("[✓] PASS: {fn_name}\n");
}

#[test]
#[serial]
fn test_sign_adder() {
    let fn_name = "adder";
    println!("[*] TEST: {fn_name}");
    let (client_key, server_key) = gen_keys();

    let server = ProcessorBoolean;
    let mut rng = rand::thread_rng();

    // Define two numbers and convert them to signed 8-bit representation.
    let a: i32 = rng.gen_range(-50..50);
    let b: i32 = rng.gen_range(-50..50);

    let ct_a = encode_encrypt(a, 8, &client_key);
    let ct_b = encode_encrypt(b, 8, &client_key);
    let mut ct_result: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); 8];

    server.adder(&server_key, &ct_a, &ct_b, &mut ct_result);

    let dec_res = decrypt_decode(&ct_result, &client_key);
    println!("\t {} {} {} = {}", a, b, fn_name, dec_res);
    assert_eq!(dec_res, a.wrapping_add(b));
    println!("[✓] PASS: {fn_name}\n");
}

#[test]
#[serial]
fn test_subtracter() {
    let fn_name = "subtracter";
    println!("[*] TEST: {fn_name}");
    let (client_key, server_key) = gen_keys();

    let server = ProcessorBoolean;
    let mut rng = rand::thread_rng();

    // Define two numbers and convert them to signed 8-bit representation.
    let a: i32 = rng.gen_range(-50..50);
    let b: i32 = rng.gen_range(-50..50);

    let ct_a = encode_encrypt(a, 8, &client_key);
    let ct_b = encode_encrypt(b, 8, &client_key);
    let mut ct_result: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); ct_a.len()];
    let mut result: Vec<bool> = vec![false; 8];

    println!("{a} - {b}");
    server.ptxt_subtracter(&encode(a, 8), &encode(b, 8), &mut result);

    server.subtracter(&server_key, &ct_a, &ct_b, &mut ct_result);

    let dec_res = decrypt_decode(&ct_result, &client_key);
    println!("\t {} {} {} = {}", a, b, fn_name, dec_res);
    assert_eq!(dec_res, a.wrapping_sub(b));
    println!("[✓] PASS: {fn_name}\n");
}

#[test]
#[serial]
fn test_multiplier() {
    let fn_name = "multiplier";
    println!("[*] TEST: {fn_name}");
    let (client_key, server_key) = gen_keys();

    let server = ProcessorBoolean;
    let mut rng = rand::thread_rng();

    // Define two numbers and convert them to signed 8-bit representation.
    let a: i32 = rng.gen_range(-10..10);
    let b: i32 = rng.gen_range(-10..10);

    let ct_a = encode_encrypt(a, 8, &client_key);
    let ct_b = encode_encrypt(b, 8, &client_key);
    let mut ct_result: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); ct_a.len()];

    server.multiplier(&server_key, &ct_a, &ct_b, &mut ct_result);

    let dec_res = decrypt_decode(&ct_result, &client_key);
    println!("\t {} {} {} = {}", a, b, fn_name, dec_res);
    assert_eq!(dec_res, a.wrapping_mul(b));
    println!("[✓] PASS: {fn_name}\n");
}
#[test]
#[serial]
fn test_div() {
    let fn_name = "divider";
    println!("[*] TEST: {fn_name}");
    let (client_key, server_key) = gen_keys();

    let server = ProcessorBoolean;
    let mut rng = rand::thread_rng();

    // Define two numbers and convert them to signed 8-bit representation.
    let a: i32 = rng.gen_range(-50..50);
    let b: i32 = rng.gen_range(-50..50);

    let ct_a = encode_encrypt(a, 8, &client_key);
    let ct_b = encode_encrypt(b, 8, &client_key);
    let mut ct_result: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); ct_a.len()];

    server.divider(&server_key, &ct_a, &ct_b, &mut ct_result);

    let dec_res = decrypt_decode(&ct_result, &client_key);
    println!("\t {} {} {} = {}", a, b, fn_name, dec_res);
    assert_eq!(dec_res, a.wrapping_div(b));
    println!("[✓] PASS: {fn_name}\n");
}
#[test]
#[serial]
fn test_modulo() {
    let fn_name = "modulo";
    println!("[*] TEST: {fn_name}");
    let (client_key, server_key) = gen_keys();

    let server = ProcessorBoolean;
    let mut rng = rand::thread_rng();

    // Define two numbers and convert them to signed 8-bit representation.
    let a: i32 = rng.gen_range(-50..50);
    let b: i32 = rng.gen_range(-50..50);

    let ct_a = encode_encrypt(a, 8, &client_key);
    let ct_b = encode_encrypt(b, 8, &client_key);
    let mut ct_result: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); ct_a.len()];

    server.modulo(&server_key, &ct_a, &ct_b, &mut ct_result);

    let dec_res = decrypt_decode(&ct_result, &client_key);
    println!("\t {} {} {} = {}", a, b, fn_name, dec_res);
    assert_eq!(dec_res, a % b);
    println!("[✓] PASS: {fn_name}\n");
}

#[test]
#[serial]
fn test_max() {
    let fn_name = "max";
    println!("[*] TEST: {fn_name}");
    let (client_key, server_key) = gen_keys();

    let server = ProcessorBoolean;

    // Define two numbers and convert them to signed 8-bit representation.
    let a: [i32; 4] = [16, 10, 4, 0];
    let mut encrypted_values: Vec<Vec<Ciphertext>> = Vec::with_capacity(4);
    let mut ct_a: Vec<&[Ciphertext]> = Vec::with_capacity(4);
    for i in a.iter() {
        let encrypted = encode_encrypt(*i, 8, &client_key);
        encrypted_values.push(encrypted);
    }

    for encrypted in &encrypted_values {
        ct_a.push(encrypted.as_slice());
    }

    let mut ct_result: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); ct_a.len()];

    server.max(&server_key, &ct_a, &mut ct_result);

    let dec_res = decrypt_decode(&ct_result, &client_key);
    assert_eq!(dec_res, *a.iter().max().unwrap());
    println!("[✓] PASS: {fn_name}\n");
}

#[test]
#[serial]
fn test_min() {
    let fn_name = "min";
    println!("[*] TEST: {fn_name}");
    let (client_key, server_key) = gen_keys();

    let server = ProcessorBoolean;

    // Define two numbers and convert them to signed 8-bit representation.
    let a: [i32; 4] = [16, 10, -1, 0];
    let mut encrypted_values: Vec<Vec<Ciphertext>> = Vec::with_capacity(4);
    let mut ct_a: Vec<&[Ciphertext]> = Vec::with_capacity(4);
    for i in a.iter() {
        let encrypted = encode_encrypt(*i, 8, &client_key);
        encrypted_values.push(encrypted);
    }

    for encrypted in &encrypted_values {
        ct_a.push(encrypted.as_slice());
    }

    let mut ct_result: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); ct_a.len()];

    server.min(&server_key, &ct_a, &mut ct_result);

    let dec_res = decrypt_decode(&ct_result, &client_key);
    assert_eq!(dec_res, *a.iter().min().unwrap());
    println!("[✓] PASS: {fn_name}\n");
}

#[test]
#[serial]
fn test_relu() {
    let fn_name = "relu";
    println!("[*] TEST: {fn_name}");
    let (client_key, server_key) = gen_keys();

    let server = ProcessorBoolean;

    // Define the number for ReLU activation
    let a: i32 = -10;

    let ct_a = encode_encrypt(a, 8, &client_key);
    let mut ct_result: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); ct_a.len()];

    server.relu(&server_key, &ct_a, &mut ct_result);

    let dec_res = decrypt_decode(&ct_result, &client_key);
    println!("\t {} {} = {}", a, fn_name, dec_res);
    assert_eq!(dec_res, std::cmp::max(0, a));
    println!("[✓] PASS: {fn_name}\n");
}
#[test]
#[serial]
fn test_sqrt() {
    let fn_name = "sqrt";
    println!("[*] TEST: {fn_name}");
    let (client_key, server_key) = gen_keys();

    let server = ProcessorBoolean;

    // Define the number for ReLU activation
    let a: i32 = 100;

    let ct_a = encode_encrypt(a, 8, &client_key);
    let mut ct_result: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); ct_a.len()];

    server.sqrt(&server_key, &ct_a, &mut ct_result);

    let dec_res = decrypt_decode(&ct_result, &client_key);
    println!("\t {} {} = {}", a, fn_name, dec_res);
    assert_eq!(dec_res, a.isqrt());
    println!("[✓] PASS: {fn_name}\n");
}
#[test]
#[serial]
fn test_mean() {
    let fn_name = "mean";
    println!("[*] TEST: {fn_name}");
    let (client_key, server_key) = gen_keys();

    let server = ProcessorBoolean;

    // Define two numbers and convert them to signed 8-bit representation.
    let a: [i32; 4] = [16, 10, 4, 2];
    let mut encrypted_values: Vec<Vec<Ciphertext>> = Vec::with_capacity(4);
    let mut ct_a: Vec<&[Ciphertext]> = Vec::with_capacity(4);
    for i in a.iter() {
        let encrypted = encode_encrypt(*i, 8, &client_key);
        encrypted_values.push(encrypted);
    }

    for encrypted in &encrypted_values {
        ct_a.push(encrypted.as_slice());
    }

    let mut ct_result: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); ct_a.len()];

    server.mean(&server_key, &ct_a, a.len(), &mut ct_result);

    let dec_res = decrypt_decode(&ct_result, &client_key);
    assert_eq!(dec_res, *a.iter().min().unwrap());
    println!("[✓] PASS: {fn_name}\n");
}
#[test]
#[serial]
fn test_variance() {
    let fn_name = "variance";
    println!("[*] TEST: {fn_name}");
    let (client_key, server_key) = gen_keys();

    let server = ProcessorBoolean;

    // Define two numbers and convert them to signed 8-bit representation.
    let a: [i32; 4] = [16, 10, 4, 2];
    let mut encrypted_values: Vec<Vec<Ciphertext>> = Vec::with_capacity(4);
    let mut ct_a: Vec<&[Ciphertext]> = Vec::with_capacity(4);
    for i in a.iter() {
        let encrypted = encode_encrypt(*i, 8, &client_key);
        encrypted_values.push(encrypted);
    }

    for encrypted in &encrypted_values {
        ct_a.push(encrypted.as_slice());
    }

    let mut ct_result: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); ct_a.len()];

    server.variance(&server_key, &ct_a, a.len(), &mut ct_result);

    let dec_res = decrypt_decode(&ct_result, &client_key);
    assert_eq!(dec_res, *a.iter().min().unwrap());
    println!("[✓] PASS: {fn_name}\n");
}
#[test]
#[serial]
fn test_standard_deviation() {
    let fn_name = "standard_deviation";
    println!("[*] TEST: {fn_name}");
    let (client_key, server_key) = gen_keys();

    let server = ProcessorBoolean;

    // Define two numbers and convert them to signed 8-bit representation.
    let a: [i32; 4] = [16, 10, 4, 2];
    let mut encrypted_values: Vec<Vec<Ciphertext>> = Vec::with_capacity(4);
    let mut ct_a: Vec<&[Ciphertext]> = Vec::with_capacity(4);
    for i in a.iter() {
        let encrypted = encode_encrypt(*i, 8, &client_key);
        encrypted_values.push(encrypted);
    }

    for encrypted in &encrypted_values {
        ct_a.push(encrypted.as_slice());
    }

    let mut ct_result: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); ct_a.len()];

    server.standard_deviation(&server_key, &ct_a, a.len(), &mut ct_result);

    let dec_res = decrypt_decode(&ct_result, &client_key);
    assert_eq!(dec_res, *a.iter().min().unwrap());
    println!("[✓] PASS: {fn_name}\n");
}
