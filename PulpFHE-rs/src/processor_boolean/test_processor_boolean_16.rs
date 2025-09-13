#![allow(warnings)]
use super::*; // Imports items from the parent module
use rand::Rng;
use serial_test::serial;

fn encode(a: i16, size: usize) -> Vec<bool> {
    // Convert to binary representation as a Vec<bool>
    let mut bits = Vec::with_capacity(size);
    for i in 0..size {
        let bit = ((a >> i) & 1) != 0;
        bits.push(bit);
    }
    println!("");
    bits
}

fn decode(bits: &[bool]) -> i16 {
    let mut res: u16 = 0;
    for (i, &bit) in bits.iter().enumerate() {
        if bit {
            res |= 1u16 << i;
        }
    }
    i16::from_ne_bytes(res.to_ne_bytes())
}

fn encrypt(bits: Vec<bool>, client_key: &ClientKey) -> Vec<Ciphertext> {
    let ct_a: Vec<Ciphertext> = bits.iter().map(|&bit| client_key.encrypt(bit)).collect();
    ct_a
}

fn decrypt(ctxt: Vec<Ciphertext>, client_key: &ClientKey) -> Vec<bool> {
    let decrypted: Vec<_> = ctxt.iter().map(|bit| client_key.decrypt(bit)).collect();
    decrypted
}

// Function to encrypt each bit of a signed integer (i64) using the Boolean API
pub fn encode_encrypt(num: i16, size: usize, ck: &ClientKey) -> Vec<Ciphertext> {
    // Binary encoding is LSB...MSB
    let mut ciphertexts = Vec::with_capacity(size);
    for i in 0..size {
        let bit = ((num >> i) & 1) != 0;
        print!("{}", bit as u16);
        ciphertexts.push(ck.encrypt(bit));
    }
    println!("");
    ciphertexts
}

// Function to decrypt the ciphertext vector and reconstruct the signed integer (i64)
pub fn decrypt_decode(ciphertexts: &[Ciphertext], client_key: &ClientKey) -> i16 {
    let mut bits: u16 = 0;
    for (i, ct) in ciphertexts.iter().enumerate() {
        let bit = client_key.decrypt(ct);
        print!("{}", bit as u16);
        if bit {
            bits |= 1u16 << i;
        }
    }
    println!("");
    println!("{:?}", bits);
    i16::from_ne_bytes(bits.to_ne_bytes())
}

pub fn new_decrypt_decode(ciphertexts: &[Ciphertext], client_key: &ClientKey) -> i16 {
    let mut bits: u16 = 0;
    for (i, ct) in ciphertexts.iter().enumerate() {
        let bit = client_key.decrypt(ct);
        print!("{}", bit as u16);
        if bit {
            bits |= 1u16 << i;
        }
    }
    println!("");
    i16::from_ne_bytes(bits.to_ne_bytes())
}

#[test]
#[serial]
fn test_encrypt_decrypt() {
    let (client_key, server_key) = gen_keys();

    let server = ProcessorBoolean;

    // Define two numbers and convert them to signed 16-bit representation.
    let a: i16 = 16;
    let b: i16 = -10;

    let ct_a = encode_encrypt(a, 16, &client_key);
    let ct_b = encode_encrypt(b, 16, &client_key);
    let dec_a = decrypt_decode(&ct_a, &client_key);
    let dec_b = decrypt_decode(&ct_b, &client_key);

    println!("[*] TEST: encrypt_decrypt");
    assert_eq!(dec_a, a);
    assert_eq!(dec_b, b);
    println!("[✓] PASS: encrypt_decrypt\n");
}
#[test]
#[serial]
fn test_gate_bootstrap_cycles() {
    println!("Measuring the time difference between gate bootstrapping and gate evaluation");
    println!("[*] All times are in milliseconds");

    let (client_key, server_key) = gen_keys();

    let server = ProcessorBoolean;
    let mut rng = rand::thread_rng();

    // Define two numbers and convert them to signed 8-bit representation.
    let a: i16 = rng.gen_range(-50..50);
    let b: i16 = rng.gen_range(-50..50);

    let ct_a = encode_encrypt(a, 16, &client_key);
    let ct_b = encode_encrypt(b, 16, &client_key);
    let mut ct_result1: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); ct_a.len()];
    let mut ct_result2: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); ct_a.len()];
    let mut ct_result3: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); ct_a.len()];
    let mut ct_result4: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); ct_a.len()];
    let mut ct_result5: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); ct_a.len()];
    let mut ct_result6: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); ct_a.len()];


    server.e_and_bench(&server_key, &ct_a, &ct_b, &mut ct_result1);
    server.e_or_bench(&server_key, &ct_a, &ct_b, &mut ct_result2);
    server.e_xor_bench(&server_key, &ct_a, &ct_b, &mut ct_result3);
    server.e_nand_bench(&server_key, &ct_a, &ct_b, &mut ct_result4);
    server.e_nor_bench(&server_key, &ct_a, &ct_b, &mut ct_result5);
    server.e_xnor_bench(&server_key, &ct_a, &ct_b, &mut ct_result6);



    let dec_res = decrypt_decode(&ct_result1, &client_key);
    assert_eq!(dec_res, (a & b));

    let dec_res = decrypt_decode(&ct_result2, &client_key);
    assert_eq!(dec_res, (a | b));

    let dec_res = decrypt_decode(&ct_result3, &client_key);
    assert_eq!(dec_res, (a ^ b));

    let dec_res = decrypt_decode(&ct_result4, &client_key);
    assert_eq!(dec_res, !(a & b));

    let dec_res = decrypt_decode(&ct_result5, &client_key);
    assert_eq!(dec_res, !(a | b));

    let dec_res = decrypt_decode(&ct_result6, &client_key);
    assert_eq!(dec_res, !(a ^ b));
}

#[test]
#[serial]
fn test_gate_cycles_nobootstrapping() {
    println!("Measuring the time difference between gate bootstrapping and gate evaluation");
    println!("[*] All times are in milliseconds");

    let (client_key, server_key) = gen_keys();

    let server = ProcessorBoolean;
    let mut rng = rand::thread_rng();

    // Define two numbers and convert them to signed 8-bit representation.
    let a: i16 = rng.gen_range(-50..50);
    let b: i16 = rng.gen_range(-50..50);

    let ct_a = encode_encrypt(a, 16, &client_key);
    let ct_b = encode_encrypt(b, 16, &client_key);
    let mut ct_result1: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); ct_a.len()];
    let mut ct_result2: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); ct_a.len()];
    let mut ct_result3: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); ct_a.len()];
    let mut ct_result4: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); ct_a.len()];
    let mut ct_result5: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); ct_a.len()];
    let mut ct_result6: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); ct_a.len()];


    server.e_and_bench_nobootstrapping(&server_key, &ct_a, &ct_b, &mut ct_result1);
    server.e_or_bench_nobootstrapping(&server_key, &ct_a, &ct_b, &mut ct_result2);
    server.e_xor_bench_nobootstrapping(&server_key, &ct_a, &ct_b, &mut ct_result3);
    server.e_nand_bench_nobootstrapping(&server_key, &ct_a, &ct_b, &mut ct_result4);
    server.e_nor_bench_nobootstrapping(&server_key, &ct_a, &ct_b, &mut ct_result5);
    server.e_xnor_bench_nobootstrapping(&server_key, &ct_a, &ct_b, &mut ct_result6);


    let dec_res = decrypt_decode(&ct_result1, &client_key);
    assert_eq!(dec_res, (a & b));

    let dec_res = decrypt_decode(&ct_result2, &client_key);
    assert_eq!(dec_res, (a | b));

    let dec_res = decrypt_decode(&ct_result3, &client_key);
    assert_eq!(dec_res, (a ^ b));

    let dec_res = decrypt_decode(&ct_result4, &client_key);
    assert_eq!(dec_res, !(a & b));

    let dec_res = decrypt_decode(&ct_result5, &client_key);
    assert_eq!(dec_res, !(a | b));

    let dec_res = decrypt_decode(&ct_result6, &client_key);
    assert_eq!(dec_res, !(a ^ b));
}
#[test]
#[serial]
fn test_and() {
    let fn_name = "e_and";
    println!("[*] TEST: {fn_name}");
    let (client_key, server_key) = gen_keys();

    let server = ProcessorBoolean;
    let mut rng = rand::thread_rng();

    // Define two numbers and convert them to signed 16-bit representation.
    let a: i16 = rng.gen_range(-50..50);
    let b: i16 = rng.gen_range(-50..50);

    let ct_a = encode_encrypt(a, 16, &client_key);
    let ct_b = encode_encrypt(b, 16, &client_key);
    let mut ct_result: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); ct_a.len()];

    server.e_and(&server_key, &ct_a, &ct_b, &mut ct_result);

    let dec_res = decrypt_decode(&ct_result, &client_key);
    println!("\t {} {} {} = {}", a, b, fn_name, dec_res);
    assert_eq!(dec_res, a & b);
    println!("[✓] PASS: {fn_name}\n");
}

#[test]
#[serial]
fn test_or() {
    let fn_name = "e_or";
    println!("[*] TEST: {fn_name}");
    let (client_key, server_key) = gen_keys();

    let server = ProcessorBoolean;
    let mut rng = rand::thread_rng();

    // Define two numbers and convert them to signed 16-bit representation.
    let a: i16 = rng.gen_range(-50..50);
    let b: i16 = rng.gen_range(-50..50);

    let ct_a = encode_encrypt(a, 16, &client_key);
    let ct_b = encode_encrypt(b, 16, &client_key);
    let mut ct_result: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); ct_a.len()];

    server.e_or(&server_key, &ct_a, &ct_b, &mut ct_result);

    let dec_res = decrypt_decode(&ct_result, &client_key);
    println!("\t {} {} {} = {}", a, b, fn_name, dec_res);
    assert_eq!(dec_res, a | b);
    println!("[✓] PASS: {fn_name}\n");
}

#[test]
#[serial]
fn test_xor() {
    let fn_name = "e_xor";
    println!("[*] TEST: {fn_name}");
    let (client_key, server_key) = gen_keys();

    let server = ProcessorBoolean;
    let mut rng = rand::thread_rng();

    // Define two numbers and convert them to signed 16-bit representation.
    let a: i16 = rng.gen_range(-50..50);
    let b: i16 = rng.gen_range(-50..50);

    let ct_a = encode_encrypt(a, 16, &client_key);
    let ct_b = encode_encrypt(b, 16, &client_key);
    let mut ct_result: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); ct_a.len()];

    server.e_xor(&server_key, &ct_a, &ct_b, &mut ct_result);

    let dec_res = decrypt_decode(&ct_result, &client_key);
    println!("\t {} {} {} = {}", a, b, fn_name, dec_res);
    assert_eq!(dec_res, a ^ b);
    println!("[✓] PASS: {fn_name}\n");
}
#[test]
#[serial]
fn test_nand() {
    let fn_name = "e_nand";
    println!("[*] TEST: {fn_name}");
    let (client_key, server_key) = gen_keys();

    let server = ProcessorBoolean;
    let mut rng = rand::thread_rng();

    // Define two numbers and convert them to signed 16-bit representation.
    let a: i16 = rng.gen_range(-50..50);
    let b: i16 = rng.gen_range(-50..50);

    let ct_a = encode_encrypt(a, 16, &client_key);
    let ct_b = encode_encrypt(b, 16, &client_key);
    let mut ct_result: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); ct_a.len()];

    server.e_nand(&server_key, &ct_a, &ct_b, &mut ct_result);

    let dec_res = decrypt_decode(&ct_result, &client_key);
    println!("\t {} {} {} = {}", a, b, fn_name, dec_res);
    assert_eq!(dec_res, !(a & b));
    println!("[✓] PASS: {fn_name}\n");
}
#[test]
#[serial]
fn test_nor() {
    let fn_name = "e_nor";
    println!("[*] TEST: {fn_name}");
    let (client_key, server_key) = gen_keys();

    let server = ProcessorBoolean;
    let mut rng = rand::thread_rng();

    // Define two numbers and convert them to signed 16-bit representation.
    let a: i16 = rng.gen_range(-50..50);
    let b: i16 = rng.gen_range(-50..50);

    let ct_a = encode_encrypt(a, 16, &client_key);
    let ct_b = encode_encrypt(b, 16, &client_key);
    let mut ct_result: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); ct_a.len()];

    server.e_nor(&server_key, &ct_a, &ct_b, &mut ct_result);

    let dec_res = decrypt_decode(&ct_result, &client_key);
    println!("\t {} {} {} = {}", a, b, fn_name, dec_res);
    assert_eq!(dec_res, !(a | b));
    println!("[✓] PASS: {fn_name}\n");
}
#[test]
#[serial]
fn test_xnor() {
    let fn_name = "e_xnor";
    println!("[*] TEST: {fn_name}");
    let (client_key, server_key) = gen_keys();

    let server = ProcessorBoolean;
    let mut rng = rand::thread_rng();

    // Define two numbers and convert them to signed 16-bit representation.
    let a: i16 = rng.gen_range(-50..50);
    let b: i16 = rng.gen_range(-50..50);

    let ct_a = encode_encrypt(a, 16, &client_key);
    let ct_b = encode_encrypt(b, 16, &client_key);
    let mut ct_result: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); ct_a.len()];

    server.e_xnor(&server_key, &ct_a, &ct_b, &mut ct_result);

    let dec_res = decrypt_decode(&ct_result, &client_key);
    println!("\t {} {} {} = {}", a, b, fn_name, dec_res);
    assert_eq!(dec_res, !(a ^ b));
    println!("[✓] PASS: {fn_name}\n");
}
#[test]
#[serial]
fn test_not() {
    let fn_name = "e_not";
    println!("[*] TEST: {fn_name}");
    let (client_key, server_key) = gen_keys();

    let server = ProcessorBoolean;
    let mut rng = rand::thread_rng();

    // Define two numbers and convert them to signed 16-bit representation.
    let a: i16 = rng.gen_range(-50..50);

    let ct_a = encode_encrypt(a, 16, &client_key);
    let mut ct_result: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); ct_a.len()];

    server.e_not(&server_key, &ct_a, &mut ct_result);

    let dec_res = decrypt_decode(&ct_result, &client_key);
    println!("\t {} {} = {}", a, fn_name, dec_res);
    assert_eq!(dec_res, !a);
    println!("[✓] PASS: {fn_name}\n");
}

#[test]
#[serial]
fn test_mux() {
    let fn_name = "e_mux";
    println!("[*] TEST: {fn_name}");
    let (client_key, server_key) = gen_keys();

    let server = ProcessorBoolean;
    let mut rng = rand::thread_rng();

    // Define two numbers and convert them to signed 16-bit representation.
    let a: i16 = rng.gen_range(-50..50);
    let b: i16 = rng.gen_range(-50..50);
    let c: bool = true;

    let ct_a = encode_encrypt(a, 16, &client_key);
    let ct_b = encode_encrypt(b, 16, &client_key);
    let ct_c = client_key.encrypt(c);
    let mut ct_result: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); ct_a.len()];

    server.e_mux(&server_key, &ct_c, &ct_a, &ct_b, &mut ct_result);

    let dec_res = decrypt_decode(&ct_result, &client_key);
    println!("\t {} {} {} = {}", a, b, fn_name, dec_res);
    assert_eq!(dec_res, if c { a } else { b });
    println!("[✓] PASS: {fn_name}\n");
}

#[test]
#[serial]
fn test_shl() {
    let fn_name = "e_shl";
    println!("[*] TEST: {fn_name}");
    let (client_key, server_key) = gen_keys();

    let server = ProcessorBoolean;

    let mut rng = rand::thread_rng();

    // Define two numbers and convert them to signed 16-bit representation.
    let a: i16 = rng.gen_range(-50..50);
    let shift: usize = 2;

    let ct_a = encode_encrypt(a, 16, &client_key);
    let mut ct_result: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); ct_a.len()];

    server.e_shl(&ct_a, shift, &mut ct_result);

    let dec_res = decrypt_decode(&ct_result, &client_key);
    println!("\t {} {} = {}", a, fn_name, dec_res);
    assert_eq!(dec_res, a << shift);
    println!("[✓] PASS: {fn_name}\n");
}

#[test]
#[serial]
fn test_shr() {
    let fn_name = "e_shr";
    println!("[*] TEST: {fn_name}");
    let (client_key, server_key) = gen_keys();

    let server = ProcessorBoolean;
    let mut rng = rand::thread_rng();

    // Define two numbers and convert them to signed 16-bit representation.
    let a: i16 = rng.gen_range(-50..50);
    let shift: usize = 2;

    let ct_a = encode_encrypt(a, 16, &client_key);
    let mut ct_result: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); ct_a.len()];

    server.e_shr(&ct_a, shift, &mut ct_result);

    let dec_res = decrypt_decode(&ct_result, &client_key);
    println!("\t {} {} = {}", a, fn_name, dec_res);
    assert_eq!(dec_res, a >> shift);
    println!("[✓] PASS: {fn_name}\n");
}

#[test]
#[serial]
fn test_e_rotr() {
    let fn_name = "e_rotr";
    println!("[*] TEST: {fn_name}");
    let (client_key, server_key) = gen_keys();

    let server = ProcessorBoolean;
    let mut rng = rand::thread_rng();

    // Define number and shift amount
    let a: i16 = rng.gen_range(-50..50);
    let shift: usize = 2;

    let ct_a = encode_encrypt(a, 16, &client_key);
    let mut ct_result: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); ct_a.len()];

    server.e_rotr(&ct_a, shift, &mut ct_result);

    let dec_res = decrypt_decode(&ct_result, &client_key);
    println!("\t {} {} = {}", a, fn_name, dec_res);
    assert_eq!(dec_res, a.rotate_right(shift as u32));
    println!("[✓] PASS: {fn_name}\n");
}

#[test]
#[serial]
fn test_e_rotl() {
    let fn_name = "e_rotl";
    println!("[*] TEST: {fn_name}");
    let (client_key, server_key) = gen_keys();

    let server = ProcessorBoolean;

    let mut rng = rand::thread_rng();

    // Define number and shift amount
    let a: i16 = rng.gen_range(-50..50);
    let shift: usize = 2;

    let ct_a = encode_encrypt(a, 16, &client_key);
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

    // Define two numbers and convert them to signed 16-bit representation.
    let a: i16 = rng.gen_range(-50..51);
    let b: i16 = -rng.gen_range(-50..51);

    let ct_a = encode_encrypt(a, 16, &client_key);
    let ct_b = encode_encrypt(b, 16, &client_key);
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

    // Define two numbers and convert them to signed 16-bit representation.
    let a: i16 = rng.gen_range(-50..50);
    let b: i16 = rng.gen_range(-50..50);

    let ct_a = encode_encrypt(a, 16, &client_key);
    let ct_b = encode_encrypt(b, 16, &client_key);
    let mut ct_result: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); 16];

    server.sign_adder(&server_key, &ct_a, &ct_b, &mut ct_result);

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

    // Define two numbers and convert them to signed 16-bit representation.
    let a: i16 = rng.gen_range(-50..50);
    let b: i16 = rng.gen_range(-50..50);

    let ct_a = encode_encrypt(a, 16, &client_key);
    let ct_b = encode_encrypt(b, 16, &client_key);
    let mut ct_result: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); ct_a.len()];
    let mut result: Vec<bool> = vec![false; 16];

    println!("{a} - {b}");
    //server.ptxt_subtracter(&encode(a, 16), &encode(b, 16), &mut result);

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

    // Define two numbers and convert them to signed 16-bit representation.
    let a: i16 = rng.gen_range(-10..10);
    let b: i16 = rng.gen_range(-10..10);
    let enc_a = encode(a, 16);
    let enc_b = encode(b, 16);
    let mut res: Vec<bool> = vec![false; 16];

    let ct_a = encode_encrypt(a, 16, &client_key);
    let ct_b = encode_encrypt(b, 16, &client_key);
    let mut ct_result: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); ct_a.len()];

    //server.ptxt_multiplier(&enc_a, &enc_b, &mut res);
    println!("{a} * {b} = {}", decode(&res));
    println!("{:?} * {:?} = {:?}", enc_a, enc_b, res);

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

    // Define two numbers and convert them to signed 16-bit representation.
    let mut a: i16 = rng.gen_range(-50..50);
    let mut b: i16 = rng.gen_range(1..50);

    while !(a >= b) {
        a = rng.gen_range(-50..50);
        b = rng.gen_range(-50..50);
    }

    let ct_a = encode_encrypt(a, 16, &client_key);
    let ct_b = encode_encrypt(b, 16, &client_key);
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

    // Define two numbers and convert them to signed 16-bit representation.
    let mut a: i16 = rng.gen_range(-50..50);
    let mut b: i16 = rng.gen_range(-50..50);

    while !(a >= b) {
        a = rng.gen_range(-50..50);
        b = rng.gen_range(-50..50);
    }

    let ct_a = encode_encrypt(a, 16, &client_key);
    let ct_b = encode_encrypt(b, 16, &client_key);
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

    // Define two numbers and convert them to signed 16-bit representation.
    let a: [i16; 4] = [16, 10, 4, 0];
    let mut encrypted_values: Vec<Vec<Ciphertext>> = Vec::with_capacity(4);
    let mut ct_a: Vec<&[Ciphertext]> = Vec::with_capacity(4);
    for i in a.iter() {
        let encrypted = encode_encrypt(*i, 16, &client_key);
        encrypted_values.push(encrypted);
    }

    for encrypted in &encrypted_values {
        ct_a.push(encrypted.as_slice());
    }

    let mut ct_result: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); ct_a[0].len()];

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

    // Define two numbers and convert them to signed 16-bit representation.
    let a: [i16; 4] = [16, 10, 1, 0];
    let mut encrypted_values: Vec<Vec<Ciphertext>> = Vec::with_capacity(4);
    let mut ct_a: Vec<&[Ciphertext]> = Vec::with_capacity(4);
    for i in a.iter() {
        let encrypted = encode_encrypt(*i, 16, &client_key);
        encrypted_values.push(encrypted);
    }

    for encrypted in &encrypted_values {
        ct_a.push(encrypted.as_slice());
    }

    let mut ct_result: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); ct_a[0].len()];

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
    let mut rng = rand::thread_rng();

    // Define two numbers and convert them to signed 16-bit representation.
    let a: i16 = rng.gen_range(-100..0);
    let b: i16 = rng.gen_range(0..50);

    let ct_a = encode_encrypt(a, 16, &client_key);
    let ct_b = encode_encrypt(b, 16, &client_key);
    let mut ct_result_a: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); ct_a.len()];
    let mut ct_result_b: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); ct_b.len()];

    server.relu(&server_key, &ct_a, &mut ct_result_a);
    server.relu(&server_key, &ct_b, &mut ct_result_b);

    let dec_res = decrypt_decode(&ct_result_a, &client_key);
    println!("\t {} {} = {}", a, fn_name, dec_res);
    assert_eq!(dec_res, std::cmp::max(0, a));
    let dec_res = decrypt_decode(&ct_result_b, &client_key);
    println!("\t {} {} = {}", b, fn_name, dec_res);
    assert_eq!(dec_res, std::cmp::max(0, b));

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
    let a: i16 = 100;

    let ct_a = encode_encrypt(a, 16, &client_key);
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

    // Define two numbers and convert them to signed 16-bit representation.
    let a: [i16; 4] = [16, 10, 4, 2];
    let mut encrypted_values: Vec<Vec<Ciphertext>> = Vec::with_capacity(4);
    let mut ct_a: Vec<&[Ciphertext]> = Vec::with_capacity(4);
    for i in a.iter() {
        let encrypted = encode_encrypt(*i, 16, &client_key);
        encrypted_values.push(encrypted);
    }

    for encrypted in &encrypted_values {
        ct_a.push(encrypted.as_slice());
    }

    let mut ct_result: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); ct_a[0].len()];

    server.mean(&server_key, &ct_a, a.len(), &mut ct_result);

    let ptxt_result: i16 = a.iter().sum();

    let dec_res = decrypt_decode(&ct_result, &client_key);
    assert_eq!(dec_res, ptxt_result.wrapping_div(a.len() as i16));
    println!("[✓] PASS: {fn_name}\n");
}
#[test]
#[serial]
fn test_variance() {
    let fn_name = "variance";
    println!("[*] TEST: {fn_name}");
    let (client_key, server_key) = gen_keys();

    let server = ProcessorBoolean;

    // Define two numbers and convert them to signed 16-bit representation.
    let a: [i16; 4] = [1, 3, 4, 2];
    let mut encrypted_values: Vec<Vec<Ciphertext>> = Vec::with_capacity(4);
    let mut ct_a: Vec<&[Ciphertext]> = Vec::with_capacity(4);
    for i in a.iter() {
        let encrypted = encode_encrypt(*i, 16, &client_key);
        encrypted_values.push(encrypted);
    }

    for encrypted in &encrypted_values {
        ct_a.push(encrypted.as_slice());
    }

    let mut ct_result: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); ct_a[0].len()];

    server.variance(&server_key, &ct_a, a.len(), &mut ct_result);

    let ptxt_result: i16 = a.iter().sum();
    let mean:i16 = ptxt_result.wrapping_div(a.len() as i16);
    let variance:i16 = a
        .iter()
        .map(|x| (x - mean).wrapping_pow(2))
        .sum::<i16>()
        .wrapping_div(a.len() as i16);

    let dec_res = decrypt_decode(&ct_result, &client_key);
    assert_eq!(dec_res, variance);
    println!("[✓] PASS: {fn_name}\n");
}
#[test]
#[serial]
fn test_standard_deviation() {
    let fn_name = "standard_deviation";
    println!("[*] TEST: {fn_name}");
    let (client_key, server_key) = gen_keys();

    let server = ProcessorBoolean;

    // Define two numbers and convert them to signed 16-bit representation.
    let a: [i16; 4] = [1,2,3,4];
    let mut encrypted_values: Vec<Vec<Ciphertext>> = Vec::with_capacity(4);
    let mut ct_a: Vec<&[Ciphertext]> = Vec::with_capacity(4);
    for i in a.iter() {
        let encrypted = encode_encrypt(*i, 16, &client_key);
        encrypted_values.push(encrypted);
    }

    for encrypted in &encrypted_values {
        ct_a.push(encrypted.as_slice());
    }

    let mut ct_result: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); ct_a[0].len()];

    server.standard_deviation(&server_key, &ct_a, a.len(), &mut ct_result);

    let ptxt_result: i16 = a.iter().sum();
    let mean:i16 = ptxt_result.wrapping_div(a.len() as i16);
    let variance:i16 = a
        .iter()
        .map(|x| (x - mean).wrapping_pow(2))
        .sum::<i16>()
        .wrapping_div(a.len() as i16);

    let stdev:i16 = variance.isqrt();

    let dec_res = decrypt_decode(&ct_result, &client_key);
    assert_eq!(dec_res, stdev);
    println!("[✓] PASS: {fn_name}\n");
}
