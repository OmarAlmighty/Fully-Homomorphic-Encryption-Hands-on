use std::time::Instant;
use tfhe::boolean::gen_keys;
use tfhe::boolean::prelude::*;
use tfhe::boolean::server_key::RefreshMeEngine;

fn and_gate(sk: &ServerKey, b: &[Ciphertext], a: &[Ciphertext]) -> Vec<Ciphertext> {
    let mut res: Vec<Ciphertext> = Vec::new();

    for (bit_a, bit_b) in a.iter().zip(b.iter()) {
        let bit_res = sk.and(bit_b, bit_a);
        //let bit_res = sk.refresh_me(&bit_res);
        res.push(bit_res);
    }
    res
}

fn or_gate(sk: &ServerKey, b: &[Ciphertext], a: &[Ciphertext]) -> Vec<Ciphertext> {
    let mut res: Vec<Ciphertext> = Vec::new();

    for (bit_a, bit_b) in a.iter().zip(b.iter()) {
        let bit_res = sk.or(bit_b, bit_a);
        //let bit_res = sk.refresh_me(&bit_res);
        res.push(bit_res);
    }
    res
}

fn xor_gate(sk: &ServerKey, b: &[Ciphertext], a: &[Ciphertext]) -> Vec<Ciphertext> {
    let mut res: Vec<Ciphertext> = Vec::new();

    for (bit_a, bit_b) in a.iter().zip(b.iter()) {
        let bit_res = sk.xor(bit_b, bit_a);
        //let bit_res = sk.refresh_me(&bit_res);
        res.push(bit_res);
    }
    res
}

fn nand_gate(sk: &ServerKey, b: &[Ciphertext], a: &[Ciphertext]) -> Vec<Ciphertext> {
    let mut res: Vec<Ciphertext> = Vec::new();

    for (bit_a, bit_b) in a.iter().zip(b.iter()) {
        let bit_res = sk.nand(bit_b, bit_a);
        // let bit_res = sk.refresh_me(&bit_res);
        res.push(bit_res);
    }
    res
}

fn nor_gate(sk: &ServerKey, b: &[Ciphertext], a: &[Ciphertext]) -> Vec<Ciphertext> {
    let mut res: Vec<Ciphertext> = Vec::new();

    for (bit_a, bit_b) in a.iter().zip(b.iter()) {
        let bit_res = sk.nor(bit_b, bit_a);
        //let bit_res = sk.refresh_me(&bit_res);
        res.push(bit_res);
    }
    res
}

fn xnor_gate(sk: &ServerKey, b: &[Ciphertext], a: &[Ciphertext]) -> Vec<Ciphertext> {
    let mut res: Vec<Ciphertext> = Vec::new();

    for (bit_a, bit_b) in a.iter().zip(b.iter()) {
        let bit_res = sk.xnor(bit_b, bit_a);
        //let bit_res = sk.refresh_me(&bit_res);
        res.push(bit_res);
    }
    res
}
fn refresh_vec(sk: &ServerKey, c: &[Ciphertext]) -> Vec<Ciphertext> {
    let mut bootstrapped: Vec<Ciphertext> = Vec::new();

    for bit_c in c.iter() {
        let bit_res = sk.refresh_me(&bit_c);
        bootstrapped.push(bit_res);
    }
    
    bootstrapped
}
fn two_gates_test(
    gate1: &str,
    gate2: &str,
    a: &[Ciphertext],
    b: &[Ciphertext],
    c: &[Ciphertext],
    sk: &ServerKey,
    ptxt_a: &[bool],
    ptxt_b: &[bool],
    ptxt_c: &[bool],
    refresh: bool,
) -> (Vec<Ciphertext>, Vec<bool>) {
    let mut res: Vec<Ciphertext> = Vec::new();
    let mut solution: Vec<bool> = Vec::new();
    match (gate1, gate2) {
        ("and", "and") => {
            if refresh {
                let a_b = and_gate(&sk, &a, &b);
                let a_b_boots = refresh_vec(sk, &a_b);
                res = and_gate(sk, &a_b_boots, &c);
            } else {
                let a_b = and_gate(&sk, &a, &b);
                res = and_gate(sk, &a_b, &c);
            }
            for (bit_a, (bit_b, bit_c)) in ptxt_a.iter().zip(ptxt_b.iter().zip(ptxt_c.iter())) {
                solution.push((bit_a & bit_b) & bit_c);
            }
            (res, solution)
        }
        ("and", "or") => {
            if refresh {
                let a_b = and_gate(&sk, &a, &b);
                let a_b_boots = refresh_vec(sk, &a_b);
                res = or_gate(sk, &a_b_boots, &c);
            } else {
                let a_b = and_gate(&sk, &a, &b);
                res = or_gate(sk, &a_b, &c);
            }
            for (bit_a, (bit_b, bit_c)) in ptxt_a.iter().zip(ptxt_b.iter().zip(ptxt_c.iter())) {
                solution.push((bit_a & bit_b) | bit_c);
            }
            (res, solution)
        }
        ("and", "xor") => {
            if refresh {
                let a_b = and_gate(&sk, &a, &b);
                let a_b_boots = refresh_vec(sk, &a_b);
                res = xor_gate(sk, &a_b_boots, &c);
            } else {
                let a_b = and_gate(&sk, &a, &b);
                res = xor_gate(sk, &a_b, &c);
            }
            for (bit_a, (bit_b, bit_c)) in ptxt_a.iter().zip(ptxt_b.iter().zip(ptxt_c.iter())) {
                solution.push((bit_a & bit_b) ^ bit_c);
            }
            (res, solution)
        }
        ("and", "nand") => {
            if refresh {
                let a_b = and_gate(&sk, &a, &b);
                let a_b_boots = refresh_vec(sk, &a_b);
                res = nand_gate(sk, &a_b_boots, &c);
            } else {
                let a_b = and_gate(&sk, &a, &b);
                res = nand_gate(sk, &a_b, &c);
            }
            for (bit_a, (bit_b, bit_c)) in ptxt_a.iter().zip(ptxt_b.iter().zip(ptxt_c.iter())) {
                solution.push(!((bit_a & bit_b) & bit_c));
            }
            (res, solution)
        }
        ("and", "nor") => {
            if refresh {
                let a_b = and_gate(&sk, &a, &b);
                let a_b_boots = refresh_vec(sk, &a_b);
                res = nor_gate(sk, &a_b_boots, &c);
            } else {
                let a_b = and_gate(&sk, &a, &b);
                res = nor_gate(sk, &a_b, &c);
            }
            for (bit_a, (bit_b, bit_c)) in ptxt_a.iter().zip(ptxt_b.iter().zip(ptxt_c.iter())) {
                solution.push(!((bit_a & bit_b) | bit_c));
            }
            (res, solution)
        }
        ("and", "xnor") => {
            if refresh {
                let a_b = and_gate(&sk, &a, &b);
                let a_b_boots = refresh_vec(sk, &a_b);
                res = xnor_gate(sk, &a_b_boots, &c);
            } else {
                let a_b = and_gate(&sk, &a, &b);
                res = xnor_gate(sk, &a_b, &c);
            }
            for (bit_a, (bit_b, bit_c)) in ptxt_a.iter().zip(ptxt_b.iter().zip(ptxt_c.iter())) {
                solution.push(!((bit_a & bit_b) ^ bit_c));
            }
            (res, solution)
        }

        ("or", "and") => {
            if refresh {
                let a_b = or_gate(&sk, &a, &b);
                let a_b_boots = refresh_vec(sk, &a_b);
                res = and_gate(sk, &a_b_boots, &c);
            } else {
                let a_b = or_gate(&sk, &a, &b);
                res = and_gate(sk, &a_b, &c);
            }
            for (bit_a, (bit_b, bit_c)) in ptxt_a.iter().zip(ptxt_b.iter().zip(ptxt_c.iter())) {
                solution.push((bit_a | bit_b) & bit_c);
            }
            (res, solution)
        }
        ("or", "or") => {
            if refresh {
                let a_b = or_gate(&sk, &a, &b);
                let a_b_boots = refresh_vec(sk, &a_b);
                res = or_gate(sk, &a_b_boots, &c);
            } else {
                let a_b = or_gate(&sk, &a, &b);
                res = or_gate(sk, &a_b, &c);
            }
            for (bit_a, (bit_b, bit_c)) in ptxt_a.iter().zip(ptxt_b.iter().zip(ptxt_c.iter())) {
                solution.push((bit_a | bit_b) | bit_c);
            }
            (res, solution)
        }
        ("or", "xor") => {
            if refresh {
                let a_b = or_gate(&sk, &a, &b);
                let a_b_boots = refresh_vec(sk, &a_b);
                res = xor_gate(sk, &a_b_boots, &c);
            } else {
                let a_b = or_gate(&sk, &a, &b);
                res = xor_gate(sk, &a_b, &c);
            }
            for (bit_a, (bit_b, bit_c)) in ptxt_a.iter().zip(ptxt_b.iter().zip(ptxt_c.iter())) {
                solution.push((bit_a | bit_b) ^ bit_c);
            }
            (res, solution)
        }
        ("or", "nand") => {
            if refresh {
                let a_b = or_gate(&sk, &a, &b);
                let a_b_boots = refresh_vec(sk, &a_b);
                res = nand_gate(sk, &a_b_boots, &c);
            } else {
                let a_b = or_gate(&sk, &a, &b);
                res = nand_gate(sk, &a_b, &c);
            }
            for (bit_a, (bit_b, bit_c)) in ptxt_a.iter().zip(ptxt_b.iter().zip(ptxt_c.iter())) {
                solution.push(!((bit_a | bit_b) & bit_c));
            }
            (res, solution)
        }
        ("or", "nor") => {
            if refresh {
                let a_b = or_gate(&sk, &a, &b);
                let a_b_boots = refresh_vec(sk, &a_b);
                res = nor_gate(sk, &a_b_boots, &c);
            } else {
                let a_b = or_gate(&sk, &a, &b);
                res = nor_gate(sk, &a_b, &c);
            }
            for (bit_a, (bit_b, bit_c)) in ptxt_a.iter().zip(ptxt_b.iter().zip(ptxt_c.iter())) {
                solution.push(!((bit_a | bit_b) | bit_c));
            }
            (res, solution)
        }
        ("or", "xnor") => {
            if refresh {
                let a_b = or_gate(&sk, &a, &b);
                let a_b_boots = refresh_vec(sk, &a_b);
                res = xnor_gate(sk, &a_b_boots, &c);
            } else {
                let a_b = or_gate(&sk, &a, &b);
                res = xnor_gate(sk, &a_b, &c);
            }
            for (bit_a, (bit_b, bit_c)) in ptxt_a.iter().zip(ptxt_b.iter().zip(ptxt_c.iter())) {
                solution.push(!((bit_a | bit_b) ^ bit_c));
            }
            (res, solution)
        }

        ("xor", "and") => {
            if refresh {
                let a_b = xor_gate(&sk, &a, &b);
                let a_b_boots = refresh_vec(sk, &a_b);
                res = and_gate(sk, &a_b_boots, &c);
            } else {
                let a_b = xor_gate(&sk, &a, &b);
                res = and_gate(sk, &a_b, &c);
            }
            for (bit_a, (bit_b, bit_c)) in ptxt_a.iter().zip(ptxt_b.iter().zip(ptxt_c.iter())) {
                solution.push((bit_a ^ bit_b) & bit_c);
            }
            (res, solution)
        }
        ("xor", "or") => {
            if refresh {
                let a_b = xor_gate(&sk, &a, &b);
                let a_b_boots = refresh_vec(sk, &a_b);
                res = or_gate(sk, &a_b_boots, &c);
            } else {
                let a_b = xor_gate(&sk, &a, &b);
                res = or_gate(sk, &a_b, &c);
            }
            for (bit_a, (bit_b, bit_c)) in ptxt_a.iter().zip(ptxt_b.iter().zip(ptxt_c.iter())) {
                solution.push((bit_a ^ bit_b) | bit_c);
            }
            (res, solution)
        }
        ("xor", "xor") => {
            if refresh {
                let a_b = xor_gate(&sk, &a, &b);
                let a_b_boots = refresh_vec(sk, &a_b);
                res = xor_gate(sk, &a_b_boots, &c);
            } else {
                let a_b = xor_gate(&sk, &a, &b);
                res = xor_gate(sk, &a_b, &c);
            }
            for (bit_a, (bit_b, bit_c)) in ptxt_a.iter().zip(ptxt_b.iter().zip(ptxt_c.iter())) {
                solution.push((bit_a ^ bit_b) ^ bit_c);
            }
            (res, solution)
        }
        ("xor", "nand") => {
            if refresh {
                let a_b = xor_gate(&sk, &a, &b);
                let a_b_boots = refresh_vec(sk, &a_b);
                res = nand_gate(sk, &a_b_boots, &c);
            } else {
                let a_b = xor_gate(&sk, &a, &b);
                res = nand_gate(sk, &a_b, &c);
            }
            for (bit_a, (bit_b, bit_c)) in ptxt_a.iter().zip(ptxt_b.iter().zip(ptxt_c.iter())) {
                solution.push(!((bit_a ^ bit_b) & bit_c));
            }
            (res, solution)
        }
        ("xor", "nor") => {
            if refresh {
                let a_b = xor_gate(&sk, &a, &b);
                let a_b_boots = refresh_vec(sk, &a_b);
                res = nor_gate(sk, &a_b_boots, &c);
            } else {
                let a_b = xor_gate(&sk, &a, &b);
                res = nor_gate(sk, &a_b, &c);
            }
            for (bit_a, (bit_b, bit_c)) in ptxt_a.iter().zip(ptxt_b.iter().zip(ptxt_c.iter())) {
                solution.push(!((bit_a ^ bit_b) | bit_c));
            }
            (res, solution)
        }
        ("xor", "xnor") => {
            if refresh {
                let a_b = xor_gate(&sk, &a, &b);
                let a_b_boots = refresh_vec(sk, &a_b);
                res = xnor_gate(sk, &a_b_boots, &c);
            } else {
                let a_b = xor_gate(&sk, &a, &b);
                res = xnor_gate(sk, &a_b, &c);
            }
            for (bit_a, (bit_b, bit_c)) in ptxt_a.iter().zip(ptxt_b.iter().zip(ptxt_c.iter())) {
                solution.push(!((bit_a ^ bit_b) ^ bit_c));
            }
            (res, solution)
        }

        ("nand", "and") => {
            if refresh {
                let a_b = nand_gate(&sk, &a, &b);
                let a_b_boots = refresh_vec(sk, &a_b);
                res = and_gate(sk, &a_b_boots, &c);
            } else {
                let a_b = nand_gate(&sk, &a, &b);
                res = and_gate(sk, &a_b, &c);
            }
            for (bit_a, (bit_b, bit_c)) in ptxt_a.iter().zip(ptxt_b.iter().zip(ptxt_c.iter())) {
                solution.push((!(bit_a & bit_b)) & bit_c);
            }
            (res, solution)
        }
        ("nand", "or") => {
            if refresh {
                let a_b = nand_gate(&sk, &a, &b);
                let a_b_boots = refresh_vec(sk, &a_b);
                res = or_gate(sk, &a_b_boots, &c);
            } else {
                let a_b = nand_gate(&sk, &a, &b);
                res = or_gate(sk, &a_b, &c);
            }
            for (bit_a, (bit_b, bit_c)) in ptxt_a.iter().zip(ptxt_b.iter().zip(ptxt_c.iter())) {
                solution.push((!(bit_a & bit_b)) | bit_c);
            }
            (res, solution)
        }
        ("nand", "xor") => {
            if refresh {
                let a_b = nand_gate(&sk, &a, &b);
                let a_b_boots = refresh_vec(sk, &a_b);
                res = xor_gate(sk, &a_b_boots, &c);
            } else {
                let a_b = nand_gate(&sk, &a, &b);
                res = xor_gate(sk, &a_b, &c);
            }
            for (bit_a, (bit_b, bit_c)) in ptxt_a.iter().zip(ptxt_b.iter().zip(ptxt_c.iter())) {
                solution.push((!(bit_a & bit_b)) ^ bit_c);
            }
            (res, solution)
        }
        ("nand", "nand") => {
            if refresh {
                let a_b = nand_gate(&sk, &a, &b);
                let a_b_boots = refresh_vec(sk, &a_b);
                res = nand_gate(sk, &a_b_boots, &c);
            } else {
                let a_b = nand_gate(&sk, &a, &b);
                res = nand_gate(sk, &a_b, &c);
            }
            for (bit_a, (bit_b, bit_c)) in ptxt_a.iter().zip(ptxt_b.iter().zip(ptxt_c.iter())) {
                solution.push(!((!(bit_a & bit_b)) & bit_c));
            }
            (res, solution)
        }
        ("nand", "nor") => {
            if refresh {
                let a_b = nand_gate(&sk, &a, &b);
                let a_b_boots = refresh_vec(sk, &a_b);
                res = nor_gate(sk, &a_b_boots, &c);
            } else {
                let a_b = nand_gate(&sk, &a, &b);
                res = nor_gate(sk, &a_b, &c);
            }
            for (bit_a, (bit_b, bit_c)) in ptxt_a.iter().zip(ptxt_b.iter().zip(ptxt_c.iter())) {
                solution.push(!((!(bit_a & bit_b)) | bit_c));
            }
            (res, solution)
        }
        ("nand", "xnor") => {
            if refresh {
                let a_b = nand_gate(&sk, &a, &b);
                let a_b_boots = refresh_vec(sk, &a_b);
                res = xnor_gate(sk, &a_b_boots, &c);
            } else {
                let a_b = nand_gate(&sk, &a, &b);
                res = xnor_gate(sk, &a_b, &c);
            }
            for (bit_a, (bit_b, bit_c)) in ptxt_a.iter().zip(ptxt_b.iter().zip(ptxt_c.iter())) {
                solution.push(!((!(bit_a & bit_b)) ^ bit_c));
            }
            (res, solution)
        }

        ("nor", "and") => {
            if refresh {
                let a_b = nor_gate(&sk, &a, &b);
                let a_b_boots = refresh_vec(sk, &a_b);
                res = and_gate(sk, &a_b_boots, &c);
            } else {
                let a_b = nor_gate(&sk, &a, &b);
                res = and_gate(sk, &a_b, &c);
            }
            for (bit_a, (bit_b, bit_c)) in ptxt_a.iter().zip(ptxt_b.iter().zip(ptxt_c.iter())) {
                solution.push((!(bit_a | bit_b)) & bit_c);
            }
            (res, solution)
        }
        ("nor", "or") => {
            if refresh {
                let a_b = nor_gate(&sk, &a, &b);
                let a_b_boots = refresh_vec(sk, &a_b);
                res = or_gate(sk, &a_b_boots, &c);
            } else {
                let a_b = nor_gate(&sk, &a, &b);
                res = or_gate(sk, &a_b, &c);
            }
            for (bit_a, (bit_b, bit_c)) in ptxt_a.iter().zip(ptxt_b.iter().zip(ptxt_c.iter())) {
                solution.push((!(bit_a | bit_b)) | bit_c);
            }
            (res, solution)
        }
        ("nor", "xor") => {
            if refresh {
                let a_b = nor_gate(&sk, &a, &b);
                let a_b_boots = refresh_vec(sk, &a_b);
                res = xor_gate(sk, &a_b_boots, &c);
            } else {
                let a_b = nor_gate(&sk, &a, &b);
                res = xor_gate(sk, &a_b, &c);
            }
            for (bit_a, (bit_b, bit_c)) in ptxt_a.iter().zip(ptxt_b.iter().zip(ptxt_c.iter())) {
                solution.push((!(bit_a | bit_b)) ^ bit_c);
            }
            (res, solution)
        }
        ("nor", "nand") => {
            if refresh {
                let a_b = nor_gate(&sk, &a, &b);
                let a_b_boots = refresh_vec(sk, &a_b);
                res = nand_gate(sk, &a_b_boots, &c);
            } else {
                let a_b = nor_gate(&sk, &a, &b);
                res = nand_gate(sk, &a_b, &c);
            }
            for (bit_a, (bit_b, bit_c)) in ptxt_a.iter().zip(ptxt_b.iter().zip(ptxt_c.iter())) {
                solution.push(!((!(bit_a | bit_b)) & bit_c));
            }
            (res, solution)
        }
        ("nor", "nor") => {
            if refresh {
                let a_b = nor_gate(&sk, &a, &b);
                let a_b_boots = refresh_vec(sk, &a_b);
                res = nor_gate(sk, &a_b_boots, &c);
            } else {
                let a_b = nor_gate(&sk, &a, &b);
                res = nor_gate(sk, &a_b, &c);
            }
            for (bit_a, (bit_b, bit_c)) in ptxt_a.iter().zip(ptxt_b.iter().zip(ptxt_c.iter())) {
                solution.push(!((!(bit_a | bit_b)) | bit_c));
            }
            (res, solution)
        }
        ("nor", "xnor") => {
            if refresh {
                let a_b = nor_gate(&sk, &a, &b);
                let a_b_boots = refresh_vec(sk, &a_b);
                res = xnor_gate(sk, &a_b_boots, &c);
            } else {
                let a_b = nor_gate(&sk, &a, &b);
                res = xnor_gate(sk, &a_b, &c);
            }
            for (bit_a, (bit_b, bit_c)) in ptxt_a.iter().zip(ptxt_b.iter().zip(ptxt_c.iter())) {
                solution.push(!((!(bit_a | bit_b)) ^ bit_c));
            }
            (res, solution)
        }

        ("xnor", "and") => {
            if refresh {
                let a_b = xnor_gate(&sk, &a, &b);
                let a_b_boots = refresh_vec(sk, &a_b);
                res = and_gate(sk, &a_b_boots, &c);
            } else {
                let a_b = xnor_gate(&sk, &a, &b);
                res = and_gate(sk, &a_b, &c);
            }
            for (bit_a, (bit_b, bit_c)) in ptxt_a.iter().zip(ptxt_b.iter().zip(ptxt_c.iter())) {
                solution.push((!(bit_a ^ bit_b)) & bit_c);
            }
            (res, solution)
        }
        ("xnor", "or") => {
            if refresh {
                let a_b = xnor_gate(&sk, &a, &b);
                let a_b_boots = refresh_vec(sk, &a_b);
                res = or_gate(sk, &a_b_boots, &c);
            } else {
                let a_b = xnor_gate(&sk, &a, &b);
                res = or_gate(sk, &a_b, &c);
            }
            for (bit_a, (bit_b, bit_c)) in ptxt_a.iter().zip(ptxt_b.iter().zip(ptxt_c.iter())) {
                solution.push((!(bit_a ^ bit_b)) | bit_c);
            }
            (res, solution)
        }
        ("xnor", "xor") => {
            if refresh {
                let a_b = xnor_gate(&sk, &a, &b);
                let a_b_boots = refresh_vec(sk, &a_b);
                res = xor_gate(sk, &a_b_boots, &c);
            } else {
                let a_b = xnor_gate(&sk, &a, &b);
                res = xor_gate(sk, &a_b, &c);
            }
            for (bit_a, (bit_b, bit_c)) in ptxt_a.iter().zip(ptxt_b.iter().zip(ptxt_c.iter())) {
                solution.push((!(bit_a ^ bit_b)) ^ bit_c);
            }
            (res, solution)
        }
        ("xnor", "nand") => {
            if refresh {
                let a_b = xnor_gate(&sk, &a, &b);
                let a_b_boots = refresh_vec(sk, &a_b);
                res = nand_gate(sk, &a_b_boots, &c);
            } else {
                let a_b = xnor_gate(&sk, &a, &b);
                res = nand_gate(sk, &a_b, &c);
            }
            for (bit_a, (bit_b, bit_c)) in ptxt_a.iter().zip(ptxt_b.iter().zip(ptxt_c.iter())) {
                solution.push(!((!(bit_a ^ bit_b)) & bit_c));
            }
            (res, solution)
        }
        ("xnor", "nor") => {
            if refresh {
                let a_b = xnor_gate(&sk, &a, &b);
                let a_b_boots = refresh_vec(sk, &a_b);
                res = nor_gate(sk, &a_b_boots, &c);
            } else {
                let a_b = xnor_gate(&sk, &a, &b);
                res = nor_gate(sk, &a_b, &c);
            }
            for (bit_a, (bit_b, bit_c)) in ptxt_a.iter().zip(ptxt_b.iter().zip(ptxt_c.iter())) {
                solution.push(!((!(bit_a ^ bit_b)) | bit_c));
            }
            (res, solution)
        }
        ("xnor", "xnor") => {
            if refresh {
                let a_b = xnor_gate(&sk, &a, &b);
                let a_b_boots = refresh_vec(sk, &a_b);
                res = xnor_gate(sk, &a_b_boots, &c);
            } else {
                let a_b = xnor_gate(&sk, &a, &b);
                res = xnor_gate(sk, &a_b, &c);
            }
            for (bit_a, (bit_b, bit_c)) in ptxt_a.iter().zip(ptxt_b.iter().zip(ptxt_c.iter())) {
                solution.push(!((!(bit_a ^ bit_b)) ^ bit_c));
            }
            (res, solution)
        }

        (_, _) => {
            println!("Unknown gates");
            (res, solution)
        }
    }
}



fn main() {
    // We generate a set of client/server keys, using the default parameters:
    let (client_key, server_key) = gen_keys();

    let a_bits = [
        true, true, false, true, true, true, false,
        false,
        //true, true, false, false, true, true, true, false,
        // true, true, false, false, true, true, true, false,
        // true, true, false, false, true, true, true, false,
    ];
    let b_bits = [
        false, true, false, true, false, false, false,
        true,
        //true, false, true, false, true, true, true, false,
        // true, false, true, false, true, true, true, false,
        // true, false, true, false, true, true, true, false,
    ];

    let c_bits = [false; 8];

    let ct_a: Vec<_> = a_bits.iter().map(|&bit| client_key.encrypt(bit)).collect();

    let ct_b: Vec<_> = b_bits.iter().map(|&bit| client_key.encrypt(bit)).collect();

    let ct_c: Vec<_> = c_bits.iter().map(|&bit| client_key.encrypt(bit)).collect();
    
    
    let gates1 = ["and", "or", "xor", "nand", "nor", "xnor"];
    let gates2 = ["and", "or", "xor", "nand", "nor", "xnor"];
    for g1 in gates1 {
        for g2 in gates2 {
            let start = Instant::now();
            let (result, solution) = two_gates_test(
                g1,
                g2,
                &ct_a,
                &ct_b,
                &ct_c,
                &server_key,
                &a_bits,
                &b_bits,
                &c_bits,
                false,
            );
            let elapsed = start.elapsed();
    
            // Decrypt result
            let decrypted: Vec<_> = result.iter().map(|bit| client_key.decrypt(bit)).collect();
    
            let mut correct = "";
            if decrypted == solution {
                correct = "OK";
            } else {
                correct = "FAILED";
            }
            println!("* {g1}; {g2} --> {correct}");
    
            println!("\t* Decrypted result: {:?}", decrypted);
            println!("\t* Solution        : {:?}", solution);
            println!("");
        }
    }
}
