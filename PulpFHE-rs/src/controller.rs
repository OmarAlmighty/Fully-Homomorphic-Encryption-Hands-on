use crate::register_table::{RegisterElement, RegisterTable, Subscriber};
use crate::reservation_stations::*;
use tfhe::boolean::prelude::*;

fn adder(sk: &ServerKey, a: &[Ciphertext], b: &[Ciphertext], result: &mut [Ciphertext]) {
    let mut a_reg = RegisterElement::new("a".to_string(), "-".to_string(), Option::from(a.to_vec()), None,false, 1);
    let mut b_reg = RegisterElement::new("b".to_string(), "-".to_string(), Option::from(b.to_vec()), None,false, 1);
    let mut result_reg = RegisterElement::new(
        "result".to_string(),
        "0".to_string(),
        Option::from(result.to_vec()),
        None,
        true,
        1,
    );
    let size = a.len();

    let mut register_tbl = RegisterTable::new();
    // Initialize temporary vectors
    let mut carry: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); size + 1]; // Includes carry-out
    let mut carry_reg = RegisterElement::new("carry".to_string(), "0".to_string(), carry, false, 1);

    let mut temp: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); size];
    let mut temp_reg = RegisterElement::new("temp".to_string(), "0".to_string(), temp, false, 1);

    let mut a_and_b: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); size];
    let mut a_and_b_reg =
        RegisterElement::new("a_and_b".to_string(), "0".to_string(), a_and_b, false, 1);

    // Compute a XOR b for all bits
    //e_xor(sk, a, b, &mut temp);
    let ret_a = register_tbl.get_element_dst("a".to_string());

    let ret_b = register_tbl.get_element_dst("b".to_string());

    let mut xor_rs = XOR_rs::new();

    // If the waiting_for of retrieved a and b are -, then the values can be directly used
    if ret_a.unwrap().waiting_for == "-" && ret_b.unwrap().waiting_for == "-" {
        let val1 = ret_a.unwrap().vec_ctxt.clone();
        let val2 = ret_b.unwrap().vec_ctxt.clone();
        xor_rs.add_entry(
            "AND_1".to_string(),
            "-".to_string(),
            "-".to_string(),
            Option::from(val1),
            Option::from(val2),
            "temp".to_string(),
        )
    } else if ret_a.unwrap().waiting_for == "-" && ret_b.unwrap().waiting_for != "-" {
        let val1 = ret_a.unwrap().vec_ctxt.clone();
        xor_rs.add_entry(
            "AND_1".to_string(),
            "-".to_string(),
            ret_b.unwrap().dst.clone(),
            Option::from(val1),
            None,
            "temp".to_string(),
        )
    } else if ret_a.unwrap().waiting_for != "-" && ret_b.unwrap().waiting_for == "-" {
        let val2 = ret_b.unwrap().vec_ctxt.clone();
        xor_rs.add_entry(
            "AND_1".to_string(),
            ret_a.unwrap().dst.clone(),
            "-".to_string(),
            None,
            Option::from(val2),
            "temp".to_string(),
        )
    } else if ret_a.unwrap().waiting_for != "-" && ret_b.unwrap().waiting_for != "-" {
        xor_rs.add_entry(
            "AND_1".to_string(),
            ret_a.unwrap().dst.clone(),
            ret_b.unwrap().dst.clone(),
            None,
            None,
            "temp".to_string(),
        )
    } else {
        panic!("Error in adder");
    }


    //e_and(sk, a, b, &mut a_and_b);
    let mut and_rs = AND_rs::new();

    // If the waiting_for of retrieved a and b are -, then the values can be directly used
    if ret_a.unwrap().waiting_for == "-" && ret_b.unwrap().waiting_for == "-" {
        let val1 = ret_a.unwrap().vec_ctxt.clone();
        let val2 = ret_b.unwrap().vec_ctxt.clone();
        and_rs.add_entry(
            "AND_1".to_string(),
            "-".to_string(),
            "-".to_string(),
            Option::from(val1),
            Option::from(val2),
            "temp".to_string(),
        )
        /*Run the AND gate*/
    } else if ret_a.unwrap().waiting_for == "-" && ret_b.unwrap().waiting_for != "-" {
        let val1 = ret_a.unwrap().vec_ctxt.clone();
        and_rs.add_entry(
            "AND_1".to_string(),
            "-".to_string(),
            ret_b.unwrap().dst.clone(),
            Option::from(val1),
            None,
            "temp".to_string(),
        )
    } else if ret_a.unwrap().waiting_for != "-" && ret_b.unwrap().waiting_for == "-" {
        let val2 = ret_b.unwrap().vec_ctxt.clone();
        and_rs.add_entry(
            "AND_1".to_string(),
            ret_a.unwrap().dst.clone(),
            "-".to_string(),
            None,
            Option::from(val2),
            "temp".to_string(),
        )
    } else if ret_a.unwrap().waiting_for != "-" && ret_b.unwrap().waiting_for != "-" {
        and_rs.add_entry(
            "AND_1".to_string(),
            ret_a.unwrap().dst.clone(),
            ret_b.unwrap().dst.clone(),
            None,
            None,
            "temp".to_string(),
        )
    } else {
        panic!("Error in adder");
    }


    // Ripple-carry adder logic
    for i in 0..size {
        // Sum bit: result[i] = a[i] XOR b[i] XOR carry[i]
        result[i] = e_xor_bit(sk, &carry[i], &temp[i]);

        if i != size - 1 {
            // Carry bit: carry[i+1] = (a[i] AND b[i]) OR (a[i] AND carry[i]) OR (b[i] AND carry[i])
            let a_and_carry = e_and_bit(sk, &a[i], &carry[i]);
            let b_and_carry = e_and_bit(sk, &b[i], &carry[i]);
            let temp_carry = e_or_bit(sk, &a_and_b[i], &a_and_carry);
            carry[i + 1] = e_or_bit(sk, &temp_carry, &b_and_carry);
        }
    }
}
