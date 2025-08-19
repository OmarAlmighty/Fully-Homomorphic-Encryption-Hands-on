mod main;

use std::time::Instant;
use tfhe::shortint::gen_keys;
use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;

pub fn main() {
    // Generate the client key and the server key:
    let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);

    // Encrypt values and add them
    let ct1 = cks.encrypt(1);
    let ct2 = cks.encrypt(1);

    let start = Instant::now();

    let res = sks.unchecked_mul_lsb(&ct1, &ct2);
    let res = sks.unchecked_add(&res, &ct1);
    let res = sks.unchecked_add(&res, &ct1);
    let res = sks.unchecked_mul_lsb(&res, &ct2);
    let res = sks.unchecked_mul_lsb(&res, &ct2);
    let res = sks.unchecked_mul_lsb(&res, &ct2);
    let res = sks.unchecked_mul_lsb(&res, &ct2);
    let res = sks.unchecked_mul_lsb(&res, &ct2);
    let res = sks.unchecked_mul_lsb(&res, &ct2);
    let res = sks.unchecked_mul_lsb(&res, &ct2);
    let res = sks.unchecked_mul_lsb(&res, &ct2);



    // println!("noise level before BS: {:?}", res.noise_level());
    //
    // // Manually bootstrap the result
    // let lut = sks.generate_lookup_table(|x| x);
    // let bootstrapped = sks.apply_lookup_table(&res, &lut);
    //
    // println!("noise level after BS: {:?}", bootstrapped.noise_level());

    let elapsed = start.elapsed();

    // Decrypt
    let dec = cks.decrypt(&res);
    println!("dec: {:?} --> (time {:?}) ", dec, elapsed);
}