use crate::processor_boolean::*;
use crate::processor_circuits::*;
use crate::processor_gates::*;
use crate::register_table::{RegisterElement, RegisterTable, Subscriber};
use crate::reservation_stations::*;
use tfhe::boolean::prelude::*;
#[cfg(test)]
mod test_controller_8;
pub struct Controller {
    and_rs: AndRs,
    or_rs: OrRs,
    xor_rs: XorRs,
    nand_rs: NandRs,
    nor_rs: NorRs,
    xnor_rs: XnorRs,
    register_tbl: RegisterTable,
    sk: ServerKey,
    processor: ProcessorBoolean,
}

impl Controller {
    pub fn new(sk: ServerKey) -> Self {
        Controller {
            and_rs: AndRs::new(),
            or_rs: OrRs::new(),
            xor_rs: XorRs::new(),
            nand_rs: NandRs::new(),
            nor_rs: NorRs::new(),
            xnor_rs: XnorRs::new(),
            register_tbl: RegisterTable::new(),
            sk: sk,
            processor: ProcessorBoolean::new(),
        }
    }

    pub fn get_and_rs(&self) -> &AndRs {
        &self.and_rs
    }

    pub fn get_or_rs(&self) -> &OrRs {
        &self.or_rs
    }

    pub fn get_xor_rs(&self) -> &XorRs {
        &self.xor_rs
    }

    pub fn get_nand_rs(&self) -> &NandRs {
        &self.nand_rs
    }

    pub fn get_nor_rs(&self) -> &NorRs {
        &self.nor_rs
    }

    pub fn get_xnor_rs(&self) -> &XnorRs {
        &self.xnor_rs
    }

    pub fn get_register_tbl(&self) -> &RegisterTable {
        &self.register_tbl
    }

    pub fn get_sk(&self) -> &ServerKey {
        &self.sk
    }

    fn add_to_reservation_station(
        &mut self,
        name: &str,
        id: &str,
        op1: &str,
        op2: &str,
        dst: &str,
        result_start_indx: i8,
        op1_start_indx: i8,
        op2_start_indx: i8,
        end_indx: i8,
    ) {
        let ret_a = self.register_tbl.get_element_dst(op1.to_string());

        let ret_b = self.register_tbl.get_element_dst(op2.to_string());
        match name {
            "AndRs" => {
                // If the waiting_for of retrieved a and b are -, then the values can be directly used
                if ret_a.unwrap().waiting_for == "-" && ret_b.unwrap().waiting_for == "-" {
                    let val1 = ret_a.unwrap().vec_ctxt.clone().unwrap();
                    let val2 = ret_b.unwrap().vec_ctxt.clone().unwrap();
                    let mut result: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); val1.len()];

                    // Perform AND operation
                    if result_start_indx == -1 {
                        self.processor.e_and(&self.sk, &val1, &val2, &mut result);

                        // Move to the Register table
                        //  1. Does it exist in the register table?
                        //   2. If yes, then update the entry
                        //   3. If no, then add a new entry
                        let rt_entry = self.register_tbl.get_element_dst(dst.to_string());
                        let updated = RegisterElement::new(
                            dst.to_string(),
                            "-".to_string(),
                            Option::from(result),
                            -1,
                            1,
                        );
                        match rt_entry {
                            Some(_value) => {
                                self.register_tbl.update_element_dst(updated);
                            }
                            None => {
                                self.register_tbl.add_element(updated);
                            }
                        }
                    } else if result_start_indx == op1_start_indx
                        && result_start_indx == op2_start_indx
                        && result_start_indx < end_indx
                    {
                        self.processor.e_and_range(
                            &self.sk,
                            &val1,
                            &val2,
                            &mut result,
                            result_start_indx as usize,
                            end_indx as usize,
                        );

                        // Move to the Register table
                        //  1. Does it exist in the register table?
                        //   2. If yes, then update the entry
                        //   3. If no, then add a new entry
                        let rt_entry = self.register_tbl.get_element_dst(dst.to_string());
                        let mut temp = rt_entry.unwrap().vec_ctxt.clone().unwrap();
                        for i in 0..result_start_indx + 1 {
                            result[i as usize] = temp[i as usize].clone();
                        }
                        for i in end_indx as usize..temp.len() {
                            result[i] = temp[i].clone();
                        }
                        let updated = RegisterElement::new(
                            dst.to_string(),
                            "-".to_string(),
                            Option::from(result),
                            -1,
                            1,
                        );
                        match rt_entry {
                            Some(_value) => {
                                self.register_tbl.update_element_dst(updated);
                            }
                            None => {
                                self.register_tbl.add_element(updated);
                            }
                        }
                    } else {
                        result[result_start_indx as usize] = self.processor.e_and_bit(
                            &self.sk,
                            &val1[op1_start_indx as usize],
                            &val2[op1_start_indx as usize],
                        );
                        let rt_entry = self.register_tbl.get_element_dst(dst.to_string());
                        match rt_entry {
                            Some(_value) => {
                                let mut temp = rt_entry.unwrap().vec_ctxt.clone().unwrap();
                                temp[result_start_indx as usize] =
                                    result[result_start_indx as usize].clone();
                                result = temp.clone();
                                let updated = RegisterElement::new(
                                    dst.to_string(),
                                    "-".to_string(),
                                    Option::from(result),
                                    -1,
                                    1,
                                );
                                self.register_tbl.update_element_dst(updated);
                            }
                            None => {
                                let updated = RegisterElement::new(
                                    dst.to_string(),
                                    "-".to_string(),
                                    Option::from(result),
                                    -1,
                                    1,
                                );
                                self.register_tbl.add_element(updated);
                            }
                        }
                    }
                } else if ret_a.unwrap().waiting_for == "-" && ret_b.unwrap().waiting_for != "-" {
                    let val1 = ret_a.unwrap().vec_ctxt.clone();
                    self.and_rs.add_entry(
                        id.to_string(),
                        "-".to_string(),
                        ret_b.unwrap().dst.clone(),
                        Option::from(val1),
                        None,
                        dst.to_string(),
                    )
                } else if ret_a.unwrap().waiting_for != "-" && ret_b.unwrap().waiting_for == "-" {
                    let val2 = ret_b.unwrap().vec_ctxt.clone();
                    self.and_rs.add_entry(
                        id.to_string(),
                        ret_a.unwrap().dst.clone(),
                        "-".to_string(),
                        None,
                        Option::from(val2),
                        dst.to_string(),
                    )
                } else if ret_a.unwrap().waiting_for != "-" && ret_b.unwrap().waiting_for != "-" {
                    self.and_rs.add_entry(
                        id.to_string(),
                        ret_a.unwrap().dst.clone(),
                        ret_b.unwrap().dst.clone(),
                        None,
                        None,
                        dst.to_string(),
                    )
                } else {
                    panic!("Error in adding an entry to AndRs");
                }
            }
            "OrRs" => {
                // If the waiting_for of retrieved a and b are -, then the values can be directly used
                if ret_a.unwrap().waiting_for == "-" && ret_b.unwrap().waiting_for == "-" {
                    let val1 = ret_a.unwrap().vec_ctxt.clone().unwrap();
                    let val2 = ret_b.unwrap().vec_ctxt.clone().unwrap();
                    let mut result: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); val1.len()];
                    // Perform or operation
                    if result_start_indx == -1 {
                        self.processor.e_or(&self.sk, &val1, &val2, &mut result);

                        // Move to the Register table
                        //  1. Does it exist in the register table?
                        //   2. If yes, then update the entry
                        //   3. If no, then add a new entry
                        let rt_entry = self.register_tbl.get_element_dst(dst.to_string());
                        let updated = RegisterElement::new(
                            dst.to_string(),
                            "-".to_string(),
                            Option::from(result),
                            -1,
                            1,
                        );
                        match rt_entry {
                            Some(_value) => {
                                self.register_tbl.update_element_dst(updated);
                            }
                            None => {
                                self.register_tbl.add_element(updated);
                            }
                        }
                    } else if result_start_indx == op1_start_indx
                        && result_start_indx == op2_start_indx
                        && result_start_indx < end_indx
                    {
                        self.processor.e_or_range(
                            &self.sk,
                            &val1,
                            &val2,
                            &mut result,
                            result_start_indx as usize,
                            end_indx as usize,
                        );

                        // Move to the Register table
                        //  1. Does it exist in the register table?
                        //   2. If yes, then update the entry
                        //   3. If no, then add a new entry
                        let rt_entry = self.register_tbl.get_element_dst(dst.to_string());
                        let mut temp = rt_entry.unwrap().vec_ctxt.clone().unwrap();
                        for i in 0..result_start_indx + 1 {
                            result[i as usize] = temp[i as usize].clone();
                        }
                        for i in end_indx as usize..temp.len() {
                            result[i] = temp[i].clone();
                        }
                        let updated = RegisterElement::new(
                            dst.to_string(),
                            "-".to_string(),
                            Option::from(result),
                            -1,
                            1,
                        );
                        match rt_entry {
                            Some(_value) => {
                                self.register_tbl.update_element_dst(updated);
                            }
                            None => {
                                self.register_tbl.add_element(updated);
                            }
                        }
                    } else {
                        result[result_start_indx as usize] = self.processor.e_or_bit(
                            &self.sk,
                            &val1[op1_start_indx as usize],
                            &val2[op1_start_indx as usize],
                        );
                        let rt_entry = self.register_tbl.get_element_dst(dst.to_string());
                        match rt_entry {
                            Some(_value) => {
                                let mut temp = rt_entry.unwrap().vec_ctxt.clone().unwrap();
                                temp[result_start_indx as usize] =
                                    result[result_start_indx as usize].clone();
                                result = temp.clone();
                                let updated = RegisterElement::new(
                                    dst.to_string(),
                                    "-".to_string(),
                                    Option::from(result),
                                    -1,
                                    1,
                                );
                                self.register_tbl.update_element_dst(updated);
                            }
                            None => {
                                let updated = RegisterElement::new(
                                    dst.to_string(),
                                    "-".to_string(),
                                    Option::from(result),
                                    -1,
                                    1,
                                );
                                self.register_tbl.add_element(updated);
                            }
                        }
                    }
                } else if ret_a.unwrap().waiting_for == "-" && ret_b.unwrap().waiting_for != "-" {
                    let val1 = ret_a.unwrap().vec_ctxt.clone();
                    self.or_rs.add_entry(
                        id.to_string(),
                        "-".to_string(),
                        ret_b.unwrap().dst.clone(),
                        Option::from(val1),
                        None,
                        dst.to_string(),
                    )
                } else if ret_a.unwrap().waiting_for != "-" && ret_b.unwrap().waiting_for == "-" {
                    let val2 = ret_b.unwrap().vec_ctxt.clone();
                    self.or_rs.add_entry(
                        id.to_string(),
                        ret_a.unwrap().dst.clone(),
                        "-".to_string(),
                        None,
                        Option::from(val2),
                        dst.to_string(),
                    )
                } else if ret_a.unwrap().waiting_for != "-" && ret_b.unwrap().waiting_for != "-" {
                    self.or_rs.add_entry(
                        id.to_string(),
                        ret_a.unwrap().dst.clone(),
                        ret_b.unwrap().dst.clone(),
                        None,
                        None,
                        dst.to_string(),
                    )
                } else {
                    panic!("Error in adding an entry to OrRs");
                }
            }
            "XorRs" => {
                // If the waiting_for of retrieved a and b are -, then the values can be directly used
                if ret_a.unwrap().waiting_for == "-" && ret_b.unwrap().waiting_for == "-" {
                    let val1 = ret_a.unwrap().vec_ctxt.clone().unwrap();
                    let val2 = ret_b.unwrap().vec_ctxt.clone().unwrap();
                    let mut result: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); val1.len()];
                    // Perform XOR operation
                    if result_start_indx == -1 {
                        self.processor.e_xor(&self.sk, &val1, &val2, &mut result);

                        // Move to the Register table
                        //  1. Does it exist in the register table?
                        //   2. If yes, then update the entry
                        //   3. If no, then add a new entry
                        let rt_entry = self.register_tbl.get_element_dst(dst.to_string());
                        let updated = RegisterElement::new(
                            dst.to_string(),
                            "-".to_string(),
                            Option::from(result),
                            -1,
                            1,
                        );
                        match rt_entry {
                            Some(_value) => {
                                self.register_tbl.update_element_dst(updated);
                            }
                            None => {
                                self.register_tbl.add_element(updated);
                            }
                        }
                    } else if result_start_indx == op1_start_indx
                        && result_start_indx == op2_start_indx
                        && result_start_indx < end_indx
                    {
                        self.processor.e_xor_range(
                            &self.sk,
                            &val1,
                            &val2,
                            &mut result,
                            result_start_indx as usize,
                            end_indx as usize,
                        );

                        // Move to the Register table
                        //  1. Does it exist in the register table?
                        //   2. If yes, then update the entry
                        //   3. If no, then add a new entry
                        let rt_entry = self.register_tbl.get_element_dst(dst.to_string());
                        let mut temp = rt_entry.unwrap().vec_ctxt.clone().unwrap();
                        for i in 0..result_start_indx + 1 {
                            result[i as usize] = temp[i as usize].clone();
                        }
                        for i in end_indx as usize..temp.len() {
                            result[i] = temp[i].clone();
                        }
                        let updated = RegisterElement::new(
                            dst.to_string(),
                            "-".to_string(),
                            Option::from(result),
                            -1,
                            1,
                        );
                        match rt_entry {
                            Some(_value) => {
                                self.register_tbl.update_element_dst(updated);
                            }
                            None => {
                                self.register_tbl.add_element(updated);
                            }
                        }
                    } else {
                        result[result_start_indx as usize] = self.processor.e_xor_bit(
                            &self.sk,
                            &val1[op1_start_indx as usize],
                            &val2[op1_start_indx as usize],
                        );
                        let rt_entry = self.register_tbl.get_element_dst(dst.to_string());
                        match rt_entry {
                            Some(_value) => {
                                let mut temp = rt_entry.unwrap().vec_ctxt.clone().unwrap();
                                temp[result_start_indx as usize] =
                                    result[result_start_indx as usize].clone();
                                result = temp.clone();
                                let updated = RegisterElement::new(
                                    dst.to_string(),
                                    "-".to_string(),
                                    Option::from(result),
                                    -1,
                                    1,
                                );
                                self.register_tbl.update_element_dst(updated);
                            }
                            None => {
                                let updated = RegisterElement::new(
                                    dst.to_string(),
                                    "-".to_string(),
                                    Option::from(result),
                                    -1,
                                    1,
                                );
                                self.register_tbl.add_element(updated);
                            }
                        }
                    }
                } else if ret_a.unwrap().waiting_for == "-" && ret_b.unwrap().waiting_for != "-" {
                    let val1 = ret_a.unwrap().vec_ctxt.clone();
                    self.xor_rs.add_entry(
                        id.to_string(),
                        "-".to_string(),
                        ret_b.unwrap().dst.clone(),
                        Option::from(val1),
                        None,
                        dst.to_string(),
                    )
                } else if ret_a.unwrap().waiting_for != "-" && ret_b.unwrap().waiting_for == "-" {
                    let val2 = ret_b.unwrap().vec_ctxt.clone();
                    self.xor_rs.add_entry(
                        id.to_string(),
                        ret_a.unwrap().dst.clone(),
                        "-".to_string(),
                        None,
                        Option::from(val2),
                        dst.to_string(),
                    )
                } else if ret_a.unwrap().waiting_for != "-" && ret_b.unwrap().waiting_for != "-" {
                    self.xor_rs.add_entry(
                        id.to_string(),
                        ret_a.unwrap().dst.clone(),
                        ret_b.unwrap().dst.clone(),
                        None,
                        None,
                        dst.to_string(),
                    )
                } else {
                    panic!("Error in adding an entry to XorRs");
                }
            }
            "NandRs" => {
                // If the waiting_for of retrieved a and b are -, then the values can be directly used
                if ret_a.unwrap().waiting_for == "-" && ret_b.unwrap().waiting_for == "-" {
                    let val1 = ret_a.unwrap().vec_ctxt.clone().unwrap();
                    let val2 = ret_b.unwrap().vec_ctxt.clone().unwrap();
                    let mut result: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); val1.len()];
                    // Perform NAND operation
                    if result_start_indx == -1 {
                        self.processor.e_nand(&self.sk, &val1, &val2, &mut result);

                        // Move to the Register table
                        //  1. Does it exist in the register table?
                        //   2. If yes, then update the entry
                        //   3. If no, then add a new entry
                        let rt_entry = self.register_tbl.get_element_dst(dst.to_string());
                        let updated = RegisterElement::new(
                            dst.to_string(),
                            "-".to_string(),
                            Option::from(result),
                            -1,
                            1,
                        );
                        match rt_entry {
                            Some(_value) => {
                                self.register_tbl.update_element_dst(updated);
                            }
                            None => {
                                self.register_tbl.add_element(updated);
                            }
                        }
                    } else if result_start_indx == op1_start_indx
                        && result_start_indx == op2_start_indx
                        && result_start_indx < end_indx
                    {
                        self.processor.e_nand_range(
                            &self.sk,
                            &val1,
                            &val2,
                            &mut result,
                            result_start_indx as usize,
                            end_indx as usize,
                        );

                        // Move to the Register table
                        //  1. Does it exist in the register table?
                        //   2. If yes, then update the entry
                        //   3. If no, then add a new entry
                        let rt_entry = self.register_tbl.get_element_dst(dst.to_string());
                        let mut temp = rt_entry.unwrap().vec_ctxt.clone().unwrap();
                        for i in 0..result_start_indx + 1 {
                            result[i as usize] = temp[i as usize].clone();
                        }
                        for i in end_indx as usize..temp.len() {
                            result[i] = temp[i].clone();
                        }
                        let updated = RegisterElement::new(
                            dst.to_string(),
                            "-".to_string(),
                            Option::from(result),
                            -1,
                            1,
                        );
                        match rt_entry {
                            Some(_value) => {
                                self.register_tbl.update_element_dst(updated);
                            }
                            None => {
                                self.register_tbl.add_element(updated);
                            }
                        }
                    } else {
                        result[result_start_indx as usize] = self.processor.e_nand_bit(
                            &self.sk,
                            &val1[op1_start_indx as usize],
                            &val2[op1_start_indx as usize],
                        );
                        let rt_entry = self.register_tbl.get_element_dst(dst.to_string());
                        match rt_entry {
                            Some(_value) => {
                                let mut temp = rt_entry.unwrap().vec_ctxt.clone().unwrap();
                                temp[result_start_indx as usize] =
                                    result[result_start_indx as usize].clone();
                                result = temp.clone();
                                let updated = RegisterElement::new(
                                    dst.to_string(),
                                    "-".to_string(),
                                    Option::from(result),
                                    -1,
                                    1,
                                );
                                self.register_tbl.update_element_dst(updated);
                            }
                            None => {
                                let updated = RegisterElement::new(
                                    dst.to_string(),
                                    "-".to_string(),
                                    Option::from(result),
                                    -1,
                                    1,
                                );
                                self.register_tbl.add_element(updated);
                            }
                        }
                    }
                } else if ret_a.unwrap().waiting_for == "-" && ret_b.unwrap().waiting_for != "-" {
                    let val1 = ret_a.unwrap().vec_ctxt.clone();
                    self.nand_rs.add_entry(
                        id.to_string(),
                        "-".to_string(),
                        ret_b.unwrap().dst.clone(),
                        Option::from(val1),
                        None,
                        dst.to_string(),
                    )
                } else if ret_a.unwrap().waiting_for != "-" && ret_b.unwrap().waiting_for == "-" {
                    let val2 = ret_b.unwrap().vec_ctxt.clone();
                    self.nand_rs.add_entry(
                        id.to_string(),
                        ret_a.unwrap().dst.clone(),
                        "-".to_string(),
                        None,
                        Option::from(val2),
                        dst.to_string(),
                    )
                } else if ret_a.unwrap().waiting_for != "-" && ret_b.unwrap().waiting_for != "-" {
                    self.nand_rs.add_entry(
                        id.to_string(),
                        ret_a.unwrap().dst.clone(),
                        ret_b.unwrap().dst.clone(),
                        None,
                        None,
                        dst.to_string(),
                    )
                } else {
                    panic!("Error in adding an entry to NandRs");
                }
            }
            "NorRs" => {
                // If the waiting_for of retrieved a and b are -, then the values can be directly used
                if ret_a.unwrap().waiting_for == "-" && ret_b.unwrap().waiting_for == "-" {
                    let val1 = ret_a.unwrap().vec_ctxt.clone().unwrap();
                    let val2 = ret_b.unwrap().vec_ctxt.clone().unwrap();
                    let mut result: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); val1.len()];
                    // Perform NOR operation
                    if result_start_indx == -1 {
                        self.processor.e_nor(&self.sk, &val1, &val2, &mut result);

                        // Move to the Register table
                        //  1. Does it exist in the register table?
                        //   2. If yes, then update the entry
                        //   3. If no, then add a new entry
                        let rt_entry = self.register_tbl.get_element_dst(dst.to_string());
                        let updated = RegisterElement::new(
                            dst.to_string(),
                            "-".to_string(),
                            Option::from(result),
                            -1,
                            1,
                        );
                        match rt_entry {
                            Some(_value) => {
                                self.register_tbl.update_element_dst(updated);
                            }
                            None => {
                                self.register_tbl.add_element(updated);
                            }
                        }
                    } else if result_start_indx == op1_start_indx
                        && result_start_indx == op2_start_indx
                        && result_start_indx < end_indx
                    {
                        self.processor.e_nor_range(
                            &self.sk,
                            &val1,
                            &val2,
                            &mut result,
                            result_start_indx as usize,
                            end_indx as usize,
                        );

                        // Move to the Register table
                        //  1. Does it exist in the register table?
                        //   2. If yes, then update the entry
                        //   3. If no, then add a new entry
                        let rt_entry = self.register_tbl.get_element_dst(dst.to_string());
                        let mut temp = rt_entry.unwrap().vec_ctxt.clone().unwrap();
                        for i in 0..result_start_indx + 1 {
                            result[i as usize] = temp[i as usize].clone();
                        }
                        for i in end_indx as usize..temp.len() {
                            result[i] = temp[i].clone();
                        }
                        let updated = RegisterElement::new(
                            dst.to_string(),
                            "-".to_string(),
                            Option::from(result),
                            -1,
                            1,
                        );
                        match rt_entry {
                            Some(_value) => {
                                self.register_tbl.update_element_dst(updated);
                            }
                            None => {
                                self.register_tbl.add_element(updated);
                            }
                        }
                    } else {
                        result[result_start_indx as usize] = self.processor.e_nor_bit(
                            &self.sk,
                            &val1[op1_start_indx as usize],
                            &val2[op1_start_indx as usize],
                        );
                        let rt_entry = self.register_tbl.get_element_dst(dst.to_string());
                        match rt_entry {
                            Some(_value) => {
                                let mut temp = rt_entry.unwrap().vec_ctxt.clone().unwrap();
                                temp[result_start_indx as usize] =
                                    result[result_start_indx as usize].clone();
                                result = temp.clone();
                                let updated = RegisterElement::new(
                                    dst.to_string(),
                                    "-".to_string(),
                                    Option::from(result),
                                    -1,
                                    1,
                                );
                                self.register_tbl.update_element_dst(updated);
                            }
                            None => {
                                let updated = RegisterElement::new(
                                    dst.to_string(),
                                    "-".to_string(),
                                    Option::from(result),
                                    -1,
                                    1,
                                );
                                self.register_tbl.add_element(updated);
                            }
                        }
                    }
                } else if ret_a.unwrap().waiting_for == "-" && ret_b.unwrap().waiting_for != "-" {
                    let val1 = ret_a.unwrap().vec_ctxt.clone();
                    self.nor_rs.add_entry(
                        id.to_string(),
                        "-".to_string(),
                        ret_b.unwrap().dst.clone(),
                        Option::from(val1),
                        None,
                        dst.to_string(),
                    )
                } else if ret_a.unwrap().waiting_for != "-" && ret_b.unwrap().waiting_for == "-" {
                    let val2 = ret_b.unwrap().vec_ctxt.clone();
                    self.nor_rs.add_entry(
                        id.to_string(),
                        ret_a.unwrap().dst.clone(),
                        "-".to_string(),
                        None,
                        Option::from(val2),
                        dst.to_string(),
                    )
                } else if ret_a.unwrap().waiting_for != "-" && ret_b.unwrap().waiting_for != "-" {
                    self.nor_rs.add_entry(
                        id.to_string(),
                        ret_a.unwrap().dst.clone(),
                        ret_b.unwrap().dst.clone(),
                        None,
                        None,
                        dst.to_string(),
                    )
                } else {
                    panic!("Error in adding an entry to NorRs");
                }
            }
            "XnorRs" => {
                // If the waiting_for of retrieved a and b are -, then the values can be directly used
                if ret_a.unwrap().waiting_for == "-" && ret_b.unwrap().waiting_for == "-" {
                    let val1 = ret_a.unwrap().vec_ctxt.clone().unwrap();
                    let val2 = ret_b.unwrap().vec_ctxt.clone().unwrap();
                    let mut result: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); val1.len()];
                    // Perform XNOR operation
                    if result_start_indx == -1 {
                        self.processor.e_xnor(&self.sk, &val1, &val2, &mut result);

                        // Move to the Register table
                        //  1. Does it exist in the register table?
                        //   2. If yes, then update the entry
                        //   3. If no, then add a new entry
                        let rt_entry = self.register_tbl.get_element_dst(dst.to_string());
                        let updated = RegisterElement::new(
                            dst.to_string(),
                            "-".to_string(),
                            Option::from(result),
                            -1,
                            1,
                        );
                        match rt_entry {
                            Some(_value) => {
                                self.register_tbl.update_element_dst(updated);
                            }
                            None => {
                                self.register_tbl.add_element(updated);
                            }
                        }
                    } else if result_start_indx == op1_start_indx
                        && result_start_indx == op2_start_indx
                        && result_start_indx < end_indx
                    {
                        self.processor.e_xnor_range(
                            &self.sk,
                            &val1,
                            &val2,
                            &mut result,
                            result_start_indx as usize,
                            end_indx as usize,
                        );

                        // Move to the Register table
                        //  1. Does it exist in the register table?
                        //   2. If yes, then update the entry
                        //   3. If no, then add a new entry
                        let rt_entry = self.register_tbl.get_element_dst(dst.to_string());
                        let mut temp = rt_entry.unwrap().vec_ctxt.clone().unwrap();
                        for i in 0..result_start_indx + 1 {
                            result[i as usize] = temp[i as usize].clone();
                        }
                        for i in end_indx as usize..temp.len() {
                            result[i] = temp[i].clone();
                        }
                        let updated = RegisterElement::new(
                            dst.to_string(),
                            "-".to_string(),
                            Option::from(result),
                            -1,
                            1,
                        );
                        match rt_entry {
                            Some(_value) => {
                                self.register_tbl.update_element_dst(updated);
                            }
                            None => {
                                self.register_tbl.add_element(updated);
                            }
                        }
                    } else {
                        result[result_start_indx as usize] = self.processor.e_xnor_bit(
                            &self.sk,
                            &val1[op1_start_indx as usize],
                            &val2[op1_start_indx as usize],
                        );
                        let rt_entry = self.register_tbl.get_element_dst(dst.to_string());
                        match rt_entry {
                            Some(_value) => {
                                let mut temp = rt_entry.unwrap().vec_ctxt.clone().unwrap();
                                temp[result_start_indx as usize] =
                                    result[result_start_indx as usize].clone();
                                result = temp.clone();
                                let updated = RegisterElement::new(
                                    dst.to_string(),
                                    "-".to_string(),
                                    Option::from(result),
                                    -1,
                                    1,
                                );
                                self.register_tbl.update_element_dst(updated);
                            }
                            None => {
                                let updated = RegisterElement::new(
                                    dst.to_string(),
                                    "-".to_string(),
                                    Option::from(result),
                                    -1,
                                    1,
                                );
                                self.register_tbl.add_element(updated);
                            }
                        }
                    }
                } else if ret_a.unwrap().waiting_for == "-" && ret_b.unwrap().waiting_for != "-" {
                    let val1 = ret_a.unwrap().vec_ctxt.clone();
                    self.xnor_rs.add_entry(
                        id.to_string(),
                        "-".to_string(),
                        ret_b.unwrap().dst.clone(),
                        Option::from(val1),
                        None,
                        dst.to_string(),
                    )
                } else if ret_a.unwrap().waiting_for != "-" && ret_b.unwrap().waiting_for == "-" {
                    let val2 = ret_b.unwrap().vec_ctxt.clone();
                    self.xnor_rs.add_entry(
                        id.to_string(),
                        ret_a.unwrap().dst.clone(),
                        "-".to_string(),
                        None,
                        Option::from(val2),
                        dst.to_string(),
                    )
                } else if ret_a.unwrap().waiting_for != "-" && ret_b.unwrap().waiting_for != "-" {
                    self.xnor_rs.add_entry(
                        id.to_string(),
                        ret_a.unwrap().dst.clone(),
                        ret_b.unwrap().dst.clone(),
                        None,
                        None,
                        dst.to_string(),
                    )
                } else {
                    panic!("Error in adding an entry to XnorRs");
                }
            }
            _ => panic!("Ouch! Error in adding an element to a reservation station."),
        }
    }
    fn adder(&mut self, a: &[Ciphertext], b: &[Ciphertext], result: &mut [Ciphertext]) {
        let a_reg = RegisterElement::new(
            "a".to_string(),
            "-".to_string(),
            Option::from(a.to_vec()),
            -2,
            1,
        );
        self.register_tbl.add_element(a_reg);
        let b_reg = RegisterElement::new(
            "b".to_string(),
            "-".to_string(),
            Option::from(b.to_vec()),
            -2,
            1,
        );
        self.register_tbl.add_element(b_reg);
        let result_reg = RegisterElement::new(
            "result".to_string(),
            "-".to_string(),
            Option::from(result.to_vec()),
            -2,
            1,
        );
        self.register_tbl.add_element(result_reg);
        let size = a.len();

        // Initialize temporary vectors
        let carry: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); size + 1]; // Includes carry-out
        let carry_reg = RegisterElement::new(
            "carry".to_string(),
            "-".to_string(),
            Option::from(carry),
            -2,
            1,
        );
        self.register_tbl.add_element(carry_reg);

        let temp: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); size];
        let temp_reg = RegisterElement::new(
            "temp".to_string(),
            "-".to_string(),
            Option::from(temp),
            -2,
            1,
        );
        self.register_tbl.add_element(temp_reg);

        let a_and_b: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); size];
        let a_and_b_reg = RegisterElement::new(
            "a_and_b".to_string(),
            "-".to_string(),
            Option::from(a_and_b),
            -2,
            1,
        );
        self.register_tbl.add_element(a_and_b_reg);

        // Compute a XOR b for all bits
        //----> e_xor(sk, a, b, &mut temp);
        self.add_to_reservation_station("XorRs", "XOR_1", "a", "b", "temp", -1, -1, -1, -1);

        //----> e_and(sk, a, b, &mut a_and_b);
        self.add_to_reservation_station("AndRs", "AND_1", "a", "b", "a_and_b", -1, -1, -1, -1);

        // Ripple-carry adder logic
        for i in 0..size {
            // Sum bit: result[i] = a[i] XOR b[i] XOR carry[i]
            // -----> result[i] = e_xor_bit(sk, &carry[i], &temp[i]);
            self.add_to_reservation_station(
                "XorRs", "XOR_2", "carry", "temp", "result", i as i8, i as i8, i as i8, i as i8,
            );

            if i != size - 1 {
                // Carry bit: carry[i+1] = (a[i] AND b[i]) OR (a[i] AND carry[i]) OR (b[i] AND carry[i])
                // -----> let a_and_carry = e_and_bit(sk, &a[i], &carry[i]);
                self.add_to_reservation_station(
                    "AndRs",
                    "AND_2",
                    "a",
                    "carry",
                    "a_and_carry",
                    i as i8,
                    i as i8,
                    i as i8,
                    i as i8,
                );
                // -----> let b_and_carry = e_and_bit(sk, &b[i], &carry[i]);
                self.add_to_reservation_station(
                    "AndRs",
                    "AND_3",
                    "b",
                    "carry",
                    "b_and_carry",
                    i as i8,
                    i as i8,
                    i as i8,
                    i as i8,
                );
                // ----> let temp_carry = e_or_bit(sk, &a_and_b[i], &a_and_carry);
                self.add_to_reservation_station(
                    "OrRs",
                    "OR_1",
                    "a_and_b",
                    "a_and_carry",
                    "temp_carry",
                    i as i8,
                    i as i8,
                    i as i8,
                    i as i8,
                );
                // ----> carry[i + 1] = e_or_bit(sk, &temp_carry, &b_and_carry);
                self.add_to_reservation_station(
                    "OrRs",
                    "OR_2",
                    "temp_carry",
                    "b_and_carry",
                    "carry",
                    (i + 1) as i8,
                    i as i8,
                    i as i8,
                    i as i8,
                );
            }
        }
        let res = self.register_tbl.get_element_dst("result".to_string());
        match res {
            Some(value) => {
                if let Some(vec_ctxt) = &value.vec_ctxt {
                    for (i, item) in vec_ctxt.iter().enumerate() {
                        if i < result.len() {
                            result[i] = item.clone();
                        }
                    }
                }
            }
            None => {
                panic!("Error in retrieving result from register table");
            }
        }
    }
}
