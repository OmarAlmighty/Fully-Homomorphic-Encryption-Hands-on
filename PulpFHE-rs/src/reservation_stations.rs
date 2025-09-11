use crate::register_table::{RegisterElement, Subscriber, RegisterTable};
use tfhe::boolean::prelude::*;

// Shape trait that extends Subscriber
pub trait rs_entry: Subscriber {
    fn get_id(&self) -> String;
    fn set_id(&mut self, id: String);

    fn get_busy(&self) -> bool;
    fn set_busy(&mut self, busy: bool);

    fn get_rs1(&self) -> String;
    fn set_rs1(&mut self, rs1: String);

    fn get_rs2(&self) -> String;
    fn set_rs2(&mut self, rs2: String);

    fn get_val1(&self) -> Ciphertext;
    fn set_val1(&mut self, val1: Ciphertext);

    fn get_val2(&self) -> Ciphertext;
    fn set_val2(&mut self, val2: Ciphertext);

    fn get_dst(&self) -> String;
    fn set_dst(&mut self, dst: String);
}

pub struct AND_rs {
    id: String,
    busy: bool,
    rs1: String,
    rs2: String,
    val1: Ciphertext,
    val2: Ciphertext,
    dst: String,
}

pub struct OR_rs {
    id: String,
    busy: bool,
    rs1: String,
    rs2: String,
    val1: Ciphertext,
    val2: Ciphertext,
    dst: String,
}

pub struct XOR_rs {
    id: String,
    busy: bool,
    rs1: String,
    rs2: String,
    val1: Ciphertext,
    val2: Ciphertext,
    dst: String,
}

pub struct NAND_rs {
    id: String,
    busy: bool,
    rs1: String,
    rs2: String,
    val1: Ciphertext,
    val2: Ciphertext,
    dst: String,
}

pub struct NOR_rs {
    id: String,
    busy: bool,
    rs1: String,
    rs2: String,
    val1: Ciphertext,
    val2: Ciphertext,
    dst: String,
}

pub struct XNOR_rs {
    id: String,
    busy: bool,
    rs1: String,
    rs2: String,
    val1: Ciphertext,
    val2: Ciphertext,
    dst: String,
}

impl AND_rs {
    pub fn new(
        id: String,
        busy: bool,
        rs1: String,
        rs2: String,
        val1: Ciphertext,
        val2: Ciphertext,
        dst: String,
    ) -> Self {
        AND_rs {id, busy, rs1, rs2, val1, val2, dst}
    }
}

impl OR_rs {
    pub fn new(
        id: String,
        busy: bool,
        rs1: String,
        rs2: String,
        val1: Ciphertext,
        val2: Ciphertext,
        dst: String,
    ) -> Self {
        OR_rs {id, busy, rs1, rs2, val1, val2, dst}
    }
}

impl XOR_rs {
    pub fn new(
        id: String,
        busy: bool,
        rs1: String,
        rs2: String,
        val1: Ciphertext,
        val2: Ciphertext,
        dst: String,
    ) -> Self {
        XOR_rs {id, busy, rs1, rs2, val1, val2, dst}
    }
}

impl NAND_rs {
    pub fn new(
        id: String,
        busy: bool,
        rs1: String,
        rs2: String,
        val1: Ciphertext,
        val2: Ciphertext,
        dst: String,
    ) -> Self {
        NAND_rs {id, busy, rs1, rs2, val1, val2, dst}
    }
}

impl NOR_rs {
    pub fn new(
        id: String,
        busy: bool,
        rs1: String,
        rs2: String,
        val1: Ciphertext,
        val2: Ciphertext,
        dst: String,
    ) -> Self {
        NOR_rs {id, busy, rs1, rs2, val1, val2, dst}
    }
}

impl XNOR_rs {
    pub fn new(
        id: String,
        busy: bool,
        rs1: String,
        rs2: String,
        val1: Ciphertext,
        val2: Ciphertext,
        dst: String,
    ) -> Self {
        XNOR_rs {id, busy, rs1, rs2, val1, val2, dst}
    }
}

impl rs_entry for AND_rs {
    fn get_id(&self) -> String {self.id.clone()}
    fn set_id(&mut self, id: String) {self.id = id}

    fn get_busy(&self) -> bool {
        self.busy
    }
    fn set_busy(&mut self, busy: bool) {
        self.busy = busy
    }

    fn get_rs1(&self) -> String {
        self.rs1.clone()
    }

    fn set_rs1(&mut self, rs1: String) {
        self.rs1 = rs1.clone()
    }

    fn get_rs2(&self) -> String {
        self.rs2.clone()
    }

    fn set_rs2(&mut self, rs2: String) {
        self.rs2 = rs2.clone()
    }

    fn get_val1(&self) -> Ciphertext {
        self.val1.clone()
    }

    fn set_val1(&mut self, val1: Ciphertext) {
        self.val1 = val1.clone()
    }

    fn get_val2(&self) -> Ciphertext {
        self.val2.clone()
    }

    fn set_val2(&mut self, val2: Ciphertext) {
        self.val2 = val2.clone()
    }

    fn get_dst(&self) -> String {
        self.dst.clone()
    }

    fn set_dst(&mut self, dst: String) {
        self.dst = dst.clone()
    }
}

impl Subscriber for AND_rs {
    fn update(&mut self, element: RegisterElement) {
        if element.dst == self.dst{
            let new_element: RegisterElement = RegisterElement::new(self.dst, self.id, self.)
        }
        if element.dst == self.rs1 {
            self.val1 = element.ctxt;
        } else if element.dst == self.rs2 {
            self.val2 = element.ctxt;
        }
    }

    fn add(&mut self, reg_elmnt: RegisterElement) {
        if reg_elmnt.dst == self.rs1 {
            self.val1 = reg_elmnt.ctxt;
        } else if reg_elmnt.dst == self.rs2 {
            self.val2 = reg_elmnt.ctxt;
        }
    }
}
