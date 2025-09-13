use crate::register_table::{RegisterElement, RegisterTable, Subscriber};
use tfhe::boolean::prelude::*;

// Shape trait that extends Subscriber
pub struct RsEntry {
    id: String,
    busy: bool,
    rs1: String,
    rs2: String,
    val1: Option<Vec<Ciphertext>>,
    val2: Option<Vec<Ciphertext>>,
    dst: String,
}

impl RsEntry {
    pub fn new(
        id: String,
        busy: bool,       
        rs1: String,
        rs2: String,
        val1: Option<Vec<Ciphertext>>,
        val2: Option<Vec<Ciphertext>>,
        dst: String,
    ) -> Self {
        Self {
            id,
            busy,
            rs1,
            rs2,
            val1,
            val2,
            dst,
        }
    }
}
pub struct AND_rs {
    entries: Vec<RsEntry>,
}
impl AND_rs {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }
    pub fn add_entry(
        &mut self,
        id: String,
        rs1: String,
        rs2: String,
        val1: Option<Vec<Ciphertext>>,
        val2: Option<Vec<Ciphertext>>,
        dst: String,
    ) {
        let entry = RsEntry::new(id, true, rs1, rs2, val1, val2, dst);
        self.entries.push(entry);
    }
}
pub struct OR_rs {
    entries: Vec<RsEntry>,
}

impl OR_rs {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }
    pub fn add_entry(
        &mut self,
        id: String,
        rs1: String,
        rs2: String,
        val1: Option<Vec<Ciphertext>>,
        val2: Option<Vec<Ciphertext>>,
        dst: String,
    ) {
        let entry = RsEntry::new(id, true, rs1, rs2, val1, val2, dst);
        self.entries.push(entry);
    }
}
pub struct XOR_rs {
    entries: Vec<RsEntry>,
}

impl XOR_rs {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }
    pub fn add_entry(
        &mut self,
        id: String,
        rs1: String,
        rs2: String,
        val1: Option<Vec<Ciphertext>>,
        val2: Option<Vec<Ciphertext>>,
        dst: String,
    ) {
        let entry = RsEntry::new(id, true, rs1, rs2, val1, val2, dst);
        self.entries.push(entry);
    }
}
pub struct NAND_rs {
    entries: Vec<RsEntry>,
}
impl NAND_rs {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }
    pub fn add_entry(
        &mut self,
        id: String,
        rs1: String,
        rs2: String,
        val1: Option<Vec<Ciphertext>>,
        val2: Option<Vec<Ciphertext>>,
        dst: String,
    ) {
        let entry = RsEntry::new(id, true, rs1, rs2, val1, val2, dst);
        self.entries.push(entry);
    }
}
pub struct NOR_rs {
    entries: Vec<RsEntry>,
}

impl NOR_rs {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }
    pub fn add_entry(
        &mut self,
        id: String,
        rs1: String,
        rs2: String,
        val1: Option<Vec<Ciphertext>>,
        val2: Option<Vec<Ciphertext>>,
        dst: String,
    ) {
        let entry = RsEntry::new(id, true, rs1, rs2, val1, val2, dst);
        self.entries.push(entry);
    }
}

pub struct XNOR_rs {
    entries: Vec<RsEntry>,
}

impl XNOR_rs {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }
    pub fn add_entry(
        &mut self,
        id: String,
        rs1: String,
        rs2: String,
        val1: Option<Vec<Ciphertext>>,
        val2: Option<Vec<Ciphertext>>,
        dst: String,
    ) {
        let entry = RsEntry::new(id, true, rs1, rs2, val1, val2, dst);
        self.entries.push(entry);
    }
}
impl Subscriber for AND_rs {
    fn decode(&self, code: u8, index: usize, dst: String) {
        // code = 1 --> a new element is added to the register table
        if code == 1 {
            for (i, e) in self.entries.iter().enumerate() {
                if e.busy == true {
                    todo!()
                }
            }
        }
        // code = 2 --> an element is removed by indx
        else if code == 2 {
            todo!()
        }
        // code = 3 --> an element is updated by indx
        else if code == 3 {
        }
        // code = 4 --> an element is removed by dst
        else if code == 4 {
        }
        // code = 5 --> an element is updated by dst
        else if code == 5 {
        }
    }

    fn update(&mut self, element: RegisterElement) {
        if element.dst == self.dst {
            //let new_element: RegisterElement = RegisterElement::new(self.dst, self.id, self.)
        }
        if element.dst == self.rs1 {
            self.val1 = element.vec_ctxt;
        } else if element.dst == self.rs2 {
            self.val2 = element.vec_ctxt;
        }
    }

    fn add(&mut self, reg_elmnt: RegisterElement) {
        if reg_elmnt.dst == self.rs1 {
            self.val1 = reg_elmnt.vec_ctxt;
        } else if reg_elmnt.dst == self.rs2 {
            self.val2 = reg_elmnt.vec_ctxt;
        }
    }

    fn fetch(&self, dst: String) {
        todo!()
    }

    fn remove(&mut self, dst: String) {
        todo!()
    }
}
