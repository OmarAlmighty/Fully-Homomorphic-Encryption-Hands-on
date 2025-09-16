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
pub struct AndRs {
    entries: Vec<RsEntry>,
}
impl AndRs {
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
pub struct OrRs {
    entries: Vec<RsEntry>,
}

impl OrRs {
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
pub struct XorRs {
    entries: Vec<RsEntry>,
}

impl XorRs {
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
pub struct NandRs {
    entries: Vec<RsEntry>,
}
impl NandRs {
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
pub struct NorRs {
    entries: Vec<RsEntry>,
}

impl NorRs {
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

pub struct XnorRs {
    entries: Vec<RsEntry>,
}

impl XnorRs {
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
impl Subscriber for AndRs {
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
        println!("This subscriber's update function is called.")
    }

    fn add(&mut self, reg_elmnt: RegisterElement) {
        println!("This subscriber's add function is called.")
    }

    fn fetch(&self, dst: String) {
        todo!()
    }

    fn remove(&mut self, dst: String) {
        todo!()
    }
}
