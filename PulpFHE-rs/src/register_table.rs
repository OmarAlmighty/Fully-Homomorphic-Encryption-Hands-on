use std::cell::RefCell;
use std::fmt::Debug;
use std::rc::Weak;
use tfhe::boolean::prelude::*;

// Struct for individual objects
#[derive(Clone, Debug)]
pub struct RegisterElement {
    pub dst: String,                       // destination register
    pub waiting_for: String,               // waiting_for which reservation station
    pub vec_ctxt: Option<Vec<Ciphertext>>, // The result ciphertext from a reservation station or a load instruction
    pub bootstrap: i8, // Bootstrap? -2 --> no bootstrapping  • -1 --> bootstrap all of the bits 0…32 --> bootstrap bits at specific index
    pub priority: u32, // priority
}

impl RegisterElement {
    pub fn new(
        dst: String,
        waiting_for: String,
        vec_ctxt: Option<Vec<Ciphertext>>,
        bootstrap: i8,
        priority: u32,
    ) -> Self {
        RegisterElement {
            dst,
            waiting_for,
            vec_ctxt,
            bootstrap,
            priority,
        }
    }
}

// Trait for subscribers (equivalent to interface)
pub trait Subscriber {
    fn decode(&self, code: u8, index: usize, dst: String);
    fn update(&mut self, reg_elmnt: RegisterElement);
    fn add(&mut self, reg_elmnt: RegisterElement);
    fn fetch(&self, dst: String);
    fn remove(&mut self, dst: String);
}

// Publisher struct implementing the Observer pattern
pub struct RegisterTable {
    reg_elements: Vec<RegisterElement>,
    subscribers: Vec<Weak<RefCell<dyn Subscriber>>>,
}

impl RegisterTable {
    // Create a new Publisher
    pub fn new() -> Self {
        RegisterTable {
            reg_elements: Vec::new(),
            subscribers: Vec::new(),
        }
    }

    // Add a new object
    pub fn add_element(&mut self, element: RegisterElement) {
        let dst = element.dst.clone();
        self.reg_elements.push(element);
        self.notify(1, self.reg_elements.len() - 1, dst);
    }

    // Remove an object by index
    pub fn remove_element_indx(&mut self, index: usize) -> bool {
        if index >= self.reg_elements.len() {
            return false;
        }
        self.reg_elements.remove(index);
        self.notify(2, index, "-".parse().unwrap());
        true
    }

    // Update an object at a specific index
    pub fn update_element_indx(&mut self, index: usize, element: RegisterElement) -> bool {
        if index >= self.reg_elements.len() {
            return false;
        }
        let dst = element.dst.clone();
        self.reg_elements[index] = element;
        self.notify(3, index, dst);
        true
    }

    pub fn remove_element_dst(&mut self, dst: String) -> bool {
        for (i, e) in self.reg_elements.iter().enumerate() {
            if e.dst == dst {
                self.reg_elements.remove(i);
                self.notify(4, i, dst);
                return true;
            }
        }
        false
    }

    // Update an object at a specific destination
    pub fn update_element_dst(&mut self, element: RegisterElement) -> bool {
        let current_dst: String = element.dst.clone();
        for (i, e) in self.reg_elements.iter().enumerate() {
            if e.dst == current_dst {
                self.reg_elements[i].dst = element.dst.clone();
                self.reg_elements[i].vec_ctxt = element.vec_ctxt.clone();
                self.reg_elements[i].bootstrap = element.bootstrap.clone();
                self.reg_elements[i].priority = element.priority.clone();
                self.notify(5, i, current_dst);
                return true;
            }
        }
        false
    }

    // Get object at index
    pub fn get_element_indx(&self, index: usize) -> Option<&RegisterElement> {
        self.reg_elements.get(index)
    }
    pub fn get_element_dst(&self, dst: String) -> Option<&RegisterElement> {
        for (i, e) in self.reg_elements.iter().enumerate() {
            if e.dst == dst {
                return Some(&self.reg_elements[i]);
            }
        }
        None
    }

    // Get all objects
    pub fn get_all_elements(&self) -> &[RegisterElement] {
        &self.reg_elements
    }

    pub fn print_register_table(&self) {
        println!("Register Table:");
        println!("=============================================");
        println!("|Index || dst | waiting_for | ctxt | bootstrap? | priority|");
        for (i, e) in self.reg_elements.iter().enumerate() {
            println!(
                "|{} || {:<4} | {:<4} | {:?} | {:<4} | {:<4}|",
                i, e.dst, e.waiting_for, e.vec_ctxt, e.bootstrap, e.priority
            );
        }
        println!("=============================================");
    }

    // Subscribe to updates
    pub fn subscribe(&mut self, subscriber: Weak<RefCell<dyn Subscriber>>) {
        self.subscribers.push(subscriber);
    }

    // Unsubscribe from updates
    pub fn unsubscribe(&mut self, subscriber: Weak<RefCell<dyn Subscriber>>) {
        self.subscribers.retain(|s| !s.ptr_eq(&subscriber));
    }

    // Notify all subscribers of changes
    fn notify(&self, code: u8, indx: usize, dst: String) {
        // Clean up any weak references that no longer exist
        let subscribers: Vec<_> = self
            .subscribers
            .iter()
            .filter_map(|s| s.upgrade())
            .collect();

        for subscriber in subscribers {
            if let Ok(mut sub) = subscriber.try_borrow_mut() {
                for element in &self.reg_elements {
                    sub.decode(code, indx, dst.clone());
                }
            }
        }
    }
}
