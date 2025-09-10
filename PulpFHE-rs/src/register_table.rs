use std::cmp::Ordering;
use std::collections::BinaryHeap;
use tfhe::boolean::prelude::*;


/*
Implement a struct that includes an array of objects, where each object the following attributes:
    - dst: destination register
    - w: weight
    - value: value
    - x: x coordinate
    - pri: priority
The objects can be added, removed, returned, or updated by other objects.
This struct is the publisher object is the Observer design pattern. There should be an interface for
which subscribers can implement to receive updates from the publisher.
 */
#[derive(Debug, Clone)]
pub struct RegisterElemnt {
    pub dst: i32,
    pub w: f64,
    pub value: String,
    pub x: i32,
    pub pri: u32, // Priority (lower value = higher priority)
}

// Implement PartialEq, Eq, PartialOrd, and Ord for BinaryHeap compatibility
impl PartialEq for RegisterElemnt {
    fn eq(&self, other: &Self) -> bool {
        self.pri == other.pri
    }
}

impl Eq for RegisterElemnt {}

impl PartialOrd for RegisterElemnt {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for RegisterElemnt {
    fn cmp(&self, other: &Self) -> Ordering {
        // Reverse ordering to make lower priority values higher priority
        other.pri.cmp(&self.pri)
    }
}

// Interface for subscribers to listen for queue updates
pub trait RegTblListener {
    // Called when an element is pushed
    fn on_push(&self, element: &RegisterElemnt);
    // Called when an element is popped
    fn on_pop(&self, element: &RegisterElemnt);
}

// Worker struct (a subscriber)
#[derive(Debug)]
pub struct Worker {
    id: u32,
}

impl Worker {
    pub fn new(id: u32) -> Self {
        Worker { id }
    }
}

impl RegTblListener for Worker {
    fn on_push(&self, element: &RegisterElemnt) {
        println!("Worker {} received push update: {:?}", self.id, element);
    }

    fn on_pop(&self, element: &RegisterElemnt) {
        println!("Worker {} received pop update: {:?}", self.id, element);
    }
}

// Helper struct (another subscriber)
#[derive(Debug)]
pub struct Helper {
    name: String,
}

impl Helper {
    pub fn new(name: &str) -> Self {
        Helper {
            name: name.to_string(),
        }
    }
}

impl RegTblListener for Helper {
    fn on_push(&self, element: &RegisterElemnt) {
        println!("Helper {} received push update: {:?}", self.name, element);
    }

    fn on_pop(&self, element: &RegisterElemnt) {
        println!("Helper {} received pop update: {:?}", self.name, element);
    }
}

// Priority queue structure (publisher)
pub struct PriorityQueue {
    heap: BinaryHeap<RegisterElemnt>,
    listeners: Vec<Box<dyn RegTblListener>>,
}

impl PriorityQueue {
    // Create a new empty priority queue
    pub fn new() -> Self {
        PriorityQueue {
            heap: BinaryHeap::new(),
            listeners: Vec::new(),
        }
    }

    // Add a listener (implements QueueListener)
    pub fn add_listener(&mut self, listener: Box<dyn RegTblListener>) {
        self.listeners.push(listener);
    }

    // Notify all listeners of a push event
    fn notify_push(&self, element: &RegisterElemnt) {
        for listener in &self.listeners {
            listener.on_push(element);
        }
    }

    // Notify all listeners of a pop event
    fn notify_pop(&self, element: &RegisterElemnt) {
        for listener in &self.listeners {
            listener.on_pop(element);
        }
    }

    // Push an element onto the priority queue
    pub fn push(&mut self, element: RegisterElemnt) {
        self.heap.push(element.clone());
        self.notify_push(&element);
    }

    // Pop the highest priority element (lowest pri value)
    pub fn pop(&mut self) -> Option<RegisterElemnt> {
        if let Some(element) = self.heap.pop() {
            self.notify_pop(&element);
            Some(element)
        } else {
            None
        }
    }

    // Peek at the highest priority element without removing it
    pub fn peek(&self) -> Option<&RegisterElemnt> {
        self.heap.peek()
    }

    // Check if the queue is empty
    pub fn is_empty(&self) -> bool {
        self.heap.is_empty()
    }

    // Get the current size of the queue
    pub fn len(&self) -> usize {
        self.heap.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_priority_queue_with_listeners() {
        let mut pq = PriorityQueue::new();

        // Add listeners
        pq.add_listener(Box::new(Worker::new(1)));
        pq.add_listener(Box::new(Helper::new("Alpha")));

        // Test empty queue
        assert!(pq.is_empty());
        assert_eq!(pq.len(), 0);
        assert_eq!(pq.pop(), None);

        // Test pushing elements
        let elem1 = RegisterElemnt {
            dst: 1,
            w: 1.5,
            value: String::from("first"),
            x: 10,
            pri: 2,
        };
        let elem2 = RegisterElemnt {
            dst: 2,
            w: 2.5,
            value: String::from("second"),
            x: 20,
            pri: 1,
        };
        let elem3 = RegisterElemnt {
            dst: 3,
            w: 3.5,
            value: String::from("third"),
            x: 30,
            pri: 3,
        };

        pq.push(elem1);
        pq.push(elem2);
        pq.push(elem3);

        // Test queue properties
        assert_eq!(pq.len(), 3);
        assert!(!pq.is_empty());

        // Test peek (should return element with pri=1)
        assert_eq!(pq.peek().unwrap().value, "second");

        // Test pop order (should be pri=1, 2, 3)
        assert_eq!(pq.pop().unwrap().value, "second");
        assert_eq!(pq.pop().unwrap().value, "first");
        assert_eq!(pq.pop().unwrap().value, "third");
        assert_eq!(pq.pop(), None);
    }
}
