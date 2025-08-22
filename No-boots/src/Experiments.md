# Boolean API

## AND
* **Input**: 8, 16, 32 bits vectors
* **Time (No bootstrapping)**: 142, 240, 350 microseconds
* **Time (Bootstrapping)**: 14, 29, 50 seconds
* **Capacity**: 1 AND operation across the vector without bootstrapping

## OR
* **Input**: 8, 16, 32 bits vectors
* **Time (No bootstrapping)**: 106, 219, 350 microseconds
* **Time (Bootstrapping)**: 13, 29, 42 seconds
* **Capacity**: 1 OR operation across the vector without bootstrapping


## XOR
* **Input**: 8, 16, 32 bits vectors
* **Time (No bootstrapping)**: 168, 296, 554 microseconds
* **Time (Bootstrapping)**:  17, 34, 52 seconds
* **Capacity**: 1 XOR operation across the vector without bootstrapping

## NAND
* **Input**: 8, 16, 32 bits vectors
* **Time (No bootstrapping)**: 145, 338, 498 microseconds
* **Time (Bootstrapping)**: 17, 35, 54 seconds
* **Capacity**: 1 NAND operation across the vector without bootstrapping

## NOR
* **Input**: 8, 16, 32 bits vectors
* **Time (No bootstrapping)**: 251, 429, 661 microseconds
* **Time (Bootstrapping)**: 18, 37, 56 seconds
* **Capacity**: 1 NOR operation across the vector without bootstrapping

## XNOR
* **Input**: 8, 16, 32 bits vectors
* **Time (No bootstrapping)**: 250, 497, 759 microseconds
* **Time (Bootstrapping)**:  15, 39, 57 seconds
* **Capacity**: 1 XNOR operation across the vector without bootstrapping

## 8-bit Two Consecutive Gates
* a_bits = [true, true, false, true, true, true, false, false]
* b_bits = [true, false, true, false, true, true, true, false]
* c_bits = [true, true,  true, true,  true, true, true, true ]

* and; and -> FAILED 
  * Decrypted result: [true, false, false, false, true, true, false, false]
  * Solution        : [true, false, false, false, true, true, false, false]

* and; or -> FAILED 
  * Decrypted result: [true, true, true, true, true, true, true, false]
  * Solution        : [true, true, true, true, true, true, true, true]

* and; xor -> FAILED 
  * Decrypted result: [false, true, true, true, false, false, true, false]
  * Solution        : [false, true, true, true, false, false, true, true]

* and; nand -> FAILED 
  * Decrypted result: [false, true, true, true, false, false, true, true]
  * Solution        : [false, true, true, true, false, false, true, true]

* and; nor -> FAILED 
  * Decrypted result: [false, false, false, false, false, false, false, true]
  * Solution        : [false, false, false, false, false, false, false, false]

* and; xnor -> FAILED 
  * Decrypted result: [true, false, false, false, true, true, false, true]
  * Solution        : [true, false, false, false, true, true, false, false]

* or; and -> FAILED 
  * Decrypted result: [true, true, true, true, true, true, true, false]
  * Solution        : [true, true, true, true, true, true, true, false]

* or; or -> FAILED 
  * Decrypted result: [false, true, true, true, false, false, true, true]
  * Solution        : [true, true, true, true, true, true, true, true]

* or; xor -> FAILED 
  * Decrypted result: [true, false, false, false, true, true, false, true]
  * Solution        : [false, false, false, false, false, false, false, true]

* or; nand -> FAILED 
  * Decrypted result: [false, false, false, false, false, false, false, true]
  * Solution        : [false, false, false, false, false, false, false, true]

* or; nor -> FAILED 
  * Decrypted result: [true, false, false, false, true, true, false, false]
  * Solution        : [false, false, false, false, false, false, false, false]

* or; xnor -> FAILED
  * Decrypted result: [false, true, true, true, false, false, true, false]
  * Solution        : [true, true, true, true, true, true, true, false]

* xor; and -> FAILED 
  * Decrypted result: [false, true, true, true, false, false, true, false]
  * Solution        : [false, true, true, true, false, false, true, false]

* xor; or -> FAILED 
  * Decrypted result: [false, false, false, true, true, true, true, false]
  * Solution        : [true, true, true, true, true, true, true, true]

* xor; xor -> FAILED 
  * Decrypted result: [false, true, true, false, true, true, false, false]
  * Solution        : [true, false, false, false, true, true, false, true]

* xor; nand -> FAILED 
  * Decrypted result: [true, false, false, false, true, true, false, true]
  * Solution        : [true, false, false, false, true, true, false, true]

* xor; nor -> FAILED
  * Decrypted result: [true, true, true, false, false, false, false, true]
  * Solution        : [false, false, false, false, false, false, false, false]

* xor; xnor -> FAILED
  * Decrypted result: [true, false, false, true, false, false, true, true]
  * Solution        : [false, true, true, true, false, false, true, false]

* nand; and -> FAILED
  * Decrypted result: [false, true, true, true, false, false, true, true]
  * Solution        : [false, true, true, true, false, false, true, true]

* nand; or -> FAILED
  * Decrypted result: [true, true, true, true, true, true, true, false]
  * Solution        : [true, true, true, true, true, true, true, true]

* nand; xor -> FAILED
  * Decrypted result: [true, false, false, false, true, true, false, true]
  * Solution        : [true, false, false, false, true, true, false, false]

* nand; nand -> FAILED
  * Decrypted result: [true, false, false, false, true, true, false, false]
  * Solution        : [true, false, false, false, true, true, false, false]

* nand; nor -> FAILED
  * Decrypted result: [false, false, false, false, false, false, false, true]
  * Solution        : [false, false, false, false, false, false, false, false]

* nand; xnor -> FAILED
  * Decrypted result: [false, true, true, true, false, false, true, false]
  * Solution        : [false, true, true, true, false, false, true, true]

* nor; and -> FAILED
  * Decrypted result: [false, false, false, false, false, false, false, true]
  * Solution        : [false, false, false, false, false, false, false, true]

* nor; or -> FAILED
  * Decrypted result: [false, true, true, true, false, false, true, true]
  * Solution        : [true, true, true, true, true, true, true, true]

* nor; xor -> FAILED
  * Decrypted result: [true, false, false, false, true, true, false, true]
  * Solution        : [true, true, true, true, true, true, true, false]

* nor; nand -> FAILED
  * Decrypted result: [true, true, true, true, true, true, true, false]
  * Solution        : [true, true, true, true, true, true, true, false]

* nor; nor -> FAILED
  * Decrypted result: [true, false, false, false, true, true, false, false]
  * Solution        : [false, false, false, false, false, false, false, false]

* nor; xnor -> FAILED
  * Decrypted result: [true, false, false, false, true, true, false, true]
  * Solution        : [false, false, false, false, false, false, false, true]

* xnor; and -> FAILED
  * Decrypted result: [true, false, false, false, true, true, false, true]
  * Solution        : [true, false, false, false, true, true, false, true]

* xnor; or -> FAILED
  * Decrypted result: [false, false, false, false, true, true, true, false]
  * Solution        : [true, true, true, true, true, true, true, true]

* xnor; xor -> FAILED
  * Decrypted result: [true, false, false, false, false, false, true, true]
  * Solution        : [false, true, true, true, false, false, true, false]

* xnor; nand -> FAILED
  * Decrypted result: [false, true, true, true, false, false, true, false]
  * Solution        : [false, true, true, true, false, false, true, false]

* xnor; nor -> FAILED
  * Decrypted result: [true, true, true, true, false, false, false, true]
  * Solution        : [false, false, false, false, false, false, false, false]

* xnor; xnor -> FAILED
  * Decrypted result: [false, true, true, true, true, true, false, false]
  * Solution        : [true, false, false, false, true, true, false, true]

## 7-bit Two Consecutive Gates
* and; and --> OK
  * Decrypted result: [false, false, false, false, false, false, false]
  * Solution        : [false, false, false, false, false, false, false]

* and; or --> OK
  * Decrypted result: [true, false, false, false, true, true, false]
  * Solution        : [true, false, false, false, true, true, false]

* and; xor --> OK
  * Decrypted result: [true, false, false, false, true, true, false]
  * Solution        : [true, false, false, false, true, true, false]

* and; nand --> OK
  * Decrypted result: [true, true, true, true, true, true, true]
  * Solution        : [true, true, true, true, true, true, true]

* and; nor --> OK
  * Decrypted result: [false, true, true, true, false, false, true]
  * Solution        : [false, true, true, true, false, false, true]

* and; xnor --> OK
  * Decrypted result: [false, true, true, true, false, false, true]
  * Solution        : [false, true, true, true, false, false, true]

* or; and --> FAILED
  * Decrypted result: [true, false, false, false, true, true, false]
  * Solution        : [false, false, false, false, false, false, false]

* or; or --> FAILED
  * Decrypted result: [true, true, true, true, true, true, true]
  * Solution        : [true, true, true, true, true, true, true]

* or; xor --> FAILED
  * Decrypted result: [false, true, true, true, false, false, true]
  * Solution        : [true, true, true, true, true, true, true]

* or; nand --> FAILED
  * Decrypted result: [false, true, true, true, false, false, true]
  * Solution        : [true, true, true, true, true, true, true]

* or; nor --> FAILED
  * Decrypted result: [false, false, false, false, false, false, false]
  * Solution        : [false, false, false, false, false, false, false]

* or; xnor --> FAILED
  * Decrypted result: [true, false, false, false, true, true, false]
  * Solution        : [false, false, false, false, false, false, false]

* xor; and --> FAILED
  * Decrypted result: [false, true, false, false, false, false, false]
  * Solution        : [false, false, false, false, false, false, false]

* xor; or --> FAILED
  * Decrypted result: [false, true, true, true, false, false, true]
  * Solution        : [false, true, true, true, false, false, true]

* xor; xor --> FAILED
  * Decrypted result: [false, false, true, true, false, false, true]
  * Solution        : [false, true, true, true, false, false, true]

* xor; nand --> FAILED
  * Decrypted result: [true, false, true, true, true, true, true]
  * Solution        : [true, true, true, true, true, true, true]

* xor; nor --> FAILED
  * Decrypted result: [true, false, false, false, true, true, false]
  * Solution        : [true, false, false, false, true, true, false]

* xor; xnor --> FAILED
  * Decrypted result: [true, true, false, false, true, true, false]
  * Solution        : [true, false, false, false, true, true, false]

* nand; and --> OK
  * Decrypted result: [false, false, false, false, false, false, false]
  * Solution        : [false, false, false, false, false, false, false]

* nand; or --> OK
  * Decrypted result: [false, true, true, true, false, false, true]
  * Solution        : [false, true, true, true, false, false, true]

* nand; xor --> OK
  * Decrypted result: [false, true, true, true, false, false, true]
  * Solution        : [false, true, true, true, false, false, true]

* nand; nand --> OK
  * Decrypted result: [true, true, true, true, true, true, true]
  * Solution        : [true, true, true, true, true, true, true]

* nand; nor --> OK
  * Decrypted result: [true, false, false, false, true, true, false]
  * Solution        : [true, false, false, false, true, true, false]

* nand; xnor --> OK
  * Decrypted result: [true, false, false, false, true, true, false]
  * Solution        : [true, false, false, false, true, true, false]

* nor; and --> FAILED
  * Decrypted result: [true, false, false, false, true, true, false]
  * Solution        : [false, false, false, false, false, false, false]

* nor; or --> FAILED
  * Decrypted result: [false, false, false, false, false, false, false]
  * Solution        : [false, false, false, false, false, false, false]

* nor; xor --> FAILED
  * Decrypted result: [true, false, false, false, true, true, false]
  * Solution        : [false, false, false, false, false, false, false]

* nor; nand --> FAILED
  * Decrypted result: [false, true, true, true, false, false, true]
  * Solution        : [true, true, true, true, true, true, true]

* nor; nor --> FAILED
  * Decrypted result: [true, true, true, true, true, true, true]
  * Solution        : [true, true, true, true, true, true, true]

* nor; xnor --> FAILED
  * Decrypted result: [false, true, true, true, false, false, true]
  * Solution        : [true, true, true, true, true, true, true]

* xnor; and --> FAILED
  * Decrypted result: [false, false, false, false, false, true, false]
  * Solution        : [false, false, false, false, false, false, false]

* xnor; or --> FAILED
  * Decrypted result: [true, false, false, false, true, true, false]
  * Solution        : [true, false, false, false, true, true, false]

* xnor; xor --> FAILED
  * Decrypted result: [true, false, false, false, true, false, false]
  * Solution        : [true, false, false, false, true, true, false]

* xnor; nand --> FAILED
  * Decrypted result: [true, true, true, true, true, false, true]
  * Solution        : [true, true, true, true, true, true, true]

* xnor; nor --> FAILED
  * Decrypted result: [false, true, true, true, false, false, true]
  * Solution        : [false, true, true, true, false, false, true]

* xnor; xnor --> FAILED
  * Decrypted result: [false, true, true, true, false, true, true]
  * Solution        : [false, true, true, true, false, false, true]


**Conclusion**
We can only perform one gate operation and recover the result without bootstrapping. Any subsequent 
operation on the ciphertext without bootstrapping is likely to be corrupted. 

ptxt1 [1, 2, 2, 3, 3, 0, 0, 0]
ptxt2 [3, 0, 1, 3, 3, 1, 0, 0]
resul [0, 3, 3, 2, 3, 2, 0, 0]