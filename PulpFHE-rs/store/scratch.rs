fn adder(&self, sk: &Key, a: &[bool], b: &[bool], result: &mut [bool]) {
    let size: usize = a.len();

    let mut carry: Vec<bool> = vec![false; size + 1];
    let mut temp: Vec<T> = vec![false; size];

    //initialize the first carry to 0
    carry[0] = false;

    self.e_xor(sk, a, b, &mut temp);

    for i in 0..size {
        result[i] = self.e_xor(sk, &carry[i], &temp[i]);
        carry[i + 1] = self.e_mux(sk, &temp[i], &carry[i], &a[i]);
    }
}
