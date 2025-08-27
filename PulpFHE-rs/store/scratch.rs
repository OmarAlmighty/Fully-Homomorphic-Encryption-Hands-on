fn subtracter(
    &self,
    sk: &ServerKey,
    a: &[Ciphertext],
    b: &[Ciphertext],
    result: &mut [Ciphertext],
) {
    let size: usize = a.len();

    let mut borrow: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); size];;
    let mut temp_0: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); size];;
    let mut temp_1: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); size];;
    let mut temp_2: Vec<Ciphertext> = vec![Ciphertext::Trivial(false); size];;

    // Run half subtracter
    result[0] = self.e_xor_bit(sk, &a[0], &b[0]);
    temp_0[0] = self.e_not_bit(sk, &a[0]);
    borrow[0] = self.e_and_bit(sk, &temp_0[0], &b[0]);

    self.e_xor_range(sk, &a, &b, &mut temp_0, 1, size);
    self.e_not_range(sk, &a, &mut temp_1, 1, size);

    for i in 1..size {
        // Calculate the difference
        result[i] = self.e_xor_bit(sk, &temp_0[i], &borrow[i - 1]);

        if i != size - 1 {
            temp_2[i] = self.e_and_bit(sk, &temp_1[i], &b[i]);
            temp_0[i] = self.e_not_bit(sk, &temp_0[i]);
            temp_1[i] = self.e_and_bit(sk, &borrow[i - 1], &temp_0[i]);
            borrow[i] = self.e_or_bit(sk, &temp_2[i], &temp_1[i]);
        }
    }
}

fn subtracter(a: &[bool], b: &[bool], result: &mut [bool]) {
    let size: usize = a.len();
    let mut borrow: Vec<bool> = vec![false; size];
    let mut temp_0: Vec<bool> = vec![false; size];
    let mut temp_1: Vec<bool> = vec![false; size];
    let mut temp_2: Vec<bool> = vec![false; size];

    // Run half subtracter
    result[0] = xor_bit(a[0], b[0]);
    temp_0[0] = not_bit(a[0]);
    borrow[0] = and_bit(temp_0[0], b[0]);

    xor_range(a, &b, &mut temp_0, 1, size);
    not_range(a, &mut temp_1, 1, size);

    for i in 1..size {
        // Calculate the difference
        result[i] = xor_bit(temp_0[i], borrow[i - 1]);
        if i != size - 1 {
            temp_2[i] = and_bit(temp_1[i], b[i]);
            temp_0[i] = not_bit(temp_0[i]);
            temp_1[i] = and_bit(borrow[i - 1], temp_0[i]);
            borrow[i] = or_bit(temp_2[i], temp_1[i]);
        }
    }
}
