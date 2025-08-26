 fn rotl(&self, a: &[T], rot_amt: usize, result: &mut [T]) {
        let size: usize = a.len();
        let mut temp: Vec<T> = vec![T::Trivial(false); size];

        for (r, q) in result.iter_mut().zip(a.iter()) {
            r.clone_from(q);
        }

        for i in 0..rot_amt {
            let msb: T = result[size - 1].clone();
            for j in 1..size {
                temp[j].clone_from(&result[j - 1]);
            }
            temp[0].clone_from(&msb);

            for (r, q) in result.iter_mut().zip(temp.iter()) {
                r.clone_from(q);
            }
        }
    }