use std::fs::{self, File};
use std::io::{self, prelude::*};

fn main() {
    let mut args = std::env::args().skip(1);
    let arg1 = args.next().unwrap_or_else(|| help());
    let passkey = args.next().unwrap_or_else(|| help());
    let (k, n) = hash(passkey);
    let (input, mut output) = if arg1 != "-" {
        let path = fs::canonicalize(arg1).expect("could not canonicalize argument");

        let src = io::BufReader::new(File::open(&path).expect("could not read file"))
            .bytes()
            .map(Result::unwrap);

        let dest = fs::OpenOptions::new()
            .write(true)
            .open(path)
            .expect("could not open destination file for writing");
        (src, dest)
    } else {
        print!("> ");
        let mut stdout = io::stdout().lock();
        stdout.flush().unwrap();
        for line in io::stdin().lines().map(Result::unwrap) {
            let mut v: Vec<u8> = Vec::new();
            let mut it = line.into_bytes();
            let d = match it.get(0) {
                Some(b'e') => false,
                Some(b'd') => true,
                Some(b'q') => break,
                _ => continue,
            };
            if d {
                it = base94::decode(&it[1..]);
            } else {
                it.remove(0);
            }
            State::new(k, n).chacha20(it.into_iter(), &mut v);
            if !d {
                v = base94::encode(&v);
            }
            stdout.write_all(&v).unwrap();
            stdout.write_all(b"\n> ").unwrap();
            stdout.flush().unwrap();
        }
        std::process::exit(0);
    };

    State::new(k, n).chacha20(input, &mut output);
    /*
        println!(
            "{:x?}",
            State::new(
                [
                    0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c, 0x13121110, 0x17161514, 0x1b1a1918,
                    0x1f1e1d1c
                ],
                [0x09000000, 0x4a000000, 0x00000000]
            )
            .chacha20_block()
        );
    */
}

fn hash(passkey: String) -> ([u32; 8], [u32; 3]) {
    let mut res = [0; 16];

    res[0..4].copy_from_slice(&K);
    res[0..4].copy_from_slice(&K);
    res[0..4].copy_from_slice(&K);
    res[0..4].copy_from_slice(&K);

    for _ in 0..10 {
        inner_block(&mut res);
    }

    for c in passkey.as_bytes().chunks(4) {
        let mut b = 0;
        for i in 0..4 {
            b = b << 8 | c[i % c.len()] as u32;
        }
        res[b as usize % 16] ^= b;
        for _ in 0..10 {
            inner_block(&mut res);
        }
    }

    (res[..8].try_into().unwrap(), res[13..].try_into().unwrap())
}

fn help() -> ! {
    println!(
        "usage: {} <filename> <passkey>",
        std::env::current_exe()
            .unwrap_or_else(|_| "enc".into())
            .display()
    );
    std::process::exit(-1);
}

fn qr(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(12);
    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(7);
}

fn inner_block(state: &mut [u32; 16]) {
    qr(state, 0, 4, 8, 12);
    qr(state, 1, 5, 9, 13);
    qr(state, 2, 6, 10, 14);
    qr(state, 3, 7, 11, 15);
    qr(state, 0, 5, 10, 15);
    qr(state, 1, 6, 11, 12);
    qr(state, 2, 7, 8, 13);
    qr(state, 3, 4, 9, 14);
}

struct State {
    prev: [u32; 16],
    counter: u32,
}

const K: [u32; 4] = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];

impl State {
    fn new(key: [u32; 8], nonce: [u32; 3]) -> Self {
        let mut prev = [0; 16];
        prev[..4].copy_from_slice(&K);
        prev[4..12].copy_from_slice(&key);
        prev[13..].copy_from_slice(&nonce);

        Self { prev, counter: 1 }
    }

    fn chacha20_block(&mut self) -> [u8; 64] {
        self.prev[12] = self.counter;
        let mut working_state = self.prev;

        for _ in 0..10 {
            inner_block(&mut working_state);
        }

        self.prev
            .iter_mut()
            .zip(working_state.iter())
            .for_each(|(a, b)| *a = a.wrapping_add(*b));

        self.counter += 1;

        let mut res = [0; 64];

        for (i, x) in self.prev.iter().map(|i| i.to_le_bytes()).enumerate() {
            res[i * 4..i * 4 + 4].copy_from_slice(&x)
        }

        res
    }

    fn chacha20(&mut self, input: impl Iterator<Item = u8>, output: &mut impl Write) {
        let mut block = self.chacha20_block();
        let mut len = 0;

        for i in input {
            if len == 64 {
                output.write_all(&block).unwrap();
                len = 0;
                block = self.chacha20_block();
            }

            block[len] ^= i;
            len += 1;
        }
        output.write_all(&block[..len]).unwrap();
        output.flush().unwrap();
    }
}
