use std::mem;
use md5::{Digest, Md5};

pub fn get_md5(content: &[u8]) -> String {
    let mut hasher = Md5::new();
    hasher.update(content);
    let result = hasher.finalize();
    format!("{:x}", (&result)) //不能加分号。加了是语句，不加是返回
}

fn fmix32(mut h: u32) -> u32 {
    h ^= h >> 16;
    h = h.wrapping_mul(0x85ebca6b);
    h ^= h >> 13;
    h = h.wrapping_mul(0xc2b2ae35);
    h ^= h >> 16;

    return h;
}

fn get_32_block(bytes: &[u8], index: usize) -> u32 {
    let b32: &[u32] = unsafe { mem::transmute(bytes) };
    return b32[index];
}

pub fn murmurhash3_x86_32(bytes: &[u8], seed: u32) -> i32 {
    let c1 = 0xcc9e2d51u32;
    let c2 = 0x1b873593u32;
    let read_size = 4;
    let len = bytes.len() as u32;
    let block_count = len / read_size;

    let mut h1 = seed;

    for i in 0..block_count as usize {
        let mut k1 = get_32_block(bytes, i);

        k1 = k1.wrapping_mul(c1);
        k1 = k1.rotate_left(15);
        k1 = k1.wrapping_mul(c2);

        h1 ^= k1;
        h1 = h1.rotate_left(13);
        h1 = h1.wrapping_mul(5);
        h1 = h1.wrapping_add(0xe6546b64)
    }
    let mut k1 = 0u32;

    if len & 3 == 3 {
        k1 ^= (bytes[(block_count * read_size) as usize + 2] as u32) << 16;
    }
    if len & 3 >= 2 {
        k1 ^= (bytes[(block_count * read_size) as usize + 1] as u32) << 8;
    }
    if len & 3 >= 1 {
        k1 ^= bytes[(block_count * read_size) as usize + 0] as u32;
        k1 = k1.wrapping_mul(c1);
        k1 = k1.rotate_left(15);
        k1 = k1.wrapping_mul(c2);
        h1 ^= k1;
    }

    h1 ^= bytes.len() as u32;
    h1 = fmix32(h1);
    if h1 & 0x80000000 == 0 {
        return h1 as i32;
    } else {
        return -(((h1 ^ 0xFFFFFFFF) + 1) as i32);
    }
}