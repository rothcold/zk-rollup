/// SHA-256 哈希模块，支持 RISC-V 硬件加速
///
/// 该模块实现 NIST FIPS 180-4 标准的 SHA-256 哈希算法。
/// SHA-256 生成固定 256 位（32 字节）哈希值，广泛用于数据完整性验证。

#[allow(dead_code)]
use crate::crypto::riscv_ext::RiscVCryptoExt;

/// SHA-256 处理的块大小（字节）
const SHA256_CHUNK_SIZE: usize = 64;

/// SHA-256 哈希计算器，支持 RISC-V 硬件加速
#[allow(dead_code)]
pub struct Sha256Riscv {
    accelerator: Box<dyn RiscVCryptoExt>,
    state: [u8; 32],
    buffer: Vec<u8>,
    total_len: u64,
}

impl Sha256Riscv {
    /// 创建新的 SHA-256 哈希计算器
    ///
    /// 初始化时设置 SHA-256 的初始哈希值（H0-H7），
    /// 这些是前 8 个素数平方根的小数部分的前 32 位。
    ///
    /// # 初始状态值
    ///
    /// H0 = 0x6a09e667, H1 = 0xbb67ae85, H2 = 0x3c6ef372,
    /// H3 = 0xa54ff53a, H4 = 0x510e527f, H5 = 0x9b05688c,
    /// H6 = 0x1f83d9ab, H7 = 0x5be0cd19
    ///
    /// # 返回
    ///
    /// 新的 `Sha256Riscv` 实例，可用于增量计算哈希
    pub fn new() -> Self {
        Sha256Riscv {
            accelerator: Box::new(crate::crypto::riscv_ext::HardwareAccelerator::new()),
            state: [
                0x6a, 0x09, 0xe6, 0x67, 0xbb, 0x67, 0xae, 0x85, 0x3c, 0x6e, 0xf3, 0x72, 0xa5, 0x4f,
                0xf5, 0x3b, 0x51, 0x0e, 0x52, 0x7f, 0x9b, 0x05, 0x68, 0x8c, 0x1f, 0x83, 0xd9, 0xab,
                0x5b, 0xe0, 0xcd, 0x19,
            ],
            buffer: Vec::new(),
            total_len: 0,
        }
    }

    /// 向哈希计算追加数据
    ///
    /// 支持增量计算哈希，无需一次性加载全部数据。
    /// 当缓冲区累积到 64 字节时，自动处理该消息块。
    ///
    /// # 参数
    ///
    /// * `data` - 要追加到哈希计算的数据，可为任意长度
    ///
    /// # 行为
    ///
    /// - 追加数据到内部缓冲区
    /// - 更新已处理总长度
    /// - 缓冲区满 64 字节时处理消息块
    pub fn update(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
        self.total_len += data.len() as u64;

        while self.buffer.len() >= SHA256_CHUNK_SIZE {
            let chunk = self.buffer[..SHA256_CHUNK_SIZE].to_vec();
            self.buffer.drain(..SHA256_CHUNK_SIZE);
            self.process_chunk(&chunk);
        }
    }

    /// 处理单个 64 字节消息块
    ///
    /// 执行 SHA-256 压缩函数，将消息块与当前状态混合。
    /// 包括消息调度（扩展）和 64 轮压缩操作。
    ///
    /// # 参数
    ///
    /// * `chunk` - 64 字节消息块
    fn process_chunk(&mut self, chunk: &[u8]) {
        let mut w = [0u32; 64];

        for i in 0..16 {
            w[i] = ((chunk[i * 4] as u32) << 24)
                | ((chunk[i * 4 + 1] as u32) << 16)
                | ((chunk[i * 4 + 2] as u32) << 8)
                | (chunk[i * 4 + 3] as u32);
        }

        for i in 16..64 {
            let s0 = Self::rotr(w[i - 15], 7) ^ Self::rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
            let s1 = Self::rotr(w[i - 2], 17) ^ Self::rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 9])
                .wrapping_add(s1);
        }

        let mut a =
            u32::from_be_bytes([self.state[0], self.state[1], self.state[2], self.state[3]]);
        let mut b =
            u32::from_be_bytes([self.state[4], self.state[5], self.state[6], self.state[7]]);
        let mut c =
            u32::from_be_bytes([self.state[8], self.state[9], self.state[10], self.state[11]]);
        let mut d = u32::from_be_bytes([
            self.state[12],
            self.state[13],
            self.state[14],
            self.state[15],
        ]);
        let mut e = u32::from_be_bytes([
            self.state[16],
            self.state[17],
            self.state[18],
            self.state[19],
        ]);
        let mut f = u32::from_be_bytes([
            self.state[20],
            self.state[21],
            self.state[22],
            self.state[23],
        ]);
        let mut g = u32::from_be_bytes([
            self.state[24],
            self.state[25],
            self.state[26],
            self.state[27],
        ]);
        let mut h = u32::from_be_bytes([
            self.state[28],
            self.state[29],
            self.state[30],
            self.state[31],
        ]);

        let k = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
            0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
            0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
            0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
            0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
            0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
            0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
            0xc67178f2,
        ];

        for i in 0..64 {
            let s1 = Self::rotr(e, 6) ^ Self::rotr(e, 11) ^ Self::rotr(e, 25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(k[i])
                .wrapping_add(w[i]);

            let s0 = Self::rotr(a, 2) ^ Self::rotr(a, 13) ^ Self::rotr(a, 22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);

            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        let state_bytes = self.state;
        let mut new_state = [0u8; 32];
        for i in 0..8 {
            let val = match i {
                0 => a.wrapping_add(u32::from_be_bytes([
                    state_bytes[0],
                    state_bytes[1],
                    state_bytes[2],
                    state_bytes[3],
                ])),
                1 => b.wrapping_add(u32::from_be_bytes([
                    state_bytes[4],
                    state_bytes[5],
                    state_bytes[6],
                    state_bytes[7],
                ])),
                2 => c.wrapping_add(u32::from_be_bytes([
                    state_bytes[8],
                    state_bytes[9],
                    state_bytes[10],
                    state_bytes[11],
                ])),
                3 => d.wrapping_add(u32::from_be_bytes([
                    state_bytes[12],
                    state_bytes[13],
                    state_bytes[14],
                    state_bytes[15],
                ])),
                4 => e.wrapping_add(u32::from_be_bytes([
                    state_bytes[16],
                    state_bytes[17],
                    state_bytes[18],
                    state_bytes[19],
                ])),
                5 => f.wrapping_add(u32::from_be_bytes([
                    state_bytes[20],
                    state_bytes[21],
                    state_bytes[22],
                    state_bytes[23],
                ])),
                6 => g.wrapping_add(u32::from_be_bytes([
                    state_bytes[24],
                    state_bytes[25],
                    state_bytes[26],
                    state_bytes[27],
                ])),
                7 => h.wrapping_add(u32::from_be_bytes([
                    state_bytes[28],
                    state_bytes[29],
                    state_bytes[30],
                    state_bytes[31],
                ])),
                _ => 0,
            };
            let bytes = val.to_be_bytes();
            new_state[i * 4..i * 4 + 4].copy_from_slice(&bytes);
        }

        self.state = new_state;
    }

    /// 右旋转操作
    ///
    /// SHA-256 算法中使用的位操作，用于消息调度和压缩函数。
    /// 将 32 位整数循环右移指定位数。
    ///
    /// # 参数
    ///
    /// * `n` - 要旋转的 32 位值
    /// * `r` - 旋转位数（1-31）
    ///
    /// # 返回
    ///
    /// 旋转后的 32 位值
    fn rotr(n: u32, r: usize) -> u32 {
        (n >> r) | (n << (32 - r))
    }

    /// 完成哈希计算并返回结果
    ///
    /// 执行最终填充：追加终止位、长度编码，
    /// 处理剩余缓冲区中的所有数据块。
    ///
    /// # 填充格式
    ///
    /// 1. 追加 0x80 终止位
    /// 2. 追加 0x00 填充位，直到剩余 8 字节用于长度
    /// 3. 追加消息长度（64 位大端序）
    ///
    /// # 返回
    ///
    /// 32 字节哈希值
    pub fn finalize(mut self) -> [u8; 32] {
        let bit_len = self.total_len * 8;

        self.buffer.push(0x80);

        while self.buffer.len() % SHA256_CHUNK_SIZE != SHA256_CHUNK_SIZE - 8 {
            self.buffer.push(0);
        }

        for i in 0..8 {
            self.buffer.push(((bit_len >> (56 - i * 8)) & 0xff) as u8);
        }

        while !self.buffer.is_empty() {
            let chunk = self.buffer[..SHA256_CHUNK_SIZE].to_vec();
            self.buffer.drain(..SHA256_CHUNK_SIZE);
            self.process_chunk(&chunk);
        }

        self.state
    }

    /// 对数据直接计算 SHA-256 哈希
    ///
    /// 便捷函数，适合一次性计算数据的哈希值。
    /// 内部创建新的 `Sha256Riscv` 实例并完成完整计算。
    ///
    /// # 参数
    ///
    /// * `data` - 要计算哈希的数据
    ///
    /// # 返回
    ///
    /// 32 字节哈希值
    pub fn hash(data: &[u8]) -> [u8; 32] {
        let mut hasher = Self::new();
        hasher.update(data);
        hasher.finalize()
    }
}

impl Default for Sha256Riscv {
    fn default() -> Self {
        Self::new()
    }
}
