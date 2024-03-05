/*
    Copyright Hyperledger. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
pub const SUPERSCRIPT_DIGITS: [&str; 10] = ["⁰", "¹", "²", "³", "⁴", "⁵", "⁶", "⁷", "⁸", "⁹"];

pub fn to_super_script_digits(n: usize) -> String {
    n.to_string()
        .chars()
        .map(|c| SUPERSCRIPT_DIGITS[c.to_digit(10).expect("a base 10 digit") as usize])
        .collect()
}
