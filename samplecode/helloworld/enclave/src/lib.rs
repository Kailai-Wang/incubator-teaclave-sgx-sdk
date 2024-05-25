// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License..

#![crate_name = "helloworldsampleenclave"]
#![crate_type = "staticlib"]
#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]

extern crate sgx_types;
extern crate k256;
extern crate musig2;

#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;
use sgx_types::*;
use std::io::{self, Write};
use std::slice;
use std::string::String;
use std::vec::Vec;

use k256::schnorr::SigningKey;
use k256::PublicKey;
use musig2::KeyAggContext;
use std::vec;

fn my_priv_key() -> SigningKey {
    SigningKey::from_bytes(&[
        252, 240, 35, 85, 243, 83, 129, 54, 7, 155, 24, 114, 254, 0, 134, 251, 207, 83, 177, 9, 92,
        118, 222, 5, 202, 239, 188, 215, 132, 113, 127, 94,
    ])
    .unwrap()
}

fn signer1_priv_key() -> SigningKey {
    SigningKey::from_bytes(&[
        42, 82, 57, 169, 208, 130, 125, 141, 62, 185, 167, 41, 142, 217, 252, 135, 158, 128, 44,
        129, 222, 71, 55, 86, 230, 183, 54, 111, 152, 83, 85, 155,
    ])
    .unwrap()
}

fn signer2_priv_key() -> SigningKey {
    SigningKey::from_bytes(&[
        117, 130, 176, 36, 185, 53, 187, 61, 123, 86, 24, 38, 174, 143, 129, 73, 245, 210, 127,
        148, 115, 136, 32, 98, 62, 47, 26, 196, 57, 211, 171, 185,
    ])
    .unwrap()
}

// use sha2::Digest as _;
// use sha2_v08_wrapper::Digest as _;

// fn sha2_v10() -> sha2::Sha256 {
//     sha2::Sha256::new()
//         .chain_update(b"hello world")
//         .chain_update(b"hello world")
// }

// fn sha2_v8() -> sha2_v08_wrapper::Sha256 {
//     let mut hasher = sha2_v08_wrapper::Sha256::new();
//     hasher.input(b"hello world");
//     hasher.input(b"hello world");
//     hasher
// }

/// A function simply invokes ocall print to print the incoming string
///
/// # Parameters
///
/// **some_string**
///
/// A pointer to the string to be printed
///
/// **len**
///
/// An unsigned int indicates the length of str
///
/// # Return value
///
/// Always returns SGX_SUCCESS
#[no_mangle]
pub extern "C" fn say_something(some_string: *const u8, some_len: usize) -> sgx_status_t {
    println!("entering say_something");

    let pubkeys: Vec<PublicKey> = vec![
        PublicKey::from(my_priv_key().verifying_key()),
        PublicKey::from(signer1_priv_key().verifying_key()),
        PublicKey::from(signer2_priv_key().verifying_key()),
    ];

    println!("before calling Context::new");

    let _ = KeyAggContext::new(pubkeys).unwrap();

    // let a = sha2_v10().finalize();
    // let b = sha2_v8().result();
    // assert_eq!(a.to_vec(), b.to_vec());

    // println!("assert passed");

    let str_slice = unsafe { slice::from_raw_parts(some_string, some_len) };
    let _ = io::stdout().write(str_slice);

    // A sample &'static string
    let rust_raw_string = "This is a ";
    // An array
    let word: [u8; 4] = [82, 117, 115, 116];
    // An vector
    let word_vec: Vec<u8> = vec![32, 115, 116, 114, 105, 110, 103, 33];

    // Construct a string from &'static string
    let mut hello_string = String::from(rust_raw_string);

    // Iterate on word array
    for c in word.iter() {
        hello_string.push(*c as char);
    }

    // Rust style convertion
    hello_string += String::from_utf8(word_vec).expect("Invalid UTF-8").as_str();

    // Ocall to normal world for output
    println!("{}", &hello_string);

    sgx_status_t::SGX_SUCCESS
}
