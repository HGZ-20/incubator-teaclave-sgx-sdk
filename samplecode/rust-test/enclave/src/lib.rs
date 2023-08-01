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

#![crate_name = "cryptosampleenclave"]
#![crate_type = "staticlib"]

#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]

#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;
extern crate sgx_rand;
extern crate sgx_rand_derive;
extern crate sgx_serialize;

#[macro_use]
extern crate sgx_serialize_derive;

// #[macro_use]
// extern crate serde_derive;
// extern crate serde_cbor;

extern crate sgx_types;
extern crate sgx_tseal;
extern crate sgx_tcrypto;
extern crate sgx_trts;
extern crate sgx_tse;

extern crate rustls;
extern crate webpki;
extern crate webpki_roots;
extern crate itertools;
extern crate base64;
extern crate httparse;
extern crate yasna;
extern crate bit_vec;
extern crate num_bigint;
extern crate chrono;

use std::sgxfs::SgxFile;
use std::io::{Read, Write};

use sgx_serialize::{SerializeHelper, DeSerializeHelper};

use std::prelude::v1::*;
use std::time::*;

use sgx_types::*;
use sgx_tcrypto::*;
// use sgx_tse::*;
use std::time::SystemTime;
use std::untrusted::time::SystemTimeEx;
use std::str;
use std::vec::Vec;
use std::convert::TryInto;
use std::string::String;

use num_bigint::BigUint;
use bit_vec::BitVec;
use yasna::models::ObjectIdentifier;
use chrono::Duration;
use chrono::TimeZone;
use chrono::Utc as TzUtc;

const CERTEXPIRYDAYS: i64 = 90i64;
const ISSUER : &str = "MesaTEE";
const SUBJECT : &str = "MesaTEE";

#[derive(Serializable, DeSerializable, Clone, Default, Debug)]
struct RSAKeyData {
    modulus: Vec<u8>,
    d: Vec<u8>,
    e: Vec<u8>,
    not_befer: time_t,
    not_after: time_t,
}

const RSA_DURATION: u64 = 604800;

fn write_file(path_str: *const u8, len: usize) -> sgx_status_t {
    let path_slice = unsafe {std::slice::from_raw_parts(path_str, len)};
    
    if path_slice.len() != len {
        println!("The file path length does not match the length parameter.");
        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
    }

    let path_str = str::from_utf8(path_slice).unwrap();

    let (rsa3072_key, sgx_status) = get_rsa_key();
    
    match sgx_status {
        sgx_status_t::SGX_SUCCESS => {},
        _ => return sgx_status,
    };
    let rsa3072_key = rsa3072_key.unwrap();

    let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
    let rsa_key_data = RSAKeyData {
        modulus: rsa3072_key.modulus.clone().try_into().unwrap(),
        d: rsa3072_key.d.clone().try_into().unwrap(),
        e: rsa3072_key.e.clone().try_into().unwrap(),
        not_befer: now as time_t,
        not_after: (now + RSA_DURATION) as time_t,
    };

    let helper = SerializeHelper::new();
    let rsa_key_bytes = match helper.encode(rsa_key_data) {
        Some(d) => d,
        None => {
            println!("encode data failed.");
            return sgx_status_t::SGX_ERROR_UNEXPECTED;
        },
    };

    let mut file = match SgxFile::create(path_str) {
        Ok(f) => f,
        Err(_) => {
            println!("SgxFile::create failed.");
            return sgx_status_t::SGX_ERROR_FILE_CANT_OPEN_RECOVERY_FILE;
        },
    };

    let write_size = match file.write(rsa_key_bytes.as_slice()) {
        Ok(len) => len,
        Err(_) => {
            println!("SgxFile::write failed.");
            return sgx_status_t::SGX_ERROR_FILE_CANT_OPEN_RECOVERY_FILE;
        },
    };

    println!("write file success, write size: {}.", write_size);
    sgx_status_t::SGX_SUCCESS
}

fn read_file(path_str: *const u8, len: usize) -> sgx_status_t {

    let path_slice = unsafe {std::slice::from_raw_parts(path_str, len)};
    
    if path_slice.len() != len {
        println!("The file path length does not match the length parameter.");
        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
    }

    let path_str = str::from_utf8(path_slice).unwrap();

    let mut file = match SgxFile::open(path_str) {
        Ok(f) => f,
        Err(_) => {
            println!("SgxFile::open failed.");
            return sgx_status_t::SGX_ERROR_FILE_CANT_OPEN_RECOVERY_FILE;
        },
    };

    let mut data = Vec::with_capacity(1000);

    let read_size = match file.read_to_end(&mut data) {
        Ok(len) => len,
        Err(_) => {
            println!("SgxFile::read failed.");
            return sgx_status_t::SGX_ERROR_FILE_BAD_STATUS;
        },
    };

    let helper = DeSerializeHelper::<RSAKeyData>::new(data);
    let rsa_key_data = match helper.decode() {
        Some(d) => d,
        None => {
            println!("decode data failed.");
            return sgx_status_t::SGX_ERROR_UNEXPECTED;
        },
    };

    println!("read file success, read size: {}, {:?}.", read_size, rsa_key_data);
    sgx_status_t::SGX_SUCCESS
}

fn get_rsa_key() -> (Option<sgx_rsa3072_key_t>, sgx_status_t) {

    let mut n: Vec<u8> = vec![0_u8; SGX_RSA3072_KEY_SIZE];
    let mut d: Vec<u8> = vec![0_u8; SGX_RSA3072_KEY_SIZE];
    let mut e: Vec<u8> = vec![1, 0, 1, 0];
    let mut p: Vec<u8> = vec![0_u8; SGX_RSA3072_KEY_SIZE / 2];
    let mut q: Vec<u8> = vec![0_u8; SGX_RSA3072_KEY_SIZE / 2];
    let mut dmp1: Vec<u8> = vec![0_u8; SGX_RSA3072_KEY_SIZE / 2];
    let mut dmq1: Vec<u8> = vec![0_u8; SGX_RSA3072_KEY_SIZE / 2];
    let mut iqmp: Vec<u8> = vec![0_u8; SGX_RSA3072_KEY_SIZE / 2];

    let result = rsgx_create_rsa_key_pair(SGX_RSA3072_KEY_SIZE as i32,
                                          SGX_RSA3072_PUB_EXP_SIZE as i32,
                                          n.as_mut_slice(),
                                          d.as_mut_slice(),
                                          e.as_mut_slice(),
                                          p.as_mut_slice(),
                                          q.as_mut_slice(),
                                          dmp1.as_mut_slice(),
                                          dmq1.as_mut_slice(),
                                          iqmp.as_mut_slice());

    match result {
        Err(x) => {
            return (None, x);
        },
        Ok(()) => {},
    };
    
    let rsa3072_key = sgx_rsa3072_key_t {
        modulus: n.clone().try_into().unwrap(),
        d: d.clone().try_into().unwrap(),
        e: e.clone().try_into().unwrap(),
    };

    let rsa3072_public_key = sgx_rsa3072_public_key_t {
        modulus: n.clone().try_into().unwrap(),
        exponent: e.clone().try_into().unwrap(),
    };


    let msg = String::from("Hello world!");
    let msg_bytes = msg.as_bytes();

    let signature =  rsgx_rsa3072_sign_slice(msg_bytes, &rsa3072_key).expect("sign error");

    match rsgx_rsa3072_verify_slice(msg_bytes, &rsa3072_public_key, &signature) {
        Ok(x) => {
            if x {
                println!("Good!");
            } else {
                println!("Bad!");
            }
        },
        Err(_) => {
            println!("verify error");
        },
    }

    (Some(rsa3072_key), sgx_status_t::SGX_SUCCESS)
}

fn get_x509_cert(rsa3072_key: Option<sgx_rsa3072_key_t>) -> sgx_status_t {
    let rsa3072_key = rsa3072_key.unwrap();

    // Generate Certificate DER
    let cert_der = yasna::construct_der(|writer| {
        writer.write_sequence(|writer| {
            writer.next().write_sequence(|writer| {
                // Certificate Version
                writer.next().write_tagged(yasna::Tag::context(0), |writer| {
                    writer.write_i8(2);
                });
                // Certificate Serial Number (unused but required)
                writer.next().write_u8(1);
                // Signature Algorithm: rsa-with-SHA256
                writer.next().write_sequence(|writer| {
                    writer.next().write_oid(&ObjectIdentifier::from_slice(&[1,2,840,113549,1,1,11]));
                });
                // Issuer: CN=MesaTEE (unused but required)
                writer.next().write_sequence(|writer| {
                    writer.next().write_set(|writer| {
                        writer.next().write_sequence(|writer| {
                            writer.next().write_oid(&ObjectIdentifier::from_slice(&[2,5,4,3]));
                            writer.next().write_utf8_string(&ISSUER);
                        });
                    });
                });
                // Validity: Issuing/Expiring Time (unused but required)
                let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
                let issue_ts = TzUtc.timestamp(now.as_secs() as i64, 0);
                let expire = now + Duration::days(CERTEXPIRYDAYS).to_std().unwrap();
                let expire_ts = TzUtc.timestamp(expire.as_secs() as i64, 0);
                writer.next().write_sequence(|writer| {
                    writer.next().write_utctime(&yasna::models::UTCTime::from_datetime(&issue_ts));
                    writer.next().write_utctime(&yasna::models::UTCTime::from_datetime(&expire_ts));
                });
                // Subject: CN=MesaTEE (unused but required)
                writer.next().write_sequence(|writer| {
                    writer.next().write_set(|writer| {
                        writer.next().write_sequence(|writer| {
                            writer.next().write_oid(&ObjectIdentifier::from_slice(&[2,5,4,3]));
                            writer.next().write_utf8_string(&SUBJECT);
                        });
                    });
                });
                // SubjectPublicKeyInfo
                writer.next().write_sequence(|writer| {
                    // Public Key Algorithm
                    writer.next().write_sequence(|writer| {
                        // id-rsaPublicKey
                        writer.next().write_oid(&ObjectIdentifier::from_slice(&[1,2,840,113549,1,1,1]));
                        writer.next().write_null();
                    });
                    // RSA Public Key
                    let sig_der = yasna::construct_der(|writer| {
                        writer.write_sequence(|writer| {
                            // modulus
                            writer.next().write_biguint(&BigUint::from_bytes_be(&rsa3072_key.modulus));
                            writer.next().write_biguint(&BigUint::from_bytes_be(&rsa3072_key.e));
                        });
                    });
                    writer.next().write_bitvec(&BitVec::from_bytes(&sig_der));
                });
            });
            // Signature Algorithm: rsa-with-SHA256
            writer.next().write_sequence(|writer| {
                writer.next().write_oid(&ObjectIdentifier::from_slice(&[1,2,840,113549,1,1,11]));
            });
            // Signature
            let sig = {
                let tbs = &writer.buf[4..];
                rsgx_rsa3072_sign_slice(tbs, &rsa3072_key).unwrap().signature
            };
            writer.next().write_bitvec(&BitVec::from_bytes(&sig));
        });
    });

    // Base64 encode
    let pem_content = base64::encode(&cert_der);
  
    // add PEM header and ending
    let pem_content = format!("-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----", pem_content);

    println!("{}", pem_content);
    sgx_status_t::SGX_SUCCESS
}


#[no_mangle]
pub unsafe extern "C" fn test() -> sgx_status_t {
    let path = "RSA_KEY";
    let ptr = path.as_ptr();
    let len = path.len();

    let result = write_file(ptr, len);
    match  result {
        sgx_status_t::SGX_SUCCESS => (),
        _ => return result,
    };

    let result = read_file(ptr, len);
    match  result {
        sgx_status_t::SGX_SUCCESS => (),
        _ => return result,
    };

    let (rsa3072_key, sgx_status) = get_rsa_key();
    
    match sgx_status {
        sgx_status_t::SGX_SUCCESS => {},
        _ => return sgx_status,
    };
    let rsa3072_key = rsa3072_key.unwrap();

    let result = get_x509_cert(Some(rsa3072_key));
    match  result {
        sgx_status_t::SGX_SUCCESS => (),
        _ => return result,
    };

    sgx_status_t::SGX_SUCCESS
}