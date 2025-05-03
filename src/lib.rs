use anchor_lang::prelude::*;
use solana_client::rpc_client::RpcClient;
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    transaction::Transaction,
};
use std::ffi::{c_void, CString};
use std::os::raw::{c_char, c_uchar, c_int};
use std::slice;
use borsh::{BorshSerialize, BorshDeserialize};
use blake3::hash;
use serde::Serialize;

declare_id!("E2oqjMNy7QH5xdighcB8Byvbfvo8hobGHsBC5V4p7pSW");

// --- Data Structures ---

#[derive(BorshSerialize, BorshDeserialize, Clone)]
pub struct MetadataPlaceholder {
    pub dummy: [u8; 57], // Adjust size if needed
}

#[account]
pub struct AmpRecord {
    pub media_hash: [u8; 24],
    pub metadata_hash: [u8; 24],
    pub metadata: MetadataPlaceholder,
    pub tee_signature: [u8; 64],
    pub tee_public_key: [u8; 32],
    pub developer_signature: [u8; 64],
    pub certificate_id: [u8; 16],
    pub media_ref: [u8; 46],
    pub commit_time: u32,
    pub owner: Pubkey,
    pub bump: u8,
}

#[derive(BorshSerialize, BorshDeserialize, Serialize)]
pub struct Metadata {
    pub protocol_version: [u8; 4],
    pub session_id: [u8; 16],
    pub timestamp: u32,
    pub lat: Option<f32>,
    pub lon: Option<f32>,
    pub fuzzed: u8,
    pub fuzz_radius: Option<f32>,
    pub device: [u8; 16],
    pub flags: u8,
}

#[repr(C)]
pub struct SerializeResult {
    pub data_ptr: *mut u8,
    pub data_len: usize,
    pub hash_ptr: *mut u8,
    pub hash_len: usize,
}

// --- Error Handling ---

#[derive(Debug)]
pub enum FfiError {
    InvalidKeypair,
    InvalidInput(String),
    SolanaClientError(solana_client::client_error::ClientError),
}

impl std::fmt::Display for FfiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FfiError::InvalidKeypair => write!(f, "Invalid keypair"),
            FfiError::InvalidInput(msg) => write!(f, "Invalid input data: {}", msg),
            FfiError::SolanaClientError(e) => write!(f, "Solana client error: {}", e),
        }
    }
}

impl std::error::Error for FfiError {}

impl From<solana_client::client_error::ClientError> for FfiError {
    fn from(err: solana_client::client_error::ClientError) -> Self {
        FfiError::SolanaClientError(err)
    }
}

// --- Constants ---

const EXPECTED_KEYPAIR_LEN: i32 = 64;
const EXPECTED_MEDIA_HASH_LEN: usize = 24;
const EXPECTED_METADATA_HASH_LEN: usize = 24;
const EXPECTED_METADATA_LEN: usize = 57;
const EXPECTED_TEE_SIGNATURE_LEN: usize = 64;
const EXPECTED_TEE_PUBLIC_KEY_LEN: usize = 32;
const EXPECTED_DEVELOPER_SIGNATURE_LEN: usize = 64;
const EXPECTED_CERTIFICATE_ID_LEN: usize = 16;
const EXPECTED_MEDIA_REF_LEN: usize = 46;

// --- FFI Functions ---

#[no_mangle]
pub extern "C" fn send_add_record(
    keypair_bytes: *const c_uchar,
    keypair_len: c_int,
    media_hash: *const c_uchar,
    metadata_bytes: *const c_uchar,
    metadata_len: c_int,
    metadata_hash: *const c_uchar,
    tee_signature: *const c_uchar,
    tee_public_key: *const c_uchar,
    developer_signature: *const c_uchar,
    certificate_id: *const c_uchar,
    media_ref: *const c_uchar,
    commit_time: u32,
) -> *mut c_char {
    match try_send_add_record(
        keypair_bytes,
        keypair_len,
        media_hash,
        metadata_bytes,
        metadata_len,
        metadata_hash,
        tee_signature,
        tee_public_key,
        developer_signature,
        certificate_id,
        media_ref,
        commit_time,
    ) {
        Ok(signature) => {
            let c_str = CString::new(signature).unwrap_or_else(|_| {
                CString::new("Error: Failed to create signature string").unwrap()
            });
            c_str.into_raw()
        }
        Err(e) => {
            let error_msg = format!("Error: {}", e);
            let c_str = CString::new(error_msg).unwrap_or_else(|_| {
                CString::new("Error: Failed to create error message").unwrap()
            });
            c_str.into_raw()
        }
    }
}

#[no_mangle]
pub extern "C" fn exists_record(
    keypair_bytes: *const c_uchar,
    keypair_len: i32,
    media_hash: *const c_uchar,
) -> *mut c_char {
    match try_exists_record(keypair_bytes, keypair_len, media_hash) {
        Ok(exists) => {
            let result = if exists { "1" } else { "0" };
            let c_str = CString::new(result).unwrap_or_else(|_| {
                CString::new("Error: Failed to create result string").unwrap()
            });
            c_str.into_raw()
        }
        Err(e) => {
            let error_msg = format!("Error: {}", e);
            let c_str = CString::new(error_msg).unwrap_or_else(|_| {
                CString::new("Error: Failed to create error message").unwrap()
            });
            c_str.into_raw()
        }
    }
}

#[no_mangle]
pub extern "C" fn delete_record(
    keypair_bytes: *const c_uchar,
    keypair_len: i32,
    media_hash: *const c_uchar,
) -> *mut c_char {
    match try_delete_record(keypair_bytes, keypair_len, media_hash) {
        Ok(signature) => {
            let c_str = CString::new(signature).unwrap_or_else(|_| {
                CString::new("Error: Failed to create signature string").unwrap()
            });
            c_str.into_raw()
        }
        Err(e) => {
            let error_msg = format!("Error: {}", e);
            let c_str = CString::new(error_msg).unwrap_or_else(|_| {
                CString::new("Error: Failed to create error message").unwrap()
            });
            c_str.into_raw()
        }
    }
}

#[no_mangle]
pub extern "C" fn serialize_and_hash_metadata(
    protocol_version: *const u8,
    session_id: *const u8,
    timestamp: u32,
    lat: *const f32,
    lon: *const f32,
    fuzzed: u8,
    fuzz_radius: *const f32,
    device: *const u8,
    flags: u8,
) -> *mut SerializeResult {
    // Validate inputs
    if protocol_version.is_null() || session_id.is_null() || lat.is_null() || lon.is_null() ||
       fuzz_radius.is_null() || device.is_null() {
        return std::ptr::null_mut();
    }

    // Construct Metadata
    let protocol_version = unsafe { slice::from_raw_parts(protocol_version, 4) }.try_into().unwrap();
    let session_id = unsafe { slice::from_raw_parts(session_id, 16) }.try_into().unwrap();
    let lat = unsafe { lat.as_ref().map(|&x| x) };
    let lon = unsafe { lon.as_ref().map(|&x| x) };
    let fuzz_radius = unsafe { fuzz_radius.as_ref().map(|&x| x) };
    let device = unsafe { slice::from_raw_parts(device, 16) }.try_into().unwrap();

    let metadata = Metadata {
        protocol_version,
        session_id,
        timestamp,
        lat,
        lon,
        fuzzed,
        fuzz_radius,
        device,
        flags,
    };

    // Serialize to bytes
    let serialized = match metadata.try_to_vec() {
        Ok(data) => data,
        Err(_) => return std::ptr::null_mut(),
    };

    // Compute BLAKE3 hash (first 24 bytes)
    let hash_full = hash(&serialized);
    let hash_bytes = &hash_full.as_bytes()[..24];

    // Allocate memory for serialized data and hash
    let data_len = serialized.len();
    let hash_len = hash_bytes.len();

    let data_ptr = unsafe {
        let ptr = libc::malloc(data_len) as *mut u8;
        if ptr.is_null() {
            return std::ptr::null_mut();
        }
        std::ptr::copy_nonoverlapping(serialized.as_ptr(), ptr, data_len);
        ptr
    };

    let hash_ptr = unsafe {
        let ptr = libc::malloc(hash_len) as *mut u8;
        if ptr.is_null() {
            libc::free(data_ptr as *mut c_void);
            return std::ptr::null_mut();
        }
        std::ptr::copy_nonoverlapping(hash_bytes.as_ptr(), ptr, hash_len);
        ptr
    };

    // Return result
    let result = Box::new(SerializeResult {
        data_ptr,
        data_len,
        hash_ptr,
        hash_len,
    });
    Box::into_raw(result)
}

#[no_mangle]
pub extern "C" fn free_serialize_result(result: *mut SerializeResult) {
    if !result.is_null() {
        unsafe {
            let result = Box::from_raw(result);
            if !result.data_ptr.is_null() {
                libc::free(result.data_ptr as *mut c_void);
            }
            if !result.hash_ptr.is_null() {
                libc::free(result.hash_ptr as *mut c_void);
            }
        }
    }
}

#[no_mangle]
pub extern "C" fn free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        unsafe {
            let _ = CString::from_raw(ptr);
        }
    }
}

// --- Internal Functions ---

fn try_send_add_record(
    keypair_bytes: *const c_uchar,
    keypair_len: c_int,
    media_hash: *const c_uchar,
    metadata_bytes: *const c_uchar,
    metadata_len: c_int,
    metadata_hash: *const c_uchar,
    tee_signature: *const c_uchar,
    tee_public_key: *const c_uchar,
    developer_signature: *const c_uchar,
    certificate_id: *const c_uchar,
    media_ref: *const c_uchar,
    commit_time: u32,
) -> std::result::Result<String, FfiError> {
    if keypair_bytes.is_null() || media_hash.is_null() || metadata_bytes.is_null() || metadata_hash.is_null() ||
       tee_signature.is_null() || tee_public_key.is_null() || developer_signature.is_null() ||
       certificate_id.is_null() || media_ref.is_null() {
        return Err(FfiError::InvalidInput("Null pointer passed".to_string()));
    }

    if keypair_len != EXPECTED_KEYPAIR_LEN {
        return Err(FfiError::InvalidInput(format!(
            "Invalid keypair length: {}, expected: {}",
            keypair_len, EXPECTED_KEYPAIR_LEN
        )));
    }

    if metadata_len != EXPECTED_METADATA_LEN as c_int {
        return Err(FfiError::InvalidInput(format!(
            "Invalid metadata length: {}, expected: {}",
            metadata_len, EXPECTED_METADATA_LEN
        )));
    }

    let keypair_slice = unsafe { slice::from_raw_parts(keypair_bytes, keypair_len as usize) };
    let keypair = Keypair::from_bytes(keypair_slice).map_err(|_| FfiError::InvalidKeypair)?;

    let media_hash_slice = unsafe { slice::from_raw_parts(media_hash, EXPECTED_MEDIA_HASH_LEN) };
    let media_hash: [u8; 24] = media_hash_slice.try_into().map_err(|_| {
        FfiError::InvalidInput(format!(
            "Invalid media_hash length: {}, expected: {}",
            media_hash_slice.len(), EXPECTED_MEDIA_HASH_LEN
        ))
    })?;

    let metadata_bytes_slice = unsafe { slice::from_raw_parts(metadata_bytes, metadata_len as usize) };
    let metadata_hash_slice = unsafe { slice::from_raw_parts(metadata_hash, EXPECTED_METADATA_HASH_LEN) };
    let metadata_hash: [u8; 24] = metadata_hash_slice.try_into().map_err(|_| {
        FfiError::InvalidInput(format!(
            "Invalid metadata_hash length: {}, expected: {}",
            metadata_hash_slice.len(), EXPECTED_METADATA_HASH_LEN
        ))
    })?;

    let tee_signature_slice = unsafe { slice::from_raw_parts(tee_signature, EXPECTED_TEE_SIGNATURE_LEN) };
    let tee_signature: [u8; 64] = tee_signature_slice.try_into().map_err(|_| {
        FfiError::InvalidInput(format!(
            "Invalid tee_signature length: {}, expected: {}",
            tee_signature_slice.len(), EXPECTED_TEE_SIGNATURE_LEN
        ))
    })?;

    let tee_public_key_slice = unsafe { slice::from_raw_parts(tee_public_key, EXPECTED_TEE_PUBLIC_KEY_LEN) };
    let tee_public_key: [u8; 32] = tee_public_key_slice.try_into().map_err(|_| {
        FfiError::InvalidInput(format!(
            "Invalid tee_public_key length: {}, expected: {}",
            tee_public_key_slice.len(), EXPECTED_TEE_PUBLIC_KEY_LEN
        ))
    })?;

    let developer_signature_slice = unsafe { slice::from_raw_parts(developer_signature, EXPECTED_DEVELOPER_SIGNATURE_LEN) };
    let developer_signature: [u8; 64] = developer_signature_slice.try_into().map_err(|_| {
        FfiError::InvalidInput(format!(
            "Invalid developer_signature length: {}, expected: {}",
            developer_signature_slice.len(), EXPECTED_DEVELOPER_SIGNATURE_LEN
        ))
    })?;

    let certificate_id_slice = unsafe { slice::from_raw_parts(certificate_id, EXPECTED_CERTIFICATE_ID_LEN) };
    let certificate_id: [u8; 16] = certificate_id_slice.try_into().map_err(|_| {
        FfiError::InvalidInput(format!(
            "Invalid certificate_id length: {}, expected: {}",
            certificate_id_slice.len(), EXPECTED_CERTIFICATE_ID_LEN
        ))
    })?;

    let media_ref_slice = unsafe { slice::from_raw_parts(media_ref, EXPECTED_MEDIA_REF_LEN) };
    let media_ref: [u8; 46] = media_ref_slice.try_into().map_err(|_| {
        FfiError::InvalidInput(format!(
            "Invalid media_ref length: {}, expected: {}",
            media_ref_slice.len(), EXPECTED_MEDIA_REF_LEN
        ))
    })?;

    let client = RpcClient::new("https://api.devnet.solana.com".to_string());

    let program_id = id();
    let pubkey_bytes = keypair.pubkey().to_bytes();
    let pda_seeds = &[pubkey_bytes.as_ref(), media_hash.as_ref()];
    let (pda, _bump) = Pubkey::find_program_address(pda_seeds, &program_id);

    let discriminator = anchor_lang::solana_program::hash::hash("global:add_record".as_bytes());
    let discriminator = &discriminator.to_bytes()[..8];

    let mut instruction_data = Vec::new();
    instruction_data.extend_from_slice(discriminator);
    instruction_data.extend_from_slice(&media_hash);
    instruction_data.extend_from_slice(&metadata_hash);
    instruction_data.extend_from_slice(metadata_bytes_slice);
    instruction_data.extend_from_slice(&tee_signature);
    instruction_data.extend_from_slice(&tee_public_key);
    instruction_data.extend_from_slice(&developer_signature);
    instruction_data.extend_from_slice(&certificate_id);
    instruction_data.extend_from_slice(&media_ref);
    instruction_data.extend_from_slice(&commit_time.to_le_bytes());

    let accounts = vec![
        AccountMeta::new(pda, false),
        AccountMeta::new(keypair.pubkey(), true),
        AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
    ];
    let instruction = Instruction::new_with_bytes(program_id, &instruction_data, accounts);

    let recent_blockhash = client
        .get_latest_blockhash()
        .map_err(FfiError::SolanaClientError)?;
    let transaction = Transaction::new_signed_with_payer(
        &[instruction],
        Some(&keypair.pubkey()),
        &[&keypair],
        recent_blockhash,
    );

    let signature = client
        .send_and_confirm_transaction(&transaction)
        .map_err(FfiError::SolanaClientError)?;
    Ok(signature.to_string())
}

fn try_exists_record(
    keypair_bytes: *const c_uchar,
    keypair_len: i32,
    media_hash: *const c_uchar,
) -> std::result::Result<bool, FfiError> {
    if keypair_bytes.is_null() || media_hash.is_null() {
        return Err(FfiError::InvalidInput("Null pointer passed".to_string()));
    }

    if keypair_len != EXPECTED_KEYPAIR_LEN {
        return Err(FfiError::InvalidInput(format!(
            "Invalid keypair length: {}, expected: {}",
            keypair_len, EXPECTED_KEYPAIR_LEN
        )));
    }

    let keypair_slice = unsafe { slice::from_raw_parts(keypair_bytes, keypair_len as usize) };
    let keypair = Keypair::from_bytes(keypair_slice).map_err(|_| FfiError::InvalidKeypair)?;

    let media_hash_slice = unsafe { slice::from_raw_parts(media_hash, EXPECTED_MEDIA_HASH_LEN) };
    let media_hash: [u8; 24] = media_hash_slice.try_into().map_err(|_| {
        FfiError::InvalidInput(format!(
            "Invalid media_hash length: {}, expected: {}",
            media_hash_slice.len(), EXPECTED_MEDIA_HASH_LEN
        ))
    })?;

    let client = RpcClient::new("https://api.devnet.solana.com".to_string());

    let program_id = id();
    let pubkey_bytes = keypair.pubkey().to_bytes();
    let pda_seeds = &[pubkey_bytes.as_ref(), media_hash.as_ref()];
    let (pda, _bump) = Pubkey::find_program_address(pda_seeds, &program_id);

    match client.get_account_data(&pda) {
        Ok(_) => Ok(true),
        Err(e) if matches!(e.kind(), solana_client::client_error::ClientErrorKind::RpcError(
            solana_client::rpc_request::RpcError::RpcRequestError(_)
        )) => Ok(false),
        Err(e) => Err(FfiError::SolanaClientError(e)),
    }
}

fn try_delete_record(
    keypair_bytes: *const c_uchar,
    keypair_len: i32,
    media_hash: *const c_uchar,
) -> std::result::Result<String, FfiError> {
    if keypair_bytes.is_null() || media_hash.is_null() {
        return Err(FfiError::InvalidInput("Null pointer passed".to_string()));
    }

    if keypair_len != EXPECTED_KEYPAIR_LEN {
        return Err(FfiError::InvalidInput(format!(
            "Invalid keypair length: {}, expected: {}",
            keypair_len, EXPECTED_KEYPAIR_LEN
        )));
    }

    let keypair_slice = unsafe { slice::from_raw_parts(keypair_bytes, keypair_len as usize) };
    let keypair = Keypair::from_bytes(keypair_slice).map_err(|_| FfiError::InvalidKeypair)?;

    let media_hash_slice = unsafe { slice::from_raw_parts(media_hash, EXPECTED_MEDIA_HASH_LEN) };
    let media_hash: [u8; 24] = media_hash_slice.try_into().map_err(|_| {
        FfiError::InvalidInput(format!(
            "Invalid media_hash length: {}, expected: {}",
            media_hash_slice.len(), EXPECTED_MEDIA_HASH_LEN
        ))
    })?;

    let client = RpcClient::new("https://api.devnet.solana.com".to_string());

    let program_id = id();
    let pubkey_bytes = keypair.pubkey().to_bytes();
    let pda_seeds = &[pubkey_bytes.as_ref(), media_hash.as_ref()];
    let (pda, _bump) = Pubkey::find_program_address(pda_seeds, &program_id);

    let discriminator = anchor_lang::solana_program::hash::hash("global:delete_record".as_bytes());
    let discriminator = &discriminator.to_bytes()[..8];

    let mut instruction_data = Vec::new();
    instruction_data.extend_from_slice(discriminator);

    let accounts = vec![
        AccountMeta::new(pda, false),
        AccountMeta::new(keypair.pubkey(), true),
    ];
    let instruction = Instruction::new_with_bytes(program_id, &instruction_data, accounts);

    let recent_blockhash = client
        .get_latest_blockhash()
        .map_err(FfiError::SolanaClientError)?;
    let transaction = Transaction::new_signed_with_payer(
        &[instruction],
        Some(&keypair.pubkey()),
        &[&keypair],
        recent_blockhash,
    );

    let signature = client
        .send_and_confirm_transaction(&transaction)
        .map_err(FfiError::SolanaClientError)?;
    Ok(signature.to_string())
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serialize_and_hash_metadata() {
        let protocol_version = [1, 0, 0, 0];
        let session_id = [1; 16];
        let timestamp = 1713115200;
        let lat = 37.7749;
        let lon = -122.4194;
        let fuzzed = 1;
        let fuzz_radius = 1609.0;
        let mut device = [0; 16];
        device[0..11].copy_from_slice(&[67; 11]);
        let flags = 3;

        let result_ptr = serialize_and_hash_metadata(
            protocol_version.as_ptr(),
            session_id.as_ptr(),
            timestamp,
            &lat,
            &lon,
            fuzzed,
            &fuzz_radius,
            device.as_ptr(),
            flags,
        );

        assert!(!result_ptr.is_null(), "Result pointer should not be null");
        unsafe {
            let result = &*result_ptr;
            assert_eq!(result.data_len, 57, "Serialized data length should be 57");
            assert_eq!(result.hash_len, 24, "Hash length should be 24");

            let serialized = slice::from_raw_parts(result.data_ptr, result.data_len);
            let hash = slice::from_raw_parts(result.hash_ptr, result.hash_len);
            println!("Serialized (hex): {:02x?}", serialized);
            println!("Hash (hex): {:02x?}", hash);

            let expected_hash = [
                0xc7, 0x2e, 0x49, 0xb4, 0x08, 0x45, 0x93, 0x44,
                0xcc, 0xe0, 0xf1, 0x2e, 0x65, 0xdb, 0xe3, 0xc4,
                0xba, 0x3f, 0xf5, 0xfa, 0xc4, 0x70, 0x86, 0x87,
            ];
            assert_eq!(hash, expected_hash, "Hash does not match expected");

            free_serialize_result(result_ptr);
        }
    }
}
