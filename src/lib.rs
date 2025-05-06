use anchor_lang::prelude::*;
use anchor_lang::system_program::ID;
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
use std::str::FromStr;
use blake3::hash;
use serde::Serialize;

// Program ID
pub const PROGRAM_ID: &str = "ENKMqg25PSLyojUB46NQNNbRirxn1t54uuiMo5X8CXjN";

// --- Data Structures ---

#[account]
pub struct AmpRecord {
    pub media_hash: [u8; 32],
    pub metadata_hash: [u8; 24],
    pub tee_signature: [u8; 64],
    pub developer_signature: [u8; 64],
    pub tee_public_key: [u8; 32],
    pub certificate_id: [u8; 16],
    pub media_ref: [u8; 46],
    pub commit_time: u32,
    pub metadata: Metadata,
    pub owner: Pubkey,
    pub bump: u8,
}

#[derive(AnchorSerialize, AnchorDeserialize, Serialize, Clone)]
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
    IoError(std::io::Error),
}

impl std::fmt::Display for FfiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FfiError::InvalidKeypair => write!(f, "Invalid keypair"),
            FfiError::InvalidInput(msg) => write!(f, "Invalid input data: {}", msg),
            FfiError::SolanaClientError(e) => write!(f, "Solana client error: {}", e),
            FfiError::IoError(e) => write!(f, "IO error: {}", e),
        }
    }
}

impl std::error::Error for FfiError {}

impl From<solana_client::client_error::ClientError> for FfiError {
    fn from(err: solana_client::client_error::ClientError) -> Self {
        FfiError::SolanaClientError(err)
    }
}

impl From<std::io::Error> for FfiError {
    fn from(err: std::io::Error) -> Self {
        FfiError::IoError(err)
    }
}

// --- Constants ---

const EXPECTED_KEYPAIR_LEN: i32 = 64;
const EXPECTED_MEDIA_HASH_LEN: usize = 32;
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
    commit_time: u32,
) -> *mut c_char {
    match try_exists_record(keypair_bytes, keypair_len, media_hash, commit_time) {
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
    commit_time: u32,
) -> *mut c_char {
    match try_delete_record(keypair_bytes, keypair_len, media_hash, commit_time) {
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
pub extern "C" fn calculate_pda(
    keypair_bytes: *const c_uchar,
    keypair_len: c_int,
    media_hash: *const c_uchar, 
    commit_time: u32
) -> *mut c_char {
    if keypair_bytes.is_null() || media_hash.is_null() {
        let error_msg = "Error: Null pointer passed";
        let c_str = CString::new(error_msg).unwrap();
        return c_str.into_raw();
    }

    if keypair_len != EXPECTED_KEYPAIR_LEN {
        let error_msg = format!("Invalid keypair length: {}, expected: {}", keypair_len, EXPECTED_KEYPAIR_LEN);
        let c_str = CString::new(error_msg).unwrap();
        return c_str.into_raw();
    }

    let keypair_slice = unsafe { slice::from_raw_parts(keypair_bytes, keypair_len as usize) };
    let keypair = match Keypair::from_bytes(keypair_slice) {
        Ok(kp) => kp,
        Err(_) => {
            let error_msg = "Error: Invalid keypair data";
            let c_str = CString::new(error_msg).unwrap();
            return c_str.into_raw();
        }
    };
    
    let media_hash_slice = unsafe { slice::from_raw_parts(media_hash, EXPECTED_MEDIA_HASH_LEN) };
    let media_hash: [u8; 32] = match media_hash_slice.try_into() {
        Ok(mh) => mh,
        Err(_) => {
            let error_msg = format!("Invalid media_hash length: {}, expected: {}", 
                                   media_hash_slice.len(), EXPECTED_MEDIA_HASH_LEN);
            let c_str = CString::new(error_msg).unwrap();
            return c_str.into_raw();
        }
    };

    let program_id = match Pubkey::from_str(PROGRAM_ID) {
        Ok(pid) => pid,
        Err(_) => {
            let error_msg = "Error: Invalid program ID";
            let c_str = CString::new(error_msg).unwrap();
            return c_str.into_raw();
        }
    };
    
    let pubkey_bytes = keypair.pubkey().to_bytes();
    let commit_time_bytes = commit_time.to_le_bytes();
    let pda_seeds = &[
        pubkey_bytes.as_ref(), 
        media_hash.as_ref(), 
        commit_time_bytes.as_ref()
    ];
    
    let (pda, bump) = Pubkey::find_program_address(pda_seeds, &program_id);
    
    let result = format!("{}:{}", pda.to_string(), bump);
    let c_str = CString::new(result).unwrap();
    c_str.into_raw()
}

#[no_mangle]
pub extern "C" fn serialize_and_hash_metadata(
    media_hash: *const u8,
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
    if media_hash.is_null() || protocol_version.is_null() || session_id.is_null() || 
       lat.is_null() || lon.is_null() || fuzz_radius.is_null() || device.is_null() {
        return std::ptr::null_mut();
    }

    let media_hash_array: [u8; 32] = unsafe { slice::from_raw_parts(media_hash, 32) }.try_into().unwrap();
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

    let metadata_serialized = match metadata.try_to_vec() {
        Ok(data) => data,
        Err(_) => return std::ptr::null_mut(),
    };

    let mut hash_input = Vec::with_capacity(32 + metadata_serialized.len());
    hash_input.extend_from_slice(&media_hash_array);
    hash_input.extend_from_slice(&metadata_serialized);

    let hash_full = hash(&hash_input);
    let hash_bytes = &hash_full.as_bytes()[..24];

    let data_len = metadata_serialized.len();
    let hash_len = hash_bytes.len();

    let data_ptr = unsafe {
        let ptr = libc::malloc(data_len) as *mut u8;
        if ptr.is_null() {
            return std::ptr::null_mut();
        }
        std::ptr::copy_nonoverlapping(metadata_serialized.as_ptr(), ptr, data_len);
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
    let media_hash: [u8; 32] = media_hash_slice.try_into().map_err(|_| {
        FfiError::InvalidInput(format!(
            "Invalid media_hash length: {}, expected: {}",
            media_hash_slice.len(), EXPECTED_MEDIA_HASH_LEN
        ))
    })?;

    let metadata_bytes_slice = unsafe { slice::from_raw_parts(metadata_bytes, metadata_len as usize) };
    let metadata: Metadata = borsh::BorshDeserialize::try_from_slice(metadata_bytes_slice).map_err(|_| {
        FfiError::InvalidInput(format!(
            "Invalid metadata_bytes length or format: {}, expected: 57",
            metadata_bytes_slice.len()
        ))
    })?;

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

    let program_id = Pubkey::from_str(PROGRAM_ID).map_err(|_| {
        FfiError::InvalidInput("Invalid program ID".to_string())
    })?;
    
    // UPDATED: Use proper PDA calculation with commit_time included
    let pubkey_bytes = keypair.pubkey().to_bytes();
    let commit_time_bytes = commit_time.to_le_bytes();
    let pda_seeds = &[
        pubkey_bytes.as_ref(), 
        media_hash.as_ref(), 
        commit_time_bytes.as_ref()
    ];
    let (pda, _bump) = Pubkey::find_program_address(pda_seeds, &program_id);

    let add_record_instruction = AddRecord {
        media_hash,
        metadata_hash,
        metadata,
        tee_signature,
        tee_public_key,
        developer_signature,
        certificate_id,
        media_ref,
        commit_time,
    };

    let discriminator = anchor_lang::solana_program::hash::hash(b"global:add_record").to_bytes()[..8].to_vec();
    let mut instruction_data = discriminator;
    instruction_data.extend_from_slice(
        &add_record_instruction.try_to_vec().map_err(|_| {
            FfiError::InvalidInput("Failed to serialize AddRecord".to_string())
        })?,
    );

    let accounts = vec![
        AccountMeta::new(pda, false),
        AccountMeta::new(keypair.pubkey(), true),
        AccountMeta::new_readonly(ID, false),
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

// UPDATED: Added commit_time parameter to properly calculate the PDA
fn try_exists_record(
    keypair_bytes: *const c_uchar,
    keypair_len: i32,
    media_hash: *const c_uchar,
    commit_time: u32,
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
    let media_hash: [u8; 32] = media_hash_slice.try_into().map_err(|_| {
        FfiError::InvalidInput(format!(
            "Invalid media_hash length: {}, expected: {}",
            media_hash_slice.len(), EXPECTED_MEDIA_HASH_LEN
        ))
    })?;

    let client = RpcClient::new("https://api.devnet.solana.com".to_string());

    let program_id = Pubkey::from_str(PROGRAM_ID).map_err(|_| {
        FfiError::InvalidInput("Invalid program ID".to_string())
    })?;
    
    // UPDATED: Use proper PDA calculation with commit_time included
    let pubkey_bytes = keypair.pubkey().to_bytes();
    let commit_time_bytes = commit_time.to_le_bytes();
    let pda_seeds = &[
        pubkey_bytes.as_ref(), 
        media_hash.as_ref(), 
        commit_time_bytes.as_ref()
    ];
    let (pda, _bump) = Pubkey::find_program_address(pda_seeds, &program_id);

    match client.get_account_data(&pda) {
        Ok(_) => Ok(true),
        Err(e) if matches!(e.kind(), solana_client::client_error::ClientErrorKind::RpcError(
            solana_client::rpc_request::RpcError::RpcRequestError(_)
        )) => Ok(false),
        Err(e) => Err(FfiError::SolanaClientError(e)),
    }
}

// UPDATED: Added commit_time parameter to properly calculate the PDA
fn try_delete_record(
    keypair_bytes: *const c_uchar,
    keypair_len: i32,
    media_hash: *const c_uchar,
    commit_time: u32,
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
    let media_hash: [u8; 32] = media_hash_slice.try_into().map_err(|_| {
        FfiError::InvalidInput(format!(
            "Invalid media_hash length: {}, expected: {}",
            media_hash_slice.len(), EXPECTED_MEDIA_HASH_LEN
        ))
    })?;

    let client = RpcClient::new("https://api.devnet.solana.com".to_string());

    let program_id = Pubkey::from_str(PROGRAM_ID).map_err(|_| {
        FfiError::InvalidInput("Invalid program ID".to_string())
    })?;
    
    // UPDATED: Use proper PDA calculation with commit_time included
    let pubkey_bytes = keypair.pubkey().to_bytes();
    let commit_time_bytes = commit_time.to_le_bytes();
    let pda_seeds = &[
        pubkey_bytes.as_ref(), 
        media_hash.as_ref(), 
        commit_time_bytes.as_ref()
    ];
    let (pda, _bump) = Pubkey::find_program_address(pda_seeds, &program_id);

    let delete_record_instruction = DeleteRecord {};
    let discriminator = anchor_lang::solana_program::hash::hash(b"global:delete_record").to_bytes()[..8].to_vec();
    let mut instruction_data = discriminator;
    instruction_data.extend_from_slice(
        &delete_record_instruction.try_to_vec().map_err(|_| {
            FfiError::InvalidInput("Failed to serialize DeleteRecord".to_string())
        })?,
    );

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

// --- Instruction Structs ---

#[derive(AnchorSerialize, AnchorDeserialize)]
pub struct AddRecord {
    pub media_hash: [u8; 32],
    pub metadata_hash: [u8; 24],
    pub metadata: Metadata,
    pub tee_signature: [u8; 64],
    pub tee_public_key: [u8; 32],
    pub developer_signature: [u8; 64],
    pub certificate_id: [u8; 16],
    pub media_ref: [u8; 46],
    pub commit_time: u32,
}

#[derive(AnchorSerialize)]
pub struct DeleteRecord {}

// --- Tests ---
#[cfg(test)]
mod ffi_tests {
    use super::*;
    use std::fs::File;
    use std::io::Read;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};
    // Use std::result explicitly to avoid confusion with anchor's Result
    use std::result::Result;

    // Helper function to load devnet keypair
    fn load_devnet_keypair() -> Result<Keypair, String> {
        let home = std::env::var("HOME").map_err(|e| e.to_string())?;
        let keypair_path = PathBuf::from(home).join(".config/solana/devnet-keypair.json");
        
        let mut file = File::open(keypair_path).map_err(|e| e.to_string())?;
        let mut contents = String::new();
        file.read_to_string(&mut contents).map_err(|e| e.to_string())?;
        
        // Parse JSON manually without serde_json
        let json_str = contents.trim_start_matches('[').trim_end_matches(']');
        let bytes: Vec<u8> = json_str
            .split(',')
            .map(|s| s.trim().parse::<u8>())
            .collect::<Result<Vec<u8>, _>>()
            .map_err(|e| e.to_string())?;
        
        Keypair::from_bytes(&bytes).map_err(|e| e.to_string())
    }
    
    // Generate mock data with correct sizes
    fn generate_test_data() -> (Vec<u8>, u32, Metadata) {
        // Create deterministic but random-looking media hash
        let mut media_hash = [0u8; 32];
        for i in 0..32 {
            media_hash[i] = (i * 7) as u8;
        }
        
        // Current time as commit time
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        let commit_time = now.as_secs() as u32;
        
        // Create test metadata
        let protocol_version = [1, 0, 0, 0];
        let mut session_id = [0u8; 16];
        for i in 0..16 {
            session_id[i] = (i * 11) as u8;
        }
        
        let metadata = Metadata {
            protocol_version,
            session_id,
            timestamp: commit_time,
            lat: Some(42.3601),
            lon: Some(-71.0589),
            fuzzed: 1,
            fuzz_radius: Some(1000.0),
            device: [1; 16],
            flags: 3,
        };
        
        (media_hash.to_vec(), commit_time, metadata)
    }
    
    // Test FFI end-to-end flow
    #[test]
    fn test_ffi_flow() {
        // This test can be disabled with environment variables if needed
        if std::env::var("SKIP_SOLANA_TESTS").is_ok() {
            return;
        }
        
        // Load keypair
        let keypair = match load_devnet_keypair() {
            Ok(kp) => kp,
            Err(e) => {
                println!("Failed to load devnet keypair: {}", e);
                return;
            }
        };
        
        // Generate test data
        let (media_hash, commit_time, metadata) = generate_test_data();
        
        // Serialize metadata
        let serialized_metadata = metadata.try_to_vec().unwrap();
        
        // Generate mock hash and signatures
        let metadata_hash = [2u8; 24];
        let tee_signature = [3u8; 64];
        let tee_public_key = [4u8; 32];
        let developer_signature = [5u8; 64];
        let certificate_id = [6u8; 16];
        let media_ref = [7u8; 46];
        
        // First check if record exists (should be false)
        let exists_result = try_exists_record(
            keypair.to_bytes().as_ptr(),
            keypair.to_bytes().len() as i32,
            media_hash.as_ptr(),
            commit_time
        );
        
        match exists_result {
            Ok(exists) => {
                if exists {
                    println!("Record unexpectedly exists, deleting first...");
                    let _ = try_delete_record(
                        keypair.to_bytes().as_ptr(),
                        keypair.to_bytes().len() as i32,
                        media_hash.as_ptr(),
                        commit_time
                    );
                }
            },
            Err(e) => {
                println!("Error checking if record exists: {}", e);
                // Continue anyway
            }
        }
        
        // Test add record
        println!("Testing add_record...");
        let add_result = try_send_add_record(
            keypair.to_bytes().as_ptr(),
            keypair.to_bytes().len() as i32,
            media_hash.as_ptr(),
            serialized_metadata.as_ptr(),
            serialized_metadata.len() as i32,
            metadata_hash.as_ptr(),
            tee_signature.as_ptr(),
            tee_public_key.as_ptr(),
            developer_signature.as_ptr(),
            certificate_id.as_ptr(),
            media_ref.as_ptr(),
            commit_time
        );
        
        match add_result {
            Ok(signature) => {
                println!("Successfully added record, signature: {}", signature);
                
                // Now check if record exists (should be true)
                let exists_result = try_exists_record(
                    keypair.to_bytes().as_ptr(),
                    keypair.to_bytes().len() as i32,
                    media_hash.as_ptr(),
                    commit_time
                );
                
                match exists_result {
                    Ok(exists) => {
                        assert!(exists, "Record should exist after adding");
                        println!("Confirmed record exists!");
                    },
                    Err(e) => {
                        panic!("Error checking if record exists after adding: {}", e);
                    }
                }
                
                // Test delete record
                println!("Testing delete_record...");
                let delete_result = try_delete_record(
                    keypair.to_bytes().as_ptr(),
                    keypair.to_bytes().len() as i32,
                    media_hash.as_ptr(),
                    commit_time
                );
                
                match delete_result {
                    Ok(signature) => {
                        println!("Successfully deleted record, signature: {}", signature);
                        
                        // Verify record no longer exists
                        let exists_result = try_exists_record(
                            keypair.to_bytes().as_ptr(),
                            keypair.to_bytes().len() as i32,
                            media_hash.as_ptr(),
                            commit_time
                        );
                        
                        match exists_result {
                            Ok(exists) => {
                                assert!(!exists, "Record should not exist after deletion");
                                println!("Confirmed record was deleted!");
                            },
                            Err(e) => {
                                panic!("Error checking if record exists after deletion: {}", e);
                            }
                        }
                    },
                    Err(e) => {
                        panic!("Error deleting record: {}", e);
                    }
                }
            },
            Err(e) => {
                panic!("Error adding record: {}", e);
            }
        }
    }
    
    #[test]
    fn test_serialize_and_hash() {
        // Generate test data
        let (media_hash, commit_time, metadata) = generate_test_data();
        
        // Test the serialization and hashing
        let result_ptr = serialize_and_hash_metadata(
            media_hash.as_ptr(),
            metadata.protocol_version.as_ptr(),
            metadata.session_id.as_ptr(),
            metadata.timestamp,
            &metadata.lat.unwrap(),
            &metadata.lon.unwrap(),
            metadata.fuzzed,
            &metadata.fuzz_radius.unwrap(),
            metadata.device.as_ptr(),
            metadata.flags
        );
        
        assert!(!result_ptr.is_null(), "Serialization result should not be null");
        
        unsafe {
            let result = &*result_ptr;
            assert!(result.data_len > 0, "Serialized data should not be empty");
            assert_eq!(result.hash_len, 24, "Hash length should be 24 bytes");
            
            // Clean up
            free_serialize_result(result_ptr);
        }
    }
}

#[test]
fn test_pda_generation_corrected() {
    // Known good values from your debug output
    let known_wallet_base58 = "BjMDzXiDKzThNF3oXaDvDzeeVC8PzN1xakAf6btJt5Ty";
    
    // Media hash as bytes - exact values from hex
    let media_hash_hex = "fffffffffff1f801f801f801f801f8014001c001f001f801fc01fc01fc01ffff";
    let mut media_hash = [0u8; 32];
    hex_string_to_bytes(media_hash_hex, &mut media_hash);
    
    let known_commit_time: u32 = 1713115200;
    let expected_pda_base58 = "7BAHNvy8nDVFnSn3NBmj53SQuioTgVCaTWRMqWFPvprs";
    let expected_bump = 254;
    
    // IMPORTANT: Use the correct program ID from your test output
    let program_id_str = "ENKMqg25PSLyojUB46NQNNbRirxn1t54uuiMo5X8CXjN";
    let program_id = Pubkey::from_str(program_id_str).unwrap();
    
    // Convert Base58 pubkey to Pubkey
    let pubkey = Pubkey::from_str(known_wallet_base58).unwrap();
    
    println!("\n===== CORRECTED PDA TEST =====");
    println!("Using program ID: {}", program_id);
    println!("Wallet public key: {}", pubkey);
    println!("Media hash (hex): {}", media_hash_hex);
    println!("Commit time: {}", known_commit_time);
    
    // Calculate PDA using LE commit time (from debug output)
    let commit_time_le = known_commit_time.to_le_bytes();
    println!("Commit time LE (hex): {}", bytes_to_hex(&commit_time_le));
    
    let pda_seeds = &[
        pubkey.as_ref(), 
        &media_hash, 
        &commit_time_le
    ];
    
    let (calculated_pda, bump) = Pubkey::find_program_address(pda_seeds, &program_id);
    
    println!("Calculated PDA: {}", calculated_pda);
    println!("Calculated bump: {}", bump);
    println!("Expected PDA: {}", expected_pda_base58);
    println!("Expected bump: {}", expected_bump);
    println!("Matches expected? {}", calculated_pda.to_string() == expected_pda_base58);
    
    assert_eq!(
        calculated_pda.to_string(), expected_pda_base58,
        "PDA calculation does not match expected PDA"
    );
    assert_eq!(
        bump, expected_bump,
        "Bump seed does not match expected bump"
    );
}

// Helper function to convert hex string to bytes
fn hex_string_to_bytes(hex: &str, output: &mut [u8]) {
    for i in 0..min(hex.len()/2, output.len()) {
        if let Ok(val) = u8::from_str_radix(&hex[i*2..i*2+2], 16) {
            output[i] = val;
        }
    }
}

// Helper function to convert bytes to hex string
fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut hex = String::new();
    for byte in bytes {
        hex.push_str(&format!("{:02x}", byte));
    }
    hex
}

fn min(a: usize, b: usize) -> usize {
    if a < b { a } else { b }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serialize_and_hash_metadata() {
        let media_hash = [1; 32];
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
            media_hash.as_ptr(),
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

            let expected_hash = [
                0xb1, 0xed, 0x78, 0x1d, 0xe9, 0x99, 0x4c, 0xfc,
                0x50, 0xb2, 0xc8, 0x79, 0x7c, 0x67, 0xa6, 0x43,
                0x05, 0x36, 0xe3, 0x9b, 0xf7, 0xcd, 0x56, 0x6b,
            ];
            assert_eq!(hash, expected_hash, "Hash does not match expected");

            let metadata: Metadata = borsh::BorshDeserialize::try_from_slice(serialized).unwrap();
            assert_eq!(metadata.protocol_version, protocol_version);
            assert_eq!(metadata.session_id, session_id);
            assert_eq!(metadata.timestamp, timestamp);
            assert_eq!(metadata.lat, Some(lat));
            assert_eq!(metadata.lon, Some(lon));
            assert_eq!(metadata.fuzzed, fuzzed);
            assert_eq!(metadata.fuzz_radius, Some(fuzz_radius));
            assert_eq!(metadata.device, device);
            assert_eq!(metadata.flags, flags);

            free_serialize_result(result_ptr);
        }
    }
    
    // Add additional tests for commit_time in PDA calculation
    #[test]
    fn test_pda_calculation() {
        // This test verifies that PDAs are calculated consistently
        let keypair = Keypair::new();
        let media_hash = [1u8; 32];
        let commit_time = 1713115200u32;
        
        // Calculate PDA manually
        let program_id = Pubkey::from_str(PROGRAM_ID).unwrap();
        let pubkey_bytes = keypair.pubkey().to_bytes();
        let commit_time_bytes = commit_time.to_le_bytes();
        let pda_seeds = &[
            pubkey_bytes.as_ref(), 
            media_hash.as_ref(), 
            commit_time_bytes.as_ref()
        ];
        let (pda1, _bump1) = Pubkey::find_program_address(pda_seeds, &program_id);
        
        // Verify that different commit times produce different PDAs
        let commit_time2 = 1713115201u32;
        let commit_time2_bytes = commit_time2.to_le_bytes();
        let pda_seeds2 = &[
            pubkey_bytes.as_ref(), 
            media_hash.as_ref(), 
            commit_time2_bytes.as_ref()
        ];
        let (pda2, _bump2) = Pubkey::find_program_address(pda_seeds2, &program_id);
        
        assert_ne!(pda1, pda2, "PDAs should be different with different commit times");
        
        // Verify that little-endian encoding is used consistently
        let commit_time_be_bytes = [
            ((commit_time >> 24) & 0xFF) as u8,
            ((commit_time >> 16) & 0xFF) as u8,
            ((commit_time >> 8) & 0xFF) as u8,
            (commit_time & 0xFF) as u8,
        ];
        let pda_seeds_be = &[
            pubkey_bytes.as_ref(), 
            media_hash.as_ref(), 
            &commit_time_be_bytes
        ];
        let (pda_be, _) = Pubkey::find_program_address(pda_seeds_be, &program_id);
        
        assert_ne!(pda1, pda_be, "Big-endian commit time should produce different PDA");
    }
}