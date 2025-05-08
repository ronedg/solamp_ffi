use anchor_lang::prelude::*;
use anchor_lang::system_program::ID as SYSTEM_PROGRAM_ID;
use solana_client::rpc_client::RpcClient;
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    transaction::Transaction,
};
use std::ffi::CString;
use std::os::raw::{c_char, c_uchar, c_int};
use std::slice;
use std::str::FromStr;
use blake3::hash;
use serde::Serialize;

// Program ID
pub const PROGRAM_ID: &str = "ENKMqg25PSLyojUB46NQNNbRirxn1t54uuiMo5X8CXjN";

// --- Data Structures ---

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
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

// --- Helper Functions ---

/// Convert a Result to a C string
fn result_to_c_string<T: ToString>(result: std::result::Result<T, FfiError>) -> *mut c_char {
    match result {
        Ok(value) => {
            let c_str = CString::new(value.to_string()).unwrap_or_else(|_| {
                CString::new("Error: Failed to create result string").unwrap()
            });
            c_str.into_raw()
        }
        Err(e) => {
            let error_msg = format!("Error: {}", e.to_string());
            let c_str = CString::new(error_msg).unwrap_or_else(|_| {
                CString::new("Error: Failed to create error message").unwrap()
            });
            c_str.into_raw()
        }
    }
}

/// Validate and convert FFI parameters into Rust types
fn validate_keypair_and_media_hash(
    keypair_bytes: *const c_uchar,
    keypair_len: i32,
    media_hash: *const c_uchar,
) -> std::result::Result<(Keypair, [u8; 32]), FfiError> {
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
    let keypair = match Keypair::from_bytes(keypair_slice) {
        Ok(kp) => kp,
        Err(_) => return Err(FfiError::InvalidKeypair),
    };

    let media_hash_slice = unsafe { slice::from_raw_parts(media_hash, EXPECTED_MEDIA_HASH_LEN) };
    let media_hash = match media_hash_slice.try_into() {
        Ok(hash) => hash,
        Err(_) => {
            return Err(FfiError::InvalidInput(format!(
                "Invalid media_hash length: {}, expected: {}",
                media_hash_slice.len(), EXPECTED_MEDIA_HASH_LEN
            )));
        }
    };

    Ok((keypair, media_hash))
}

/// Calculate PDA from keypair, media hash and commit time
fn calculate_pda_internal(
    keypair: &Keypair,
    media_hash: &[u8; 32],
    commit_time: u32,
) -> std::result::Result<(Pubkey, u8), FfiError> {
    let program_id = match Pubkey::from_str(PROGRAM_ID) {
        Ok(id) => id,
        Err(_) => return Err(FfiError::InvalidInput("Invalid program ID".to_string())),
    };
    
    let pubkey_bytes = keypair.pubkey().to_bytes();
    let commit_time_bytes = commit_time.to_le_bytes();
    let pda_seeds = &[
        pubkey_bytes.as_ref(), 
        media_hash.as_ref(), 
        commit_time_bytes.as_ref()
    ];
    
    Ok(Pubkey::find_program_address(pda_seeds, &program_id))
}

// --- FFI Functions ---

/// FFI function to serialize metadata and add a record to the blockchain
#[no_mangle]
pub extern "C" fn serialize_and_add_record(
    keypair_bytes: *const c_uchar,
    keypair_len: c_int,
    media_hash: *const c_uchar,
    protocol_version: *const c_uchar,
    session_id: *const c_uchar,
    timestamp: u32,
    lat: *const f32,
    lon: *const f32,
    fuzzed: u8,
    fuzz_radius: *const f32,
    device: *const c_uchar,
    flags: u8,
    tee_signature: *const c_uchar,
    tee_public_key: *const c_uchar,
    developer_signature: *const c_uchar,
    certificate_id: *const c_uchar,
    media_ref: *const c_uchar,
    commit_time: u32,
) -> *mut c_char {
    // Step 1: Serialize metadata
    let result = unsafe {
        if media_hash.is_null() || protocol_version.is_null() || session_id.is_null() || 
           lat.is_null() || lon.is_null() || fuzz_radius.is_null() || device.is_null() {
            return result_to_c_string::<String>(Err(FfiError::InvalidInput("Null pointer passed".to_string())));
        }

        // Extract metadata parts
        let protocol_version = match slice::from_raw_parts(protocol_version, 4).try_into() {
            Ok(v) => v,
            Err(_) => return result_to_c_string::<String>(Err(FfiError::InvalidInput("Invalid protocol version".to_string()))),
        };
        
        let session_id = match slice::from_raw_parts(session_id, 16).try_into() {
            Ok(s) => s,
            Err(_) => return result_to_c_string::<String>(Err(FfiError::InvalidInput("Invalid session ID".to_string()))),
        };
        
        let lat = lat.as_ref().map(|&x| x);
        let lon = lon.as_ref().map(|&x| x);
        let fuzz_radius = fuzz_radius.as_ref().map(|&x| x);
        
        let device = match slice::from_raw_parts(device, 16).try_into() {
            Ok(d) => d,
            Err(_) => return result_to_c_string::<String>(Err(FfiError::InvalidInput("Invalid device".to_string()))),
        };

        // Create metadata
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

        // Serialize
        let metadata_serialized = match metadata.try_to_vec() {
            Ok(data) => data,
            Err(_) => return result_to_c_string::<String>(Err(FfiError::InvalidInput("Failed to serialize metadata".to_string()))),
        };

        // Compute metadata hash
        let media_hash_array: [u8; 32] = match slice::from_raw_parts(media_hash, 32).try_into() {
            Ok(h) => h,
            Err(_) => return result_to_c_string::<String>(Err(FfiError::InvalidInput("Invalid media hash".to_string()))),
        };
        
        let mut hash_input = Vec::with_capacity(32 + metadata_serialized.len());
        hash_input.extend_from_slice(&media_hash_array);
        hash_input.extend_from_slice(&metadata_serialized);
        let hash_full = hash(&hash_input);
        let metadata_hash: [u8; 24] = hash_full.as_bytes()[..24].try_into().unwrap();

        // Extract other parameters
        let tee_signature_slice = slice::from_raw_parts(tee_signature, EXPECTED_TEE_SIGNATURE_LEN);
        let tee_signature: [u8; 64] = match tee_signature_slice.try_into() {
            Ok(s) => s,
            Err(_) => return result_to_c_string::<String>(Err(FfiError::InvalidInput("Invalid TEE signature".to_string()))),
        };
        
        let tee_public_key_slice = slice::from_raw_parts(tee_public_key, EXPECTED_TEE_PUBLIC_KEY_LEN);
        let tee_public_key: [u8; 32] = match tee_public_key_slice.try_into() {
            Ok(k) => k,
            Err(_) => return result_to_c_string::<String>(Err(FfiError::InvalidInput("Invalid TEE public key".to_string()))),
        };
        
        let developer_signature_slice = slice::from_raw_parts(developer_signature, EXPECTED_DEVELOPER_SIGNATURE_LEN);
        let developer_signature: [u8; 64] = match developer_signature_slice.try_into() {
            Ok(s) => s,
            Err(_) => return result_to_c_string::<String>(Err(FfiError::InvalidInput("Invalid developer signature".to_string()))),
        };
        
        let certificate_id_slice = slice::from_raw_parts(certificate_id, EXPECTED_CERTIFICATE_ID_LEN);
        let certificate_id: [u8; 16] = match certificate_id_slice.try_into() {
            Ok(id) => id,
            Err(_) => return result_to_c_string::<String>(Err(FfiError::InvalidInput("Invalid certificate ID".to_string()))),
        };
        
        let media_ref_slice = slice::from_raw_parts(media_ref, EXPECTED_MEDIA_REF_LEN);
        let media_ref: [u8; 46] = match media_ref_slice.try_into() {
            Ok(r) => r,
            Err(_) => return result_to_c_string::<String>(Err(FfiError::InvalidInput("Invalid media reference".to_string()))),
        };

        // Step 2: Add record to blockchain
        try_send_add_record(
            keypair_bytes,
            keypair_len,
            &media_hash_array,
            &metadata_hash,
            &tee_signature,
            &tee_public_key,
            &developer_signature,
            &certificate_id,
            &media_ref,
            commit_time,
            metadata,
        )
    };
    
    result_to_c_string(result)
}

/// Add a record to the blockchain
fn try_send_add_record(
    keypair_bytes: *const c_uchar,
    keypair_len: c_int,
    media_hash: &[u8; 32],
    metadata_hash: &[u8; 24],
    tee_signature: &[u8; 64],
    tee_public_key: &[u8; 32],
    developer_signature: &[u8; 64],
    certificate_id: &[u8; 16],
    media_ref: &[u8; 46],
    commit_time: u32,
    metadata: Metadata,
) -> std::result::Result<String, FfiError> {
    // Validate and extract keypair
    let (keypair, _) = validate_keypair_and_media_hash(keypair_bytes, keypair_len, media_hash.as_ptr())?;

    // Create RPC client
    let client = RpcClient::new("https://api.devnet.solana.com".to_string());

    // Get program ID
    let program_id = match Pubkey::from_str(PROGRAM_ID) {
        Ok(id) => id,
        Err(_) => return Err(FfiError::InvalidInput("Invalid program ID".to_string())),
    };
    
    // Calculate PDA
    let (pda, _) = calculate_pda_internal(&keypair, media_hash, commit_time)?;

    // Create instruction data
    let add_record_instruction = AddRecord {
        media_hash: *media_hash,
        metadata_hash: *metadata_hash,
        metadata,
        tee_signature: *tee_signature,
        tee_public_key: *tee_public_key,
        developer_signature: *developer_signature,
        certificate_id: *certificate_id,
        media_ref: *media_ref,
        commit_time,
    };

    // Create instruction
    let discriminator = anchor_lang::solana_program::hash::hash(b"global:add_record").to_bytes()[..8].to_vec();
    let mut instruction_data = discriminator;
    
    let serialized_data = match add_record_instruction.try_to_vec() {
        Ok(data) => data,
        Err(_) => return Err(FfiError::InvalidInput("Failed to serialize AddRecord".to_string())),
    };
    
    instruction_data.extend_from_slice(&serialized_data);

    let accounts = vec![
        AccountMeta::new(pda, false),
        AccountMeta::new(keypair.pubkey(), true),
        AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
    ];
    let instruction = Instruction::new_with_bytes(program_id, &instruction_data, accounts);

    // Send transaction
    let recent_blockhash = match client.get_latest_blockhash() {
        Ok(hash) => hash,
        Err(e) => return Err(FfiError::SolanaClientError(e)),
    };
    
    let transaction = Transaction::new_signed_with_payer(
        &[instruction],
        Some(&keypair.pubkey()),
        &[&keypair],
        recent_blockhash,
    );

    match client.send_and_confirm_transaction(&transaction) {
        Ok(signature) => Ok(signature.to_string()),
        Err(e) => Err(FfiError::SolanaClientError(e)),
    }
}

/// FFI function to delete a record from the blockchain
#[no_mangle]
pub extern "C" fn delete_record_wrapper(
    keypair_bytes: *const c_uchar,
    keypair_len: c_int,
    media_hash: *const c_uchar,
    commit_time: u32,
) -> *mut c_char {
    // Validate input parameters
    let validated = validate_keypair_and_media_hash(keypair_bytes, keypair_len, media_hash);
    
    let result = match validated {
        Ok((keypair, media_hash)) => {
            // Log inputs for debugging
            println!("deleteRecordWrapper inputs:");
            println!("  keypair pubkey: {}", keypair.pubkey());
            println!("  mediaHash: {:?}", media_hash.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(""));
            println!("  commitTime: {} (hex: {:08x})", commit_time, commit_time);
            
            // Calculate PDA
            let pda_result = calculate_pda_internal(&keypair, &media_hash, commit_time);
            match pda_result {
                Ok((pda, bump)) => {
                    println!("  PDA: {}:{}", pda, bump);
                    
                    // Create RPC client and prepare transaction
                    let client = RpcClient::new("https://api.devnet.solana.com".to_string());
                    let program_id = match Pubkey::from_str(PROGRAM_ID) {
                        Ok(id) => id,
                        Err(_) => return result_to_c_string::<String>(Err(FfiError::InvalidInput("Invalid program ID".to_string()))),
                    };
                    
                    // Create delete instruction
                    let delete_record_instruction = DeleteRecord {
                        commit_time,  // Include commit_time parameter here
                    };
                    
                    let discriminator = anchor_lang::solana_program::hash::hash(b"global:delete_record").to_bytes()[..8].to_vec();
                    println!("  Discriminator: {:?}", discriminator.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(""));
                    
                    let mut instruction_data = discriminator;
                    
                    let serialized_data = match delete_record_instruction.try_to_vec() {
                        Ok(data) => data,
                        Err(_) => return result_to_c_string::<String>(Err(FfiError::InvalidInput("Failed to serialize DeleteRecord".to_string()))),
                    };
                    
                    println!("  DeleteRecord payload: {:?}", serialized_data.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(""));
                    instruction_data.extend_from_slice(&serialized_data);
                    
                    let accounts = vec![
                        AccountMeta::new(pda, false),
                        AccountMeta::new(keypair.pubkey(), true),
                    ];
                    
                    let instruction = Instruction::new_with_bytes(program_id, &instruction_data, accounts);
                    
                    // Send transaction
                    let recent_blockhash = match client.get_latest_blockhash() {
                        Ok(hash) => hash,
                        Err(e) => return result_to_c_string::<String>(Err(FfiError::SolanaClientError(e))),
                    };
                    
                    let transaction = Transaction::new_signed_with_payer(
                        &[instruction],
                        Some(&keypair.pubkey()),
                        &[&keypair],
                        recent_blockhash,
                    );
                    
                    match client.send_and_confirm_transaction(&transaction) {
                        Ok(signature) => Ok(signature.to_string()),
                        Err(e) => Err(FfiError::SolanaClientError(e)),
                    }
                },
                Err(e) => Err(e),
            }
        },
        Err(e) => Err(e),
    };
    
    result_to_c_string(result)
}

/// FFI function to check if a record exists on the blockchain
#[no_mangle]
pub extern "C" fn exists_record(
    keypair_bytes: *const c_uchar,
    keypair_len: c_int,
    media_hash: *const c_uchar,
    commit_time: u32,
) -> *mut c_char {
    let validated = validate_keypair_and_media_hash(keypair_bytes, keypair_len, media_hash);
    
    let result = match validated {
        Ok((keypair, media_hash)) => {
            let client = RpcClient::new("https://api.devnet.solana.com".to_string());
            
            // Calculate PDA
            match calculate_pda_internal(&keypair, &media_hash, commit_time) {
                Ok((pda, _)) => {
                    // Check if account exists
                    match client.get_account_data(&pda) {
                        Ok(_) => Ok("1".to_string()),
                        Err(e) if matches!(e.kind(), solana_client::client_error::ClientErrorKind::RpcError(
                            solana_client::rpc_request::RpcError::RpcRequestError(_)
                        )) => Ok("0".to_string()),
                        Err(e) => Err(FfiError::SolanaClientError(e)),
                    }
                },
                Err(e) => Err(e),
            }
        },
        Err(e) => Err(e),
    };
    
    result_to_c_string(result)
}

/// FFI function to calculate a Program Derived Address (PDA) for a record
#[no_mangle]
pub extern "C" fn calculate_pda(
    keypair_bytes: *const c_uchar,
    keypair_len: c_int,
    media_hash: *const c_uchar, 
    commit_time: u32
) -> *mut c_char {
    let validated = validate_keypair_and_media_hash(keypair_bytes, keypair_len, media_hash);
    
    let result = match validated {
        Ok((keypair, media_hash)) => {
            match calculate_pda_internal(&keypair, &media_hash, commit_time) {
                Ok((pda, bump)) => Ok(format!("{}:{}", pda.to_string(), bump)),
                Err(e) => Err(e),
            }
        },
        Err(e) => Err(e),
    };
    
    result_to_c_string(result)
}

/// Free a C string previously allocated by an FFI function
#[no_mangle]
pub extern "C" fn free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        unsafe {
            let _ = CString::from_raw(ptr);
        }
    }
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

// Must include commit_time parameter for proper deserialization on the program side
#[derive(AnchorSerialize)]
pub struct DeleteRecord {
    pub commit_time: u32,
}
#[cfg(test)]
mod tests {
    use super::*;
    use anchor_lang::solana_program::hash::hash;
    
    #[test]
    fn test_metadata_hash_calculation() {
        // Create test inputs
        let media_hash: [u8; 32] = [0x9a, 0x81, 0x59, 0xbd, 0x31, 0x72, 0x3a, 0x47, 
                                    0xf6, 0x47, 0x09, 0x3b, 0x35, 0xe1, 0x17, 0x66,
                                    0xe5, 0x2e, 0x23, 0xad, 0x8d, 0xb3, 0xa0, 0xa5,
                                    0x20, 0x93, 0xea, 0x39, 0xc1, 0x0e, 0xef, 0x03];
                                    
        let metadata = Metadata {
            protocol_version: [1, 0, 0, 0],
            session_id: [0; 16],
            timestamp: 1746667195,
            lat: Some(43.246),
            lon: Some(-70.868),
            fuzzed: 1,
            fuzz_radius: Some(1609.0),
            device: [83, 77, 45, 65, 49, 51, 53, 85, 0, 0, 0, 0, 0, 0, 0, 0],
            flags: 3,
        };
        
        // Serialize metadata
        let metadata_bytes = metadata.try_to_vec().unwrap();
        
        // Calculate the hash
        let mut hash_input = Vec::with_capacity(32 + metadata_bytes.len());
        hash_input.extend_from_slice(&media_hash);
        hash_input.extend_from_slice(&metadata_bytes);
        let hash_result = hash(&hash_input);
        let metadata_hash: [u8; 24] = hash_result.to_bytes()[..24].try_into().unwrap();
        
        // Verify hash is not all zeros (basic sanity check)
        assert!(metadata_hash.iter().any(|&x| x != 0), 
                "Metadata hash is all zeros, which is highly unlikely");
    }

    #[test]
    fn test_metadata_hash_calculation2() {
        // Create test inputs
        let media_hash: [u8; 32] = [0x9a, 0x81, 0x59, 0xbd, 0x31, 0x72, 0x3a, 0x47, 
                                   0xf6, 0x47, 0x09, 0x3b, 0x35, 0xe1, 0x17, 0x66,
                                   0xe5, 0x2e, 0x23, 0xad, 0x8d, 0xb3, 0xa0, 0xa5,
                                   0x20, 0x93, 0xea, 0x39, 0xc1, 0x0e, 0xef, 0x03];
                                   
        let metadata = Metadata {
            protocol_version: [1, 0, 0, 0],
            session_id: [0; 16],
            timestamp: 1746667195,
            lat: Some(43.246),
            lon: Some(-70.868),
            fuzzed: 1,
            fuzz_radius: Some(1609.0),
            device: [83, 77, 45, 65, 49, 51, 53, 85, 0, 0, 0, 0, 0, 0, 0, 0],
            flags: 3,
        };
        
        // Serialize metadata
        let metadata_bytes = metadata.try_to_vec().unwrap();
        
        // Calculate the hash
        let mut hash_input = Vec::with_capacity(32 + metadata_bytes.len());
        hash_input.extend_from_slice(&media_hash);
        hash_input.extend_from_slice(&metadata_bytes);
        let hash_result = hash(&hash_input);  // Using anchor_lang::solana_program::hash::hash
        let metadata_hash: [u8; 24] = hash_result.to_bytes()[..24].try_into().unwrap();
        
        // Verify hash is not all zeros (basic sanity check)
        assert!(metadata_hash.iter().any(|&x| x != 0), 
                "Metadata hash is all zeros, which is highly unlikely");
    }
    
    #[test]
    fn test_delete_record_instruction_serialization() {
        // Test with commit_time
        let commit_time: u32 = 1746667195;
        let delete_instruction = DeleteRecord { commit_time };
        
        // Serialize the DeleteRecord
        let serialized = delete_instruction.try_to_vec().unwrap();
        
        // Verify serialized data
        assert_eq!(serialized.len(), 4, "Serialized DeleteRecord should be 4 bytes (u32)");
        
        // Verify serialized commit_time
        let expected_bytes = commit_time.to_le_bytes();
        assert_eq!(serialized, expected_bytes, 
                  "Serialized DeleteRecord should contain commit_time as little-endian bytes");
        
        // Compute the instruction discriminator
        let discriminator = anchor_lang::solana_program::hash::hash(b"global:delete_record").to_bytes()[..8].to_vec();
        println!("Delete Record Discriminator: {:?}", discriminator.iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<String>>()
            .join(""));
            
        // Full instruction data
        let mut instruction_data = discriminator;
        instruction_data.extend_from_slice(&serialized);
        
        println!("Full delete instruction data: {:?}", instruction_data.iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<String>>()
            .join(""));
    }
    
    #[test]
    fn test_pda_calculation() {
        // Create test keypair (for testing only)
        let keypair = Keypair::new();
        
        // Test inputs
        let media_hash: [u8; 32] = [0x9a, 0x81, 0x59, 0xbd, 0x31, 0x72, 0x3a, 0x47, 
                                   0xf6, 0x47, 0x09, 0x3b, 0x35, 0xe1, 0x17, 0x66,
                                   0xe5, 0x2e, 0x23, 0xad, 0x8d, 0xb3, 0xa0, 0xa5,
                                   0x20, 0x93, 0xea, 0x39, 0xc1, 0x0e, 0xef, 0x03];
        let commit_time: u32 = 1746667195;
        
        // PDA calculation
        let pubkey_bytes = keypair.pubkey().to_bytes();
        let commit_time_bytes = commit_time.to_le_bytes();
        
        // For debugging
        println!("Signer key: {}", keypair.pubkey());
        println!("Media hash: {:?}", media_hash.iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<String>>()
            .join(""));
        println!("Commit time: {} (hex: {:08x})", commit_time, commit_time);
        
        // Calculate PDA
        let program_id = Pubkey::from_str(PROGRAM_ID).unwrap();
        let seeds = &[
            pubkey_bytes.as_ref(),
            media_hash.as_ref(),
            commit_time_bytes.as_ref(),
        ];
        
        let (pda, bump) = Pubkey::find_program_address(seeds, &program_id);
        
        // Verify PDA is not the default public key
        assert_ne!(pda, Pubkey::default(), "PDA should not be the default pubkey");
        // Bump should be between 0-255
        assert!(bump < 255, "Bump seed should be < 255");
        
        println!("PDA: {}", pda);
        println!("Bump seed: {}", bump);
    }
}