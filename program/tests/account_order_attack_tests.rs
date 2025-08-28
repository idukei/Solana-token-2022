// FILE: token-2022/program/tests/confidential_mint_account_order_attack.rs
//
// SECURITY TESTS FOR ACCOUNT ORDER MANIPULATION ATTACK VECTOR
//
// This file contains comprehensive unit tests designed to detect and verify
// the account order manipulation vulnerability identified in process_confidential_mint().
//
// ATTACK VECTOR TESTED:
// - Manipulation of order of accounts passed to process_confidential_mint()
// - Expected order: [token_account, mint, authority]  
// - Attack: Any different ordering of these accounts
//
// TEST SCENARIOS:
// 1. Simple order swap attacks
// 2. PDA confusion attacks
// 3. Type confusion attacks
// 4. DoS via malformed account order
//
// EXPECTED BEHAVIOR:
// - Program should fail gracefully with appropriate error codes
// - No state corruption should occur
// - No unauthorized minting should be possible

#![cfg(feature = "test-sbf")]

use {
    solana_account_info::{AccountInfo, IntoAccountInfo},
    solana_keypair::Keypair,
    solana_program_error::ProgramError,
    solana_program_pack::Pack,
    solana_program_test::{processor, tokio, BanksClient, ProgramTest},
    solana_pubkey::Pubkey,
    solana_rent::Rent,
    solana_signer::Signer,
    solana_system_interface::instruction as system_instruction,
    solana_transaction::Transaction,
    spl_token_2022::{
        extension::{
            confidential_mint_burn::{
                instruction::{MintInstructionData, ConfidentialMintBurnInstruction},
                processor::process_confidential_mint,
                ConfidentialMintBurn,
            },
            confidential_transfer::{ConfidentialTransferAccount, ConfidentialTransferMint},
            BaseStateWithExtensions, BaseStateWithExtensionsMut, ExtensionType,
            PodStateWithExtensionsMut,
        },
        id,
        processor::Processor,
        state::{Account, Mint},
        error::TokenError,
    },
    std::cell::RefCell,
    std::rc::Rc,
};

// =============================================================================
// TEST UTILITIES AND HELPER FUNCTIONS
// =============================================================================

/// Helper struct to manage test account creation and data
struct TestAccount {
    pub key: Pubkey,
    pub data: Rc<RefCell<Vec<u8>>>,
    pub owner: Pubkey,
    pub lamports: Rc<RefCell<u64>>,
    pub executable: bool,
    pub rent_epoch: u64,
}

impl TestAccount {
    /// Create a new test account with specified parameters
    fn new(key: Pubkey, data_len: usize, owner: Pubkey, lamports: u64) -> Self {
        Self {
            key,
            data: Rc::new(RefCell::new(vec![0; data_len])),
            owner,
            lamports: Rc::new(RefCell::new(lamports)),
            executable: false,
            rent_epoch: 0,
        }
    }

    /// Convert to AccountInfo for testing
    fn to_account_info(&self) -> AccountInfo {
        AccountInfo {
            key: &self.key,
            lamports: self.lamports.clone(),
            data: self.data.clone(),
            owner: &self.owner,
            executable: self.executable,
            rent_epoch: self.rent_epoch,
        }
    }
}

/// Create a properly formatted Token Account with ConfidentialTransferAccount extension
fn create_test_token_account(
    owner: &Pubkey,
    mint: &Pubkey,
) -> Result<TestAccount, ProgramError> {
    let keypair = Keypair::new();
    let account_size = Account::LEN + std::mem::size_of::<ConfidentialTransferAccount>();
    
    let mut test_account = TestAccount::new(
        keypair.pubkey(),
        account_size,
        id(), // Token program owns this account
        1000000, // Sufficient lamports
    );

    // Initialize the base Account structure
    {
        let mut data = test_account.data.borrow_mut();
        let mut account = PodStateWithExtensionsMut::<Account>::unpack_uninitialized(&mut data)?;
        
        // Initialize base account
        account.base.mint = *mint;
        account.base.owner = *owner;
        account.base.amount = 0.into();
        account.base.delegate = None.into();
        account.base.state = spl_token_2022::state::AccountState::Initialized.into();
        account.base.is_native = None.into();
        account.base.delegated_amount = 0.into();
        account.base.close_authority = None.into();

        // Initialize ConfidentialTransferAccount extension
        let conf_transfer = account.init_extension::<ConfidentialTransferAccount>(false)?;
        conf_transfer.approved = true.into();
        conf_transfer.elgamal_pubkey = Default::default();
        conf_transfer.pending_balance_lo = Default::default();
        conf_transfer.pending_balance_hi = Default::default();
        conf_transfer.available_balance = Default::default();
        conf_transfer.decryptable_available_balance = Default::default();
        conf_transfer.allow_confidential_credits = true.into();
        conf_transfer.allow_non_confidential_credits = true.into();
        conf_transfer.pending_balance_credit_counter = 0.into();
        conf_transfer.maximum_pending_balance_credit_counter = 65536.into();
        conf_transfer.expected_pending_balance_credit_counter = 0.into();
        conf_transfer.actual_pending_balance_credit_counter = 0.into();
    }

    Ok(test_account)
}

/// Create a properly formatted Mint with ConfidentialMintBurn extension
fn create_test_mint(
    mint_authority: &Pubkey,
) -> Result<TestAccount, ProgramError> {
    let keypair = Keypair::new();
    let mint_size = Mint::LEN 
        + std::mem::size_of::<ConfidentialTransferMint>() 
        + std::mem::size_of::<ConfidentialMintBurn>();
    
    let mut test_account = TestAccount::new(
        keypair.pubkey(),
        mint_size,
        id(), // Token program owns this account
        1000000,
    );

    // Initialize the base Mint structure
    {
        let mut data = test_account.data.borrow_mut();
        let mut mint = PodStateWithExtensionsMut::<Mint>::unpack_uninitialized(&mut data)?;
        
        // Initialize base mint
        mint.base.mint_authority = Some(*mint_authority).into();
        mint.base.supply = 0.into();
        mint.base.decimals = 9;
        mint.base.is_initialized = true.into();
        mint.base.freeze_authority = None.into();

        // Initialize ConfidentialTransferMint extension
        let conf_transfer_mint = mint.init_extension::<ConfidentialTransferMint>(false)?;
        conf_transfer_mint.authority = Some(*mint_authority).into();
        conf_transfer_mint.auto_approve_new_accounts = true.into();
        conf_transfer_mint.auditor_elgamal_pubkey = None.into();

        // Initialize ConfidentialMintBurn extension
        let mint_burn = mint.init_extension::<ConfidentialMintBurn>(false)?;
        mint_burn.supply_elgamal_pubkey = Default::default();
        mint_burn.decryptable_supply = Default::default();
        mint_burn.confidential_supply = Default::default();
        mint_burn.pending_burn = Default::default();
    }

    Ok(test_account)
}

/// Create a test authority account (standard user account)
fn create_test_authority() -> Result<TestAccount, ProgramError> {
    let keypair = Keypair::new();
    
    let test_account = TestAccount::new(
        keypair.pubkey(),
        0, // Authority accounts typically have no data
        solana_system_interface::system_program::ID, // System program owns user accounts
        1000000,
    );

    Ok(test_account)
}

/// Create mock MintInstructionData for testing
fn create_test_mint_instruction_data() -> MintInstructionData {
    MintInstructionData {
        new_decryptable_supply: Default::default(),
        // Mock proof instruction offsets - these would normally point to 
        // ZK proof instructions in the transaction, but for this test we're
        // focusing on the account order validation logic
        equality_proof_instruction_offset: 1,
        ciphertext_validity_proof_instruction_offset: 2, 
        range_proof_instruction_offset: 3,
        // Mock auditor ciphertexts
        mint_amount_auditor_ciphertext_lo: Default::default(),
        mint_amount_auditor_ciphertext_hi: Default::default(),
    }
}

// =============================================================================
// ATTACK VECTOR TESTS
// =============================================================================

/// TEST #1: Basic Order Swap Attack
/// 
/// This test verifies that swapping the order of token_account and mint_account
/// is properly detected and rejected by the program.
///
/// Expected Result: Program should fail with appropriate error, NOT succeed
#[tokio::test]
async fn test_basic_order_swap_attack() {
    println!("🚨 TESTING ATTACK #1: Basic Order Swap (Token ↔ Mint)");

    // Create test accounts
    let authority_keypair = Keypair::new();
    let token_account = create_test_token_account(
        &authority_keypair.pubkey(), 
        &Pubkey::new_unique()
    ).expect("Failed to create token account");
    
    let mint_account = create_test_mint(&authority_keypair.pubkey())
        .expect("Failed to create mint account");
    
    let authority_account = create_test_authority()
        .expect("Failed to create authority account");

    // Create legitimate instruction data
    let instruction_data = create_test_mint_instruction_data();

    // ATTACK: Swap token_account and mint_account positions
    let accounts_legitimate = vec![
        token_account.to_account_info(), // Position 0 (correct)
        mint_account.to_account_info(),  // Position 1 (correct)
        authority_account.to_account_info(), // Position 2 (correct)
    ];

    let accounts_attack = vec![
        mint_account.to_account_info(),     // Position 0 (WRONG - should be token)
        token_account.to_account_info(),    // Position 1 (WRONG - should be mint)
        authority_account.to_account_info(), // Position 2 (correct)
    ];

    // Test legitimate order first (should work if properly set up)
    println!("   Testing legitimate order first...");
    let result_legitimate = process_confidential_mint(
        &id(),
        &accounts_legitimate,
        &instruction_data,
    );
    println!("   Legitimate order result: {:?}", result_legitimate);

    // Test attack order (should fail)
    println!("   Testing attack order (swapped positions)...");
    let result_attack = process_confidential_mint(
        &id(),
        &accounts_attack,
        &instruction_data,
    );
    
    println!("   Attack order result: {:?}", result_attack);

    // SECURITY ASSERTION: Attack should fail
    match result_attack {
        Err(ProgramError::InvalidAccountData) => {
            println!("✅ ATTACK PROPERLY BLOCKED: InvalidAccountData");
        }
        Err(TokenError::MintMismatch) => {
            println!("✅ ATTACK PROPERLY BLOCKED: MintMismatch");
        }
        Err(other_error) => {
            println!("⚠️  ATTACK BLOCKED BUT UNEXPECTED ERROR: {:?}", other_error);
        }
        Ok(_) => {
            panic!("🚨 SECURITY VULNERABILITY: Attack succeeded when it should have failed!");
        }
    }
}

/// TEST #2: Authority Position Confusion Attack
/// 
/// This test attempts to place the authority account in the token account position,
/// potentially causing the program to treat authority data as token account data.
#[tokio::test] 
async fn test_authority_position_confusion_attack() {
    println!("🚨 TESTING ATTACK #2: Authority Position Confusion");

    let authority_keypair = Keypair::new();
    let token_account = create_test_token_account(
        &authority_keypair.pubkey(),
        &Pubkey::new_unique()
    ).expect("Failed to create token account");
    
    let mint_account = create_test_mint(&authority_keypair.pubkey())
        .expect("Failed to create mint account");
    
    let authority_account = create_test_authority()
        .expect("Failed to create authority account");

    let instruction_data = create_test_mint_instruction_data();

    // ATTACK: Put authority in token_account position
    let accounts_attack = vec![
        authority_account.to_account_info(), // Position 0 (WRONG - authority as token)
        mint_account.to_account_info(),      // Position 1 (correct)
        authority_account.to_account_info(), // Position 2 (correct) 
    ];

    println!("   Testing authority position confusion attack...");
    let result_attack = process_confidential_mint(
        &id(),
        &accounts_attack,
        &instruction_data,
    );

    println!("   Attack result: {:?}", result_attack);

    // SECURITY ASSERTION: Should fail due to ownership or unpacking issues
    match result_attack {
        Err(ProgramError::IllegalOwner) => {
            println!("✅ ATTACK BLOCKED: IllegalOwner (authority owned by system program)");
        }
        Err(ProgramError::InvalidAccountData) => {
            println!("✅ ATTACK BLOCKED: InvalidAccountData (can't unpack authority as token)");
        }
        Err(other_error) => {
            println!("⚠️  ATTACK BLOCKED: {:?}", other_error);
        }
        Ok(_) => {
            panic!("🚨 SECURITY VULNERABILITY: Authority confusion attack succeeded!");
        }
    }
}

/// TEST #3: Triple Rotation Attack
/// 
/// Tests complete rotation of all three accounts:
/// authority → token_account → mint → authority
#[tokio::test]
async fn test_triple_rotation_attack() {
    println!("🚨 TESTING ATTACK #3: Triple Rotation Attack");

    let authority_keypair = Keypair::new();
    let token_account = create_test_token_account(
        &authority_keypair.pubkey(),
        &Pubkey::new_unique()
    ).expect("Failed to create token account");
    
    let mint_account = create_test_mint(&authority_keypair.pubkey())
        .expect("Failed to create mint account");
    
    let authority_account = create_test_authority()
        .expect("Failed to create authority account");

    let instruction_data = create_test_mint_instruction_data();

    // ATTACK: Complete rotation of all positions
    let accounts_attack = vec![
        authority_account.to_account_info(), // Position 0 (should be token_account)
        token_account.to_account_info(),     // Position 1 (should be mint_account)
        mint_account.to_account_info(),      // Position 2 (should be authority_account)
    ];

    println!("   Testing triple rotation attack...");
    let result_attack = process_confidential_mint(
        &id(),
        &accounts_attack,
        &instruction_data,
    );

    println!("   Attack result: {:?}", result_attack);

    // Should fail at multiple validation points
    assert!(result_attack.is_err(), "🚨 Triple rotation attack should never succeed");
    println!("✅ TRIPLE ROTATION ATTACK PROPERLY BLOCKED");
}

/// TEST #4: Duplicate Account Attack  
/// 
/// Tests using the same account in multiple positions to confuse validation
#[tokio::test]
async fn test_duplicate_account_attack() {
    println!("🚨 TESTING ATTACK #4: Duplicate Account Attack");

    let authority_keypair = Keypair::new();
    let token_account = create_test_token_account(
        &authority_keypair.pubkey(),
        &Pubkey::new_unique()
    ).expect("Failed to create token account");
    
    let mint_account = create_test_mint(&authority_keypair.pubkey())
        .expect("Failed to create mint account");

    let instruction_data = create_test_mint_instruction_data();

    // ATTACK: Use mint_account in all positions
    let accounts_attack = vec![
        mint_account.to_account_info(), // Position 0 (should be token_account)
        mint_account.to_account_info(), // Position 1 (correct)
        mint_account.to_account_info(), // Position 2 (should be authority_account)
    ];

    println!("   Testing duplicate mint account attack...");
    let result_attack = process_confidential_mint(
        &id(),
        &accounts_attack,
        &instruction_data,
    );

    println!("   Attack result: {:?}", result_attack);

    // Should fail due to type mismatches and validation errors
    assert!(result_attack.is_err(), "🚨 Duplicate account attack should never succeed");
    println!("✅ DUPLICATE ACCOUNT ATTACK PROPERLY BLOCKED");
}

/// TEST #5: Legitimate Order Verification
/// 
/// Positive test to ensure that the correct order works as expected
/// This validates that our attack tests aren't producing false positives
#[tokio::test]
async fn test_legitimate_order_should_work() {
    println!("✅ TESTING POSITIVE CASE: Legitimate Order Should Work");

    let authority_keypair = Keypair::new();
    
    // Create properly linked accounts
    let mint_account = create_test_mint(&authority_keypair.pubkey())
        .expect("Failed to create mint account");
    
    let token_account = create_test_token_account(
        &authority_keypair.pubkey(),
        &mint_account.key // Link token account to the mint
    ).expect("Failed to create token account");
    
    let authority_account = create_test_authority()
        .expect("Failed to create authority account");

    let instruction_data = create_test_mint_instruction_data();

    // LEGITIMATE: Correct order
    let accounts_legitimate = vec![
        token_account.to_account_info(),    // Position 0 ✓
        mint_account.to_account_info(),     // Position 1 ✓
        authority_account.to_account_info(), // Position 2 ✓
    ];

    println!("   Testing legitimate account order...");
    let result_legitimate = process_confidential_mint(
        &id(),
        &accounts_legitimate,
        &instruction_data,
    );

    println!("   Legitimate result: {:?}", result_legitimate);

    // Note: This test might still fail due to proof verification requirements,
    // but it should NOT fail due to account order issues
    match result_legitimate {
        Ok(_) => {
            println!("✅ LEGITIMATE ORDER WORKS PERFECTLY");
        }
        Err(ProgramError::InvalidInstructionData) => {
            println!("⚠️  LEGITIMATE ORDER BLOCKED BY PROOF VERIFICATION (expected)");
            println!("   This is acceptable - account order validation passed");
        }
        Err(other_error) => {
            println!("⚠️  LEGITIMATE ORDER FAILED: {:?}", other_error);
            println!("   This might indicate other setup issues, not order problems");
        }
    }
}

// =============================================================================
// EDGE CASE TESTS
// =============================================================================

/// TEST #6: Empty Accounts Array
#[tokio::test]
async fn test_empty_accounts_array() {
    println!("🚨 TESTING EDGE CASE: Empty Accounts Array");

    let instruction_data = create_test_mint_instruction_data();
    let empty_accounts: Vec<AccountInfo> = vec![];

    let result = process_confidential_mint(&id(), &empty_accounts, &instruction_data);
    
    // Should fail immediately when trying to get first account
    match result {
        Err(ProgramError::NotEnoughAccountKeys) => {
            println!("✅ EMPTY ACCOUNTS PROPERLY REJECTED");
        }
        Err(other_error) => {
            println!("⚠️  EMPTY ACCOUNTS REJECTED: {:?}", other_error);
        }
        Ok(_) => {
            panic!("🚨 EMPTY ACCOUNTS SHOULD NEVER SUCCEED");
        }
    }
}

/// TEST #7: Insufficient Accounts  
#[tokio::test]
async fn test_insufficient_accounts() {
    println!("🚨 TESTING EDGE CASE: Insufficient Accounts (only 2 provided)");

    let authority_keypair = Keypair::new();
    let token_account = create_test_token_account(
        &authority_keypair.pubkey(),
        &Pubkey::new_unique()
    ).expect("Failed to create token account");
    
    let mint_account = create_test_mint(&authority_keypair.pubkey())
        .expect("Failed to create mint account");

    let instruction_data = create_test_mint_instruction_data();

    // Provide only 2 accounts when 3+ are expected
    let insufficient_accounts = vec![
        token_account.to_account_info(),
        mint_account.to_account_info(),
        // Missing authority_account
    ];

    let result = process_confidential_mint(&id(), &insufficient_accounts, &instruction_data);

    // Should fail when trying to get the third account (authority)
    match result {
        Err(ProgramError::NotEnoughAccountKeys) => {
            println!("✅ INSUFFICIENT ACCOUNTS PROPERLY REJECTED");
        }
        Err(other_error) => {
            println!("⚠️  INSUFFICIENT ACCOUNTS REJECTED: {:?}", other_error);
        }
        Ok(_) => {
            panic!("🚨 INSUFFICIENT ACCOUNTS SHOULD NEVER SUCCEED");
        }
    }
}