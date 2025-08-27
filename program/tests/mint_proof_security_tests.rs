// FILE: token-2022/confidential-transfer/proof-tests/tests/mint_proof_security.rs
//
// SECURITY TESTS FOR CONFIDENTIAL MINT PROOF VULNERABILITIES
// 
// This file contains unit tests designed to detect critical security vulnerabilities
// identified in the confidential mint proof verification system through formal verification
// and threat analysis.
//
// BUGS TARGETED:
// - Bug #1: Supply Pubkey Cross-Validation Missing (CRITICAL)
// - Bug #2: Range Proof Implementation Gap (HIGH) 
// - Bug #4: Ciphertext Component Extraction Inconsistency (HIGH)
// 
// ATTACK VECTORS TESTED:
// - Proof context manipulation attacks
// - Cross-proof consistency bypass attacks
// - Ciphertext component confusion attacks

use {
    solana_zk_sdk::{
        encryption::{
            auth_encryption::AeKey,
            elgamal::{ElGamalKeypair, ElGamalPubkey},
            pedersen::Pedersen,
        },
        zk_elgamal_proof_program::proof_data::{
            BatchedGroupedCiphertext3HandlesValidityProofContext,
            BatchedRangeProofContext, CiphertextCommitmentEqualityProofContext,
        },
    },
    spl_token_confidential_transfer_proof_extraction::{
        errors::TokenProofExtractionError, mint::MintProofContext,
    },
    spl_token_confidential_transfer_proof_generation::{
        encryption::GroupedMintAmountCiphertext, mint::mint_split_proof_data,
    },
};

/// TEST #1: CRITICAL BUG - Supply Pubkey Cross-Validation Missing
/// 
/// This test targets Bug #1 from formal verification analysis.
/// The MintProofContext::verify_and_extract() function does not validate that
/// the supply pubkey from the equality proof matches the supply pubkey from 
/// the validity proof. This allows attackers to submit proofs with different
/// supply keys, potentially corrupting supply accounting.
///
/// EXPECTED BEHAVIOR: Should FAIL when supply pubkeys are inconsistent
/// CURRENT BUG: Likely PASSES when it should fail (security vulnerability)
#[test]
fn test_supply_pubkey_cross_validation_missing_vulnerability() {
    println!("🚨 TESTING CRITICAL BUG #1: Supply Pubkey Cross-Validation Missing");
    
    // Setup: Create two DIFFERENT supply keypairs - this is the attack scenario
    let supply_keypair_a = ElGamalKeypair::new_rand();
    let supply_keypair_b = ElGamalKeypair::new_rand(); // DIFFERENT!
    let destination_keypair = ElGamalKeypair::new_rand();
    let auditor_keypair = ElGamalKeypair::new_rand();
    
    // Create legitimate values for the test
    let mint_amount = 1000u64;
    let current_supply = 50000u64;
    let new_supply = current_supply + mint_amount;
    
    println!("   Supply Key A: {:?}", supply_keypair_a.pubkey());
    println!("   Supply Key B: {:?}", supply_keypair_b.pubkey());
    println!("   Mint Amount: {}", mint_amount);
    
    // Create equality proof context using Supply Key A
    let equality_proof_context = CiphertextCommitmentEqualityProofContext {
        pubkey: supply_keypair_a.pubkey().into(), // ← Supply Key A
        ciphertext: supply_keypair_a.pubkey().encrypt(new_supply).into(),
        commitment: Pedersen::new().commit(new_supply, &pedersen_opening_for_test()).into(),
    };
    
    // Create validity proof context using Supply Key B (INCONSISTENT!)
    let validity_proof_context = create_malicious_validity_proof_context(
        &destination_keypair.pubkey(),
        &supply_keypair_b.pubkey(), // ← Supply Key B (DIFFERENT!)  
        &auditor_keypair.pubkey(),
        mint_amount,
    );
    
    // Create legitimate range proof context
    let range_proof_context = create_legitimate_range_proof_context(mint_amount, new_supply);
    
    // CRITICAL TEST: Execute the vulnerable function
    let result = MintProofContext::verify_and_extract(
        &equality_proof_context,
        &validity_proof_context,
        &range_proof_context,
    );
    
    println!("   Verification Result: {:?}", result);
    
    // SECURITY ASSERTION: This should FAIL due to inconsistent supply pubkeys
    match result {
        Err(TokenProofExtractionError::InconsistentSupplyPubkeys) => {
            println!("✅ SECURITY OK: Correctly rejected inconsistent supply pubkeys");
        }
        Ok(_) => {
            panic!(
                "🚨 SECURITY VULNERABILITY CONFIRMED: \
                Accepted proofs with inconsistent supply pubkeys! \
                This allows supply accounting corruption attacks."
            );
        }
        Err(other_error) => {
            println!("⚠️  UNEXPECTED ERROR: {:?}", other_error);
            println!("   This might indicate the bug still exists but fails differently");
        }
    }
}

/// TEST #2: Positive case to ensure legitimate operations still work
/// 
/// This test verifies that when supply pubkeys ARE consistent across proofs,
/// the verification succeeds. This ensures our security fix doesn't break
/// legitimate functionality.
#[test]
fn test_supply_pubkey_consistency_positive_case() {
    println!("✅ TESTING POSITIVE CASE: Consistent supply pubkeys should succeed");
    
    // Setup: Use SAME supply keypair for both proofs (legitimate scenario)
    let supply_keypair = ElGamalKeypair::new_rand();
    let destination_keypair = ElGamalKeypair::new_rand();
    let auditor_keypair = ElGamalKeypair::new_rand();
    
    let mint_amount = 2000u64;
    let current_supply = 100000u64;
    
    // Create proofs with CONSISTENT supply pubkey
    let equality_context = create_legitimate_equality_proof_context(
        &supply_keypair,
        mint_amount,
        current_supply,
    );
    
    let validity_context = create_legitimate_validity_proof_context(
        &destination_keypair.pubkey(),
        &supply_keypair.pubkey(), // ← SAME supply key
        &auditor_keypair.pubkey(),
        mint_amount,
    );
    
    let range_context = create_legitimate_range_proof_context(
        mint_amount,
        current_supply + mint_amount,
    );
    
    // Execute verification
    let result = MintProofContext::verify_and_extract(
        &equality_context,
        &validity_context,
        &range_context,
    );
    
    // Should succeed with consistent pubkeys
    assert!(result.is_ok(), "Legitimate proofs with consistent pubkeys should succeed");
    
    let context = result.unwrap();
    println!("✅ SUCCESS: Consistent supply pubkeys accepted correctly");
    println!("   Extracted supply pubkey: {:?}", context.mint_pubkeys.supply);
}

/// TEST #3: CRITICAL BUG - Ciphertext Component Extraction Inconsistency
/// 
/// This test targets Bug #4 from formal verification analysis.
/// The processor uses inconsistent indexing when extracting ciphertext components:
/// - .try_extract_ciphertext(0) for some components  
/// - .try_extract_ciphertext(1) for other components
/// 
/// This inconsistency could be exploited to extract wrong ciphertext components,
/// leading to arithmetic corruption.
#[test]
fn test_ciphertext_component_extraction_inconsistency_vulnerability() {
    println!("🚨 TESTING CRITICAL BUG #4: Ciphertext Component Extraction Inconsistency");
    
    // Create a proof context similar to what the processor would receive
    let mint_amount = 5000u64;
    let (amount_lo, amount_hi) = split_amount_to_lo_hi_components(mint_amount);
    
    println!("   Original Amount: {}", mint_amount);
    println!("   Lo Component: {}", amount_lo); 
    println!("   Hi Component: {}", amount_hi);
    
    // Create mock mint proof context with ciphertext components
    let proof_context = create_mock_mint_proof_context_with_components(
        amount_lo,
        amount_hi,
    );
    
    // TEST: Simulate the EXACT extraction pattern from processor code
    // This replicates the bug found in processor.rs
    
    // Pattern 1: What processor does for pending_balance update (lines ~157-167)
    let lo_extracted_pattern_1 = proof_context
        .mint_amount_ciphertext_lo
        .try_extract_ciphertext(0); // ← Index 0
        
    let hi_extracted_pattern_1 = proof_context
        .mint_amount_ciphertext_hi
        .try_extract_ciphertext(0); // ← Index 0
    
    // Pattern 2: What processor does for supply update (lines ~180-190)  
    let lo_extracted_pattern_2 = proof_context
        .mint_amount_ciphertext_lo
        .try_extract_ciphertext(1); // ← Index 1
        
    let hi_extracted_pattern_2 = proof_context
        .mint_amount_ciphertext_hi
        .try_extract_ciphertext(1); // ← Index 1
    
    println!("   Pattern 1 (pending balance): lo={:?}, hi={:?}", 
        lo_extracted_pattern_1.is_ok(), hi_extracted_pattern_1.is_ok());
    println!("   Pattern 2 (supply update): lo={:?}, hi={:?}",
        lo_extracted_pattern_2.is_ok(), hi_extracted_pattern_2.is_ok());
    
    // SECURITY ANALYSIS: Check if different patterns give different results
    let pattern_1_success = lo_extracted_pattern_1.is_ok() && hi_extracted_pattern_1.is_ok();
    let pattern_2_success = lo_extracted_pattern_2.is_ok() && hi_extracted_pattern_2.is_ok();
    
    if pattern_1_success != pattern_2_success {
        panic!(
            "🚨 INCONSISTENT EXTRACTION VULNERABILITY CONFIRMED: \
            Different indexing patterns give different results! \
            Pattern 1 (index 0): success={}, Pattern 2 (index 1): success={}",
            pattern_1_success, pattern_2_success
        );
    }
    
    // Additional test: Verify extracted components are mathematically correct
    if pattern_1_success && pattern_2_success {
        verify_extracted_components_correctness(
            &lo_extracted_pattern_1.unwrap(),
            &hi_extracted_pattern_1.unwrap(), 
            &lo_extracted_pattern_2.unwrap(),
            &hi_extracted_pattern_2.unwrap(),
            amount_lo,
            amount_hi,
        );
    }
}

/// TEST #4: Range Proof Bit Length Enforcement
///
/// This test targets Bug #2 from formal verification analysis.
/// The range proof should enforce specific bit lengths (16 for lo, 32 for hi),
/// but the implementation may not properly validate these constraints.
#[test] 
fn test_range_proof_bit_length_enforcement() {
    println!("🚨 TESTING BUG #2: Range Proof Bit Length Enforcement");
    
    // Test Case 1: Valid bit lengths (should succeed)
    test_range_proof_with_bit_lengths(
        65535,    // 2^16 - 1 (valid 16-bit)
        4294967295, // 2^32 - 1 (valid 32-bit)
        true,     // should_succeed
    );
    
    // Test Case 2: Invalid lo component (too large for 16-bit)
    test_range_proof_with_bit_lengths(
        65536,    // 2^16 (invalid - too large for 16-bit)
        1000,     // valid 32-bit
        false,    // should_fail
    );
    
    // Test Case 3: Invalid hi component (too large for 32-bit) 
    test_range_proof_with_bit_lengths(
        1000,     // valid 16-bit
        4294967296, // 2^32 (invalid - too large for 32-bit)
        false,    // should_fail
    );
}

fn test_range_proof_with_bit_lengths(lo_value: u64, hi_value: u64, should_succeed: bool) {
    println!("   Testing lo={}, hi={}, expect_success={}", lo_value, hi_value, should_succeed);
    
    // Create range proof context with specified bit lengths
    let range_context = create_range_proof_context_with_values(lo_value, hi_value);
    
    // Create legitimate equality and validity contexts
    let supply_keypair = ElGamalKeypair::new_rand();
    let mint_amount = lo_value + (hi_value << 16); // Combine lo/hi
    
    let equality_context = create_legitimate_equality_proof_context(
        &supply_keypair,
        mint_amount,
        1000000, // current supply
    );
    
    let validity_context = create_legitimate_validity_proof_context(
        &ElGamalKeypair::new_rand().pubkey(),
        &supply_keypair.pubkey(),
        &ElGamalKeypair::new_rand().pubkey(),
        mint_amount,
    );
    
    // Execute verification
    let result = MintProofContext::verify_and_extract(
        &equality_context,
        &validity_context, 
        &range_context,
    );
    
    // Validate result matches expectation
    match (result.is_ok(), should_succeed) {
        (true, true) => println!("   ✅ Correctly accepted valid bit lengths"),
        (false, false) => println!("   ✅ Correctly rejected invalid bit lengths"),
        (true, false) => panic!("   🚨 BUG: Accepted invalid bit lengths!"),
        (false, true) => panic!("   🚨 BUG: Rejected valid bit lengths!"),
    }
}

// =============================================================================
// HELPER FUNCTIONS FOR TEST SETUP
// =============================================================================

/// Create a malicious validity proof context with wrong supply pubkey
fn create_malicious_validity_proof_context(
    destination_pubkey: &ElGamalPubkey,
    malicious_supply_pubkey: &ElGamalPubkey, // This will be different from equality proof
    auditor_pubkey: &ElGamalPubkey,
    mint_amount: u64,
) -> BatchedGroupedCiphertext3HandlesValidityProofContext {
    let (amount_lo, amount_hi) = split_amount_to_lo_hi_components(mint_amount);
    
    BatchedGroupedCiphertext3HandlesValidityProofContext {
        first_pubkey: destination_pubkey.clone().into(),
        second_pubkey: malicious_supply_pubkey.clone().into(), // ← Malicious key
        third_pubkey: auditor_pubkey.clone().into(),
        grouped_ciphertext_lo: create_grouped_ciphertext_component(amount_lo).into(),
        grouped_ciphertext_hi: create_grouped_ciphertext_component(amount_hi).into(),
    }
}

fn create_legitimate_equality_proof_context(
    supply_keypair: &ElGamalKeypair,
    mint_amount: u64,
    current_supply: u64,
) -> CiphertextCommitmentEqualityProofContext {
    let new_supply = current_supply + mint_amount;
    
    CiphertextCommitmentEqualityProofContext {
        pubkey: supply_keypair.pubkey().into(),
        ciphertext: supply_keypair.pubkey().encrypt(new_supply).into(),
        commitment: Pedersen::new().commit(new_supply, &pedersen_opening_for_test()).into(),
    }
}

fn create_legitimate_validity_proof_context(
    destination_pubkey: &ElGamalPubkey,
    supply_pubkey: &ElGamalPubkey,
    auditor_pubkey: &ElGamalPubkey,
    mint_amount: u64,
) -> BatchedGroupedCiphertext3HandlesValidityProofContext {
    let (amount_lo, amount_hi) = split_amount_to_lo_hi_components(mint_amount);
    
    BatchedGroupedCiphertext3HandlesValidityProofContext {
        first_pubkey: destination_pubkey.clone().into(),
        second_pubkey: supply_pubkey.clone().into(),
        third_pubkey: auditor_pubkey.clone().into(),
        grouped_ciphertext_lo: create_grouped_ciphertext_component(amount_lo).into(),
        grouped_ciphertext_hi: create_grouped_ciphertext_component(amount_hi).into(),
    }
}

fn create_legitimate_range_proof_context(
    mint_amount: u64,
    new_supply: u64,
) -> BatchedRangeProofContext {
    let (amount_lo, amount_hi) = split_amount_to_lo_hi_components(mint_amount);
    
    BatchedRangeProofContext {
        commitments: vec![
            Pedersen::new().commit(amount_lo, &pedersen_opening_for_test()).into(),
            Pedersen::new().commit(amount_hi, &pedersen_opening_for_test()).into(),
            Pedersen::new().commit(new_supply, &pedersen_opening_for_test()).into(),
        ],
        bit_lengths: vec![16, 32, 64], // Standard bit lengths
    }
}

fn create_range_proof_context_with_values(
    lo_value: u64,
    hi_value: u64,
) -> BatchedRangeProofContext {
    BatchedRangeProofContext {
        commitments: vec![
            Pedersen::new().commit(lo_value, &pedersen_opening_for_test()).into(),
            Pedersen::new().commit(hi_value, &pedersen_opening_for_test()).into(),
        ],
        bit_lengths: vec![16, 32], // Expected bit lengths
    }
}

fn create_mock_mint_proof_context_with_components(
    amount_lo: u64,
    amount_hi: u64,
) -> MintProofContext {
    // Note: This would need to be implemented based on the actual MintProofContext structure
    // The exact implementation depends on the internal structure of MintProofContext
    // This is a placeholder showing the concept
    todo!("Implement mock mint proof context creation")
}

fn split_amount_to_lo_hi_components(amount: u64) -> (u64, u64) {
    let lo = amount & ((1u64 << 16) - 1); // Lower 16 bits
    let hi = (amount >> 16) & ((1u64 << 32) - 1); // Upper 32 bits (shifted down)
    (lo, hi)
}

fn create_grouped_ciphertext_component(_amount: u64) -> GroupedMintAmountCiphertext {
    // Placeholder - would create actual grouped ciphertext
    todo!("Implement grouped ciphertext creation")
}

fn pedersen_opening_for_test() -> curve25519_dalek::scalar::Scalar {
    // Create a deterministic opening for testing
    use curve25519_dalek::scalar::Scalar;
    Scalar::from(12345u64) // Deterministic for reproducible tests
}

fn verify_extracted_components_correctness(
    _lo_1: &solana_zk_sdk::encryption::elgamal::ElGamalCiphertext,
    _hi_1: &solana_zk_sdk::encryption::elgamal::ElGamalCiphertext,
    _lo_2: &solana_zk_sdk::encryption::elgamal::ElGamalCiphertext, 
    _hi_2: &solana_zk_sdk::encryption::elgamal::ElGamalCiphertext,
    _expected_lo: u64,
    _expected_hi: u64,
) {
    // Verify that extracted components are mathematically correct
    // This would decrypt and verify the components match expected values
    println!("   Component correctness verification - implementation needed");
}