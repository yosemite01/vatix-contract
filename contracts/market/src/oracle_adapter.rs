#![allow(dead_code)]

//! Oracle adapter interface — feature-gated stub for issue #139.
//!
//! Provides an `OracleAdapter` trait that abstracts over the existing
//! Ed25519 single-signer path, the Reflector on-chain oracle, and Pyth.
//! Concrete implementations for Reflector and Pyth are unimplemented stubs;
//! see docs/adr-001-oracle-adapter.md for the design rationale and testnet
//! comparison.
//!
//! # no_std / Soroban note
//! `dyn OracleAdapter` requires heap allocation and is unavailable in this
//! `#![no_std]` crate.  Callers should either monomorphise over a concrete
//! adapter type (`impl OracleAdapter`) or use the [`AnyAdapter`] enum for
//! runtime dispatch without an allocator.

use crate::error::ContractError;
use soroban_sdk::{contracttype, Address, Bytes, BytesN, Env, IntoVal, Symbol, Val, Vec};

// ---------------------------------------------------------------------------
// Trait
// ---------------------------------------------------------------------------

/// Adapter-agnostic interface for resolving a prediction-market outcome.
///
/// Each implementor bridges between the contract's binary `(market_id,
/// outcome)` model and a specific oracle provider's on-chain proof mechanism.
pub trait OracleAdapter {
    /// Verify that `outcome` is the correct resolution for `market_id`.
    ///
    /// `proof` carries adapter-specific evidence:
    /// - [`Ed25519Adapter`]: exactly 64 bytes — the Ed25519 signature produced
    ///   by the market's stored oracle key over
    ///   `keccak256(market_id_be || outcome_byte)`.
    /// - [`ReflectorAdapter`]: empty (`Bytes::new`); the adapter fetches the
    ///   price on-chain from the Reflector contract.
    /// - [`PythAdapter`]: raw Wormhole VAA bytes containing the price
    ///   attestation; the adapter submits them to the Pyth receiver contract
    ///   before reading the verified price.
    ///
    /// # Errors
    /// Returns [`ContractError::InvalidSignature`] or
    /// [`ContractError::UnauthorizedOracle`] on verification failure.
    fn verify_outcome(
        &self,
        env: &Env,
        market_id: u32,
        outcome: bool,
        proof: &Bytes,
    ) -> Result<(), ContractError>;
}

// ---------------------------------------------------------------------------
// Ed25519 adapter — wraps the existing single-signer path
// ---------------------------------------------------------------------------

/// Wraps the existing Ed25519 single-signer path as an [`OracleAdapter`].
///
/// `proof` must be exactly 64 bytes (the Ed25519 signature).  Delegates to
/// [`crate::oracle::verify_oracle_signature`] so behaviour is identical to
/// the pre-adapter code path.
pub struct Ed25519Adapter<'a> {
    pub oracle_pubkey: &'a BytesN<32>,
}

impl<'a> OracleAdapter for Ed25519Adapter<'a> {
    fn verify_outcome(
        &self,
        env: &Env,
        market_id: u32,
        outcome: bool,
        proof: &Bytes,
    ) -> Result<(), ContractError> {
        let sig: BytesN<64> =
            BytesN::try_from(proof.clone()).map_err(|_| ContractError::InvalidSignature)?;
        crate::oracle::verify_oracle_signature(env, market_id, outcome, &sig, self.oracle_pubkey)
    }
}

// ---------------------------------------------------------------------------
// Reflector adapter
// ---------------------------------------------------------------------------

/// Mirror of the `Asset` contracttype accepted by the Reflector oracle.
///
/// Variant names and field types must match the Reflector contract's XDR
/// encoding exactly so that cross-contract serialisation round-trips cleanly.
/// See <https://reflector.network> for the canonical contract source.
#[contracttype]
pub enum ReflectorAsset {
    /// A Stellar-native token identified by its contract address.
    Stellar(Address),
    /// An off-chain asset identified by a short symbol (e.g. `"BTC"`).
    Other(Symbol),
}

/// Mirror of the `PriceData` contracttype returned by the Reflector oracle.
///
/// Field names and order must match the Reflector contract's XDR encoding.
#[contracttype]
struct ReflectorPriceData {
    price: i128,
    timestamp: u64,
}

/// Adapter for the [Reflector](https://reflector.network) on-chain price oracle.
///
/// Reflector is a Stellar-native, threshold-multisig federated oracle.
/// Integration is a single cross-contract call — no off-chain keeper required.
/// The adapter fetches `lastprice(asset)` and compares the returned price
/// against `resolution_price` to derive the outcome.
///
/// Testnet contract (2026-06-20):
/// `CAZP4SMCQX7L6O42AT4GLLRRSFDXPXS7IH7MMHZ52QWUQBFPXFQVMGQ`
pub struct ReflectorAdapter {
    /// Address of the Reflector contract on the target network.
    pub contract_id: Address,
    /// Asset to query via `lastprice`.
    pub asset: ReflectorAsset,
    /// Price threshold in the same unit as `ReflectorPriceData.price`
    /// (fixed-point integer scaled by the Reflector contract's decimal factor).
    /// The outcome resolves YES when `lastprice >= resolution_price`.
    pub resolution_price: i128,
}

impl OracleAdapter for ReflectorAdapter {
    /// Fetches the latest price from the Reflector contract and compares it
    /// against `resolution_price` to determine whether `outcome` is correct.
    ///
    /// Returns [`ContractError::InvalidSignature`] when:
    /// - the Reflector contract has no price for the asset (`lastprice` → `None`), or
    /// - the derived outcome (`price >= resolution_price`) does not match `outcome`.
    fn verify_outcome(
        &self,
        env: &Env,
        _market_id: u32,
        outcome: bool,
        _proof: &Bytes,
    ) -> Result<(), ContractError> {
        let args: Vec<Val> = soroban_sdk::vec![env, self.asset.into_val(env)];
        let maybe_price: Option<ReflectorPriceData> =
            env.invoke_contract(&self.contract_id, &Symbol::new(env, "lastprice"), args);

        match maybe_price {
            None => Err(ContractError::InvalidSignature),
            Some(data) => {
                let resolved_yes = data.price >= self.resolution_price;
                if resolved_yes != outcome {
                    return Err(ContractError::InvalidSignature);
                }
                Ok(())
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Pyth adapter stub
// ---------------------------------------------------------------------------

/// Stub for the [Pyth Network](https://pyth.network) cross-chain price oracle.
///
/// Pyth on Soroban uses a pull model: the resolution caller (or a keeper)
/// must first submit a Wormhole VAA via `update_price_feeds`, after which the
/// verified price can be read with `get_price`.  `proof` carries the raw VAA
/// bytes from the Hermes off-chain API.
///
/// Testnet receiver contract (Stellar testnet, 2026-06-20):
/// `HDWN46CTTXDZ5L5SWKQFUU25L5R2L6XNMCPDWP34PZMBVQJMZAPDVSN`
///
/// # Status
/// Unimplemented stub — see docs/adr-001-oracle-adapter.md.
pub struct PythAdapter {
    /// Address of the Pyth Soroban receiver contract on the target network.
    pub contract_id: Address,
    /// 32-byte Pyth price-feed ID for the asset this market tracks.
    pub price_feed_id: BytesN<32>,
}

impl OracleAdapter for PythAdapter {
    fn verify_outcome(
        &self,
        _env: &Env,
        _market_id: u32,
        _outcome: bool,
        _proof: &Bytes,
    ) -> Result<(), ContractError> {
        // TODO(#324): Two-step Pyth integration.
        //
        // Step 1 — submit VAA (caller passes Hermes-fetched bytes in `proof`):
        //   _env.invoke_contract(&self.contract_id,
        //       &Symbol::new(_env, "update_price_feeds"), (_proof.clone(),).into_val(_env));
        //
        // Step 2 — read verified price:
        //   let price: PythPrice = _env.invoke_contract(&self.contract_id,
        //       &Symbol::new(_env, "get_price"), (self.price_feed_id.clone(),).into_val(_env));
        //
        //   let resolved_yes = price.price >= self.resolution_price;
        //   if resolved_yes != _outcome { return Err(ContractError::InvalidSignature); }
        //   Ok(())
        unimplemented!("Pyth adapter — tracked in #324")
    }
}

// ---------------------------------------------------------------------------
// Runtime-dispatch enum (no heap required)
// ---------------------------------------------------------------------------

/// Runtime-dispatch wrapper over the three adapter variants.
///
/// Use this when the adapter kind is determined at runtime but `dyn
/// OracleAdapter` is unavailable (no heap in `#![no_std]`).
pub enum AnyAdapter<'a> {
    Ed25519(Ed25519Adapter<'a>),
    Reflector(ReflectorAdapter),
    Pyth(PythAdapter),
}

impl<'a> OracleAdapter for AnyAdapter<'a> {
    fn verify_outcome(
        &self,
        env: &Env,
        market_id: u32,
        outcome: bool,
        proof: &Bytes,
    ) -> Result<(), ContractError> {
        match self {
            AnyAdapter::Ed25519(a) => a.verify_outcome(env, market_id, outcome, proof),
            AnyAdapter::Reflector(a) => a.verify_outcome(env, market_id, outcome, proof),
            AnyAdapter::Pyth(a) => a.verify_outcome(env, market_id, outcome, proof),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{contract, contractimpl, testutils::Address as _, Env};

    // ---- Mock Reflector contract ----

    /// A minimal mock of the Reflector oracle contract for unit tests.
    /// Registered in the Soroban test environment so that `invoke_contract`
    /// resolves without network I/O.
    #[contract]
    struct MockReflector;

    /// Controls what `MockReflector` returns during the current test.
    #[contracttype]
    #[derive(Clone)]
    pub enum MockMode {
        ReturnPrice(i128),
        ReturnNone,
    }

    #[contractimpl]
    impl MockReflector {
        pub fn set_mode(env: Env, mode: MockMode) {
            env.storage().instance().set(&soroban_sdk::symbol_short!("mode"), &mode);
        }

        pub fn lastprice(env: Env, _asset: ReflectorAsset) -> Option<ReflectorPriceData> {
            let mode: MockMode = env
                .storage()
                .instance()
                .get(&soroban_sdk::symbol_short!("mode"))
                .unwrap_or(MockMode::ReturnNone);
            match mode {
                MockMode::ReturnPrice(p) => Some(ReflectorPriceData { price: p, timestamp: 1_000_000 }),
                MockMode::ReturnNone => None,
            }
        }
    }

    fn setup_mock_reflector(env: &Env) -> Address {
        env.register(MockReflector, ())
    }

    // ---- ReflectorAdapter tests ----

    #[test]
    fn reflector_returns_ok_when_price_meets_threshold_yes() {
        let env = Env::default();
        let contract_id = setup_mock_reflector(&env);
        let mock_client = MockReflectorClient::new(&env, &contract_id);
        mock_client.set_mode(&MockMode::ReturnPrice(1_000));

        let adapter = ReflectorAdapter {
            contract_id,
            asset: ReflectorAsset::Other(Symbol::new(&env, "BTC")),
            resolution_price: 1_000,
        };
        // price (1_000) >= resolution_price (1_000) → YES
        assert_eq!(
            adapter.verify_outcome(&env, 1, true, &Bytes::new(&env)),
            Ok(())
        );
    }

    #[test]
    fn reflector_returns_ok_when_price_below_threshold_no() {
        let env = Env::default();
        let contract_id = setup_mock_reflector(&env);
        let mock_client = MockReflectorClient::new(&env, &contract_id);
        mock_client.set_mode(&MockMode::ReturnPrice(999));

        let adapter = ReflectorAdapter {
            contract_id,
            asset: ReflectorAsset::Other(Symbol::new(&env, "BTC")),
            resolution_price: 1_000,
        };
        // price (999) < resolution_price (1_000) → NO
        assert_eq!(
            adapter.verify_outcome(&env, 1, false, &Bytes::new(&env)),
            Ok(())
        );
    }

    #[test]
    fn reflector_returns_invalid_signature_on_outcome_mismatch() {
        let env = Env::default();
        let contract_id = setup_mock_reflector(&env);
        let mock_client = MockReflectorClient::new(&env, &contract_id);
        // price meets threshold but caller claims NO
        mock_client.set_mode(&MockMode::ReturnPrice(2_000));

        let adapter = ReflectorAdapter {
            contract_id,
            asset: ReflectorAsset::Other(Symbol::new(&env, "ETH")),
            resolution_price: 1_000,
        };
        assert_eq!(
            adapter.verify_outcome(&env, 1, false, &Bytes::new(&env)),
            Err(ContractError::InvalidSignature)
        );
    }

    #[test]
    fn reflector_returns_invalid_signature_when_no_price() {
        let env = Env::default();
        let contract_id = setup_mock_reflector(&env);
        let mock_client = MockReflectorClient::new(&env, &contract_id);
        mock_client.set_mode(&MockMode::ReturnNone);

        let adapter = ReflectorAdapter {
            contract_id,
            asset: ReflectorAsset::Other(Symbol::new(&env, "BTC")),
            resolution_price: 1_000,
        };
        assert_eq!(
            adapter.verify_outcome(&env, 1, true, &Bytes::new(&env)),
            Err(ContractError::InvalidSignature)
        );
    }

    #[test]
    fn reflector_stellar_asset_variant_resolves() {
        let env = Env::default();
        let contract_id = setup_mock_reflector(&env);
        let mock_client = MockReflectorClient::new(&env, &contract_id);
        mock_client.set_mode(&MockMode::ReturnPrice(500));

        let token_addr = Address::generate(&env);
        let adapter = ReflectorAdapter {
            contract_id,
            asset: ReflectorAsset::Stellar(token_addr),
            resolution_price: 1_000,
        };
        // price (500) < threshold (1_000) → NO
        assert_eq!(
            adapter.verify_outcome(&env, 2, false, &Bytes::new(&env)),
            Ok(())
        );
    }
}
