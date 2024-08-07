//! # SP1 SDK
//!
//! A library for interacting with the SP1 RISC-V zkVM.
//!
//! Visit the [Getting Started](https://succinctlabs.github.io/sp1/getting-started.html) section
//! in the official SP1 documentation for a quick start guide.

#[rustfmt::skip]
pub mod proto {
    pub mod network;
}
pub mod action;
pub mod artifacts;
pub mod install;
#[cfg(feature = "network")]
pub mod network;
#[cfg(feature = "network")]
pub use crate::network::prover::NetworkProver;

pub mod proof;
pub mod provers;
pub mod utils {
    pub use sp1_core::utils::setup_logger;
}

use cfg_if::cfg_if;
pub use proof::*;
pub use provers::SP1VerificationError;
use sp1_prover::components::DefaultProverComponents;

pub use provers::{LocalProver, MockProver, Prover};

pub use sp1_core::runtime::{ExecutionReport, Hook, HookEnv, SP1Context, SP1ContextBuilder};
use sp1_core::SP1_CIRCUIT_VERSION;
pub use sp1_prover::{
    CoreSC, HashableKey, InnerSC, OuterSC, PlonkBn254Proof, SP1Prover, SP1ProvingKey,
    SP1PublicValues, SP1Stdin, SP1VerifyingKey,
};

/// A client for interacting with SP1.
pub struct ProverClient {
    /// The underlying prover implementation.
    pub prover: Box<dyn Prover<DefaultProverComponents>>,
}

impl ProverClient {
    /// Creates a new [ProverClient] with the provided prover.
    ///
    /// ### Examples
    ///
    /// ```no_run
    /// use sp1_sdk::ProverClient;
    /// use sp1_sdk::provers::MockProver;
    ///
    /// let prover = MockProver::new();
    /// let client = ProverClient::new(prover);
    /// ```
    pub fn new<T: Prover<DefaultProverComponents> + 'static>(prover: T) -> Self {
        Self { prover: Box::new(prover) }
    }

    /// Creates a new [ProverClient] with the mock prover.
    ///
    /// Recommended for testing and development.
    ///
    /// ### Examples
    ///
    /// ```no_run
    /// use sp1_sdk::ProverClient;
    ///
    /// let client = ProverClient::mock();
    /// ```
    pub fn mock() -> Self {
        Self {
            prover: Box::new(MockProver::new()),
        }
    }

    /// Creates a new [ProverClient] with the local prover.
    ///
    /// Recommended for proving end-to-end locally.
    ///
    /// ### Examples
    ///
    /// ```no_run
    /// use sp1_sdk::ProverClient;
    ///
    /// let client = ProverClient::local();
    /// ```
    pub fn local() -> Self {
        Self {
            prover: Box::new(LocalProver::new()),
        }
    }

    /// Creates a new [ProverClient] with the network prover.
    ///
    /// Recommended for outsourcing proof generation to an RPC.
    ///
    /// ### Examples
    ///
    /// ```no_run
    /// use sp1_sdk::ProverClient;
    ///
    /// let client = ProverClient::network();
    /// ```
    pub fn network() -> Self {
        cfg_if! {
            if #[cfg(feature = "network")] {
                Self {
                    prover: Box::new(NetworkProver::new()),
                }
            } else {
                panic!("network feature is not enabled")
            }
        }
    }

    /// Prepare to execute the given program on the given input (without generating a proof).
    /// The returned [action::Execute] may be configured via its methods before running.
    /// For example, calling [action::Execute::with_hook] registers hooks for execution.
    ///
    /// To execute, call [action::Execute::run], which returns
    /// the public values and execution report of the program after it has been executed.
    ///
    /// ### Examples
    /// ```no_run
    /// use sp1_sdk::{ProverClient, SP1Stdin, SP1Context};
    /// use sp1_sdk::provers::MockProver;
    ///
    /// // Load the program.
    /// let elf = include_bytes!("../../examples/fibonacci/program/elf/riscv32im-succinct-zkvm-elf");
    ///
    /// // Initialize the prover.
    /// let prover = MockProver::new();
    ///
    /// // Initialize the prover client.
    /// let client = ProverClient::new(prover);
    ///
    /// // Setup the inputs.
    /// let mut stdin = SP1Stdin::new();
    /// stdin.write(&10usize);
    ///
    /// // Execute the program on the inputs.
    /// let (public_values, report) = client.execute(elf, stdin).run().unwrap();
    /// ```
    pub fn execute<'a>(&'a self, elf: &'a [u8], stdin: SP1Stdin) -> action::Execute<'a> {
        action::Execute::new(self.prover.as_ref(), elf, stdin)
    }

    /// Prepare to prove the execution of the given program with the given input in the default mode.
    /// The returned [action::Prove] may be configured via its methods before running.
    /// For example, calling [action::Prove::compress] sets the mode to compressed mode.
    ///
    /// To prove, call [action::Prove::run], which returns a proof of the program's execution.
    /// By default the proof generated will not be compressed to constant size.
    /// To create a more succinct proof, use the [Self::prove_compressed],
    /// [Self::prove_plonk], or [Self::prove_plonk] methods.
    ///
    /// ### Examples
    /// ```no_run
    /// use sp1_sdk::{ProverClient, SP1Stdin, SP1Context};
    /// use sp1_sdk::provers::MockProver;
    ///
    /// // Load the program.
    /// let elf = include_bytes!("../../examples/fibonacci/program/elf/riscv32im-succinct-zkvm-elf");
    ///
    /// // Initialize the prover.
    /// let prover = MockProver::new();
    ///
    /// // Initialize the prover client.
    /// let client = ProverClient::new(prover);
    ///
    /// // Setup the program.
    /// let (pk, vk) = client.setup(elf);
    ///
    /// // Setup the inputs.
    /// let mut stdin = SP1Stdin::new();
    /// stdin.write(&10usize);
    ///
    /// // Generate the proof.
    /// let proof = client.prove(&pk, stdin).run().unwrap();
    /// ```
    pub fn prove<'a>(&'a self, pk: &'a SP1ProvingKey, stdin: SP1Stdin) -> action::Prove<'a> {
        action::Prove::new(self.prover.as_ref(), pk, stdin)
    }

    /// Verifies that the given proof is valid and matches the given verification key produced by
    /// [Self::setup].
    ///
    /// ### Examples
    /// ```no_run
    /// use sp1_sdk::{ProverClient, SP1Stdin};
    /// use sp1_sdk::provers::MockProver;
    ///
    /// let elf = include_bytes!("../../examples/fibonacci/program/elf/riscv32im-succinct-zkvm-elf");
    /// let client = ProverClient::new(MockProver::new());
    /// let (pk, vk) = client.setup(elf);
    /// let mut stdin = SP1Stdin::new();
    /// stdin.write(&10usize);
    /// let proof = client.prove(&pk, stdin).run().unwrap();
    /// client.verify(&proof, &vk).unwrap();
    /// ```
    pub fn verify(
        &self,
        proof: &SP1ProofWithPublicValues,
        vk: &SP1VerifyingKey,
    ) -> Result<(), SP1VerificationError> {
        self.prover.verify(proof, vk)
    }

    /// Gets the current version of the SP1 zkVM.
    ///
    /// Note: This is not the same as the version of the SP1 SDK.
    pub fn version(&self) -> String {
        SP1_CIRCUIT_VERSION.to_string()
    }

    /// Setup a program to be proven and verified by the SP1 RISC-V zkVM by computing the proving
    /// and verifying keys.
    ///
    /// The proving key and verifying key essentially embed the program, as well as other auxiliary
    /// data (such as lookup tables) that are used to prove the program's correctness.
    ///
    /// ### Examples
    /// ```no_run
    /// use sp1_sdk::{ProverClient, SP1Stdin};
    /// use sp1_sdk::provers::MockProver;
    ///
    /// let elf = include_bytes!("../../examples/fibonacci/program/elf/riscv32im-succinct-zkvm-elf");
    /// let client = ProverClient::new(MockProver::new());
    /// let mut stdin = SP1Stdin::new();
    /// stdin.write(&10usize);
    /// let (pk, vk) = client.setup(elf);
    /// ```
    pub fn setup(&self, elf: &[u8]) -> (SP1ProvingKey, SP1VerifyingKey) {
        self.prover.setup(elf)
    }
}

#[cfg(test)]
mod tests {

    use std::sync::atomic::{AtomicU32, Ordering};

    use sp1_core::runtime::{hook_ecrecover, FD_ECRECOVER_HOOK};

    use crate::{utils, ProverClient, SP1Stdin};

    #[test]
    fn test_execute() {
        utils::setup_logger();
        let client = ProverClient::local();
        let elf =
            include_bytes!("../../examples/fibonacci/program/elf/riscv32im-succinct-zkvm-elf");
        let mut stdin = SP1Stdin::new();
        stdin.write(&10usize);
        client.execute(elf, stdin).run().unwrap();
    }

    #[test]
    fn test_execute_new() {
        // Wrap the hook and check that it was called.
        let call_ct = AtomicU32::new(0);
        utils::setup_logger();
        let client = ProverClient::local();
        let elf = include_bytes!("../../tests/ecrecover/elf/riscv32im-succinct-zkvm-elf");
        let stdin = SP1Stdin::new();
        client
            .execute(elf, stdin)
            .with_hook(FD_ECRECOVER_HOOK, |env, buf| {
                call_ct.fetch_add(1, Ordering::Relaxed);
                hook_ecrecover(env, buf)
            })
            .run()
            .unwrap();
        assert_ne!(call_ct.into_inner(), 0);
    }

    #[test]
    fn test_prove_new() {
        // Wrap the hook and check that it was called.
        let call_ct = AtomicU32::new(0);
        utils::setup_logger();
        let client = ProverClient::local();
        let elf = include_bytes!("../../tests/ecrecover/elf/riscv32im-succinct-zkvm-elf");
        let stdin = SP1Stdin::new();
        let (pk, _) = client.setup(elf);
        client
            .prove(&pk, stdin)
            .with_hook(FD_ECRECOVER_HOOK, |env, buf| {
                call_ct.fetch_add(1, Ordering::Relaxed);
                hook_ecrecover(env, buf)
            })
            .run()
            .unwrap();
        assert_ne!(call_ct.into_inner(), 0);
    }

    #[test]
    #[should_panic]
    fn test_execute_panic() {
        utils::setup_logger();
        let client = ProverClient::local();
        let elf = include_bytes!("../../tests/panic/elf/riscv32im-succinct-zkvm-elf");
        let mut stdin = SP1Stdin::new();
        stdin.write(&10usize);
        client.execute(elf, stdin).run().unwrap();
    }

    #[should_panic]
    #[test]
    fn test_cycle_limit_fail() {
        utils::setup_logger();
        let client = ProverClient::local();
        let elf = include_bytes!("../../tests/panic/elf/riscv32im-succinct-zkvm-elf");
        let mut stdin = SP1Stdin::new();
        stdin.write(&10usize);
        client.execute(elf, stdin).max_cycles(1).run().unwrap();
    }

    #[test]
    fn test_e2e_prove_plonk() {
        utils::setup_logger();
        let client = ProverClient::local();
        let elf =
            include_bytes!("../../examples/fibonacci/program/elf/riscv32im-succinct-zkvm-elf");
        let (pk, vk) = client.setup(elf);
        let mut stdin = SP1Stdin::new();
        stdin.write(&10usize);
        let proof = client.prove(&pk, stdin).plonk().run().unwrap();
        client.verify(&proof, &vk).unwrap();
    }

    #[test]
    fn test_e2e_prove_plonk_mock() {
        utils::setup_logger();
        let client = ProverClient::mock();
        let elf =
            include_bytes!("../../examples/fibonacci/program/elf/riscv32im-succinct-zkvm-elf");
        let (pk, vk) = client.setup(elf);
        let mut stdin = SP1Stdin::new();
        stdin.write(&10usize);
        let proof = client.prove(&pk, stdin).plonk().run().unwrap();
        client.verify(&proof, &vk).unwrap();
    }
}
