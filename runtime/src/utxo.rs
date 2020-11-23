use super::Aura;
use codec::{Decode, Encode};
use frame_support::{
    decl_event, decl_module, decl_storage,
    dispatch::{DispatchResult, Vec},
    ensure,
};
use sp_core::{H256, H512};
use sp_io;
#[cfg(feature = "std")]
use serde::{Deserialize, Serialize};
use sp_core::sr25519::{Public, Signature};
use sp_runtime::traits::{BlakeTwo256, Hash, SaturatedConversion};
use sp_std::collections::btree_map::BTreeMap;
use sp_runtime::transaction_validity::{TransactionLongevity, ValidTransaction};

pub trait Trait: frame_system::Trait {
    type Event: From<Event> + Into<<Self as frame_system::Trait>::Event>;
}

#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
#[derive(PartialEq, Eq, PartialOrd, Ord, Default, Clone, Encode, Decode, Hash, Debug)]
pub struct TransactionInput {
    pub out_point: H256,
    pub sig_script: H512,
}

pub type Value = u128;

#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
#[derive(PartialEq, Eq, PartialOrd, Ord, Default, Clone, Encode, Decode, Hash, Debug)]
pub struct TransactionOutput {
    pub value: Value,
    pub pub_key: H256,
}

#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
#[derive(PartialEq, Eq, PartialOrd, Ord, Default, Clone, Encode, Decode, Hash, Debug)]
pub struct Transaction {
    pub inputs: Vec<TransactionInput>,
    pub outputs: Vec<TransactionOutput>,
}

decl_storage! {
    trait Store for Module<T: Trait> as Utxo {
        UtxoStore build(|config: &GenesisConfig| {
            config.genesis_utxos
            .iter()
            .cloned()
            .map( |u| (BlakeTwo256::hash_of(&u), u) )
            .collect::<Vec<_>>()
        }): map hasher(identity) H256 => Option<TransactionOutput>;

        pub RewardTotal get(fn reward_total) : Value;
    }

    add_extra_genesis {
        config(genesis_utxos): Vec<TransactionOutput>;
    }
}

// External functions: callable by the end user
decl_module! {
    pub struct Module<T: Trait> for enum Call where origin: T::Origin {
        fn deposit_event() = default;

        #[weight = 10_000]
        pub fn spend(_origin, transaction: Transaction) -> DispatchResult {
            let valid_transaction = Self::validate_transaction(&transaction)?;
            Self::update_storage(&transaction, valid_transaction.priority as Value)?;
            Self::deposit_event(Event::TransactionSuccess(transaction));
            Ok(())
        }

        fn on_finalize() {
            let auth: Vec<_> = Aura::authorities().iter().map( |x| {
                let r: &Public = x.as_ref();
                r.0.into()
            }).collect();
            Self::disperse_reward(&auth);
        }
    }
}

decl_event! {
    pub enum Event {
        TransactionSuccess(Transaction),
    }
}

impl<T: Trait> Module<T> {
    pub fn get_simple_transaction (transaction: &Transaction) -> Vec<u8> {
        let mut trx = transaction.clone();
        for input in trx.inputs.iter_mut() {
            input.sig_script = H512::zero();
        }
        trx.encode()
    }

    pub fn validate_transaction(transaction: &Transaction) -> Result<ValidTransaction, &'static str> {
        ensure!(!transaction.inputs.is_empty(), "no inputs");
        ensure!(!transaction.outputs.is_empty(), "no outputs");

        {
            let input_set: BTreeMap<_, ()> = transaction.inputs.iter().map( |input| (input, ()) ).collect();
            ensure!(input_set.len() == transaction.inputs.len(), "each input must only be used once");
        }

        {
            let output_set: BTreeMap<_, ()> = transaction.outputs.iter().map( |output| (output, ()) ).collect();
            ensure!(output_set.len() == transaction.outputs.len(), "each output must only be used once");
        }

        let simple_transaction = Self::get_simple_transaction(transaction);
        let mut total_input: Value = 0;
        let mut total_output: Value = 0;

        let mut missing_utxos = Vec::new();
        let mut new_utxos = Vec::new();
        let mut reward = 0;

        for input in transaction.inputs.iter() {
            if let Some(input_utxo) = <UtxoStore>::get(&input.out_point) {
                ensure!(sp_io::crypto::sr25519_verify(
                    &Signature::from_raw(*input.sig_script.as_fixed_bytes()),
                    &simple_transaction,
                    &Public::from_h256(input_utxo.pub_key)
                ), "signature must be valid");
                total_input = total_input.checked_add(input_utxo.value).ok_or("input value overflow")?;
            } else {
                missing_utxos.push(input.out_point.clone().as_fixed_bytes().to_vec());
            }
        }

        let mut output_index: u64 = 0;

        for output in transaction.outputs.iter() {
            ensure!(output.value > 0, "output value must be nonzero");
            let hash = BlakeTwo256::hash_of( &(&transaction.encode(), output_index) );
            output_index = output_index.checked_add(1).ok_or("output index overflow")?;
            ensure!(! <UtxoStore>::contains_key(hash), "output already exists" );
            total_output = total_output.checked_add(output.value).ok_or("output value overflow")?;
            new_utxos.push(hash.as_fixed_bytes().to_vec());
        }

        if missing_utxos.is_empty() {
            ensure!( total_input >= total_output, "output value must not excceed input value" );
            reward = total_input.checked_sub(total_output).ok_or("reward underflow")?;
        }

        Ok(ValidTransaction{
            requires: missing_utxos,
            provides: new_utxos,
            priority: reward as u64,
            longevity: TransactionLongevity::max_value(),
            propagate: true,
        })
    }

    fn update_storage(transaction: &Transaction, reward: Value) -> DispatchResult {
        let new_total = <RewardTotal>::get()
            .checked_add(reward)
            .ok_or("reward overflow")?;
        <RewardTotal>::put(new_total);

        for input in &transaction.inputs {
            <UtxoStore>::remove(input.out_point);
        }

        let mut index: u64 = 0;
        for output in &transaction.outputs {
            let hash = BlakeTwo256::hash_of( &(&transaction.encode(), index) );
            index = index.checked_add(1).ok_or("output index overflow")?;
            <UtxoStore>::insert(hash, output);
        }
        Ok(())
    }

    fn disperse_reward(authorities: &[H256]) {
        let reward = <RewardTotal>::take();
        let share_value: Value = reward
            .checked_div(authorities.len() as Value)
            .ok_or("No authorities")
            .unwrap();
        if share_value == 0 {return}

        let remainder = reward
            .checked_sub(share_value * authorities.len() as Value)
            .ok_or("Sub underflow")
            .unwrap();
        
        <RewardTotal>::put(remainder as Value);

        for authrity in authorities {
            let utxo = TransactionOutput {
                value: share_value,
                pub_key: *authrity,
            };

            let hash = BlakeTwo256::hash_of( &(&utxo, <frame_system::Module<T>>::block_number().saturated_into::<u64>()) );

            if !<UtxoStore>::contains_key(hash) {
                <UtxoStore>::insert(hash, utxo);
                sp_runtime::print("Transaction reward sent to");
                sp_runtime::print(hash.as_fixed_bytes() as &[u8]);
            } else {
                sp_runtime::print("Transaction reward wasted due to hash collision");
            }
        }
    }
}