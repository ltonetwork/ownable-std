use cosmwasm_std::{Addr, Api, BlockInfo, CanonicalAddr, ContractInfo, Empty, Env, MemoryStorage, OwnedDeps, Querier, RecoverPubkeyError, StdError, StdResult, Timestamp, VerificationError, Order, Storage, Uint128, Response};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::to_string;
use serde_with::serde_as;
use wasm_bindgen::{JsValue, JsError};
use std::collections::HashMap;
use std::marker::PhantomData;
use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use sha2::Digest as Sha2Digest;
use sha3::{Digest};

const CANONICAL_LENGTH: usize = 54;

pub fn create_lto_env() -> Env {
    Env {
        block: BlockInfo {
            height: 0,
            time: Timestamp::from_seconds(0),
            chain_id: "lto".to_string(),
        },
        contract: ContractInfo {
            address: Addr::unchecked(""),
        },
        transaction: None,
    }
}

pub fn load_lto_deps(state_dump: Option<IdbStateDump>) -> OwnedDeps<MemoryStorage, EmptyApi, EmptyQuerier, Empty> {
    match state_dump {
        None => OwnedDeps {
            storage: MemoryStorage::default(),
            api: EmptyApi::default(),
            querier: EmptyQuerier::default(),
            custom_query_type: PhantomData,
        },
        Some(dump) => {
            let idb_storage = IdbStorage::load(dump);
            OwnedDeps {
                storage: idb_storage.storage,
                api: EmptyApi::default(),
                querier: EmptyQuerier::default(),
                custom_query_type: PhantomData,
            }
        }
    }

}

/// takes a b58 of compressed secp256k1 pk
pub fn address_eip155(public_key: String) -> Result<Addr, StdError> {
    if public_key.is_empty() {
        return Err(StdError::not_found("empty input"));
    }

    // decode b58 pk
    let pk = bs58::decode(public_key.as_bytes()).into_vec();
    let decoded_pk = match pk {
        Ok(pk) => pk,
        Err(e) => return Err(StdError::generic_err(e.to_string())),
    };

    // instantiate secp256k1 public key from input
    let public_key = secp256k1::PublicKey::from_slice(decoded_pk.as_slice()).unwrap();
    let mut uncompressed_hex_pk = hex::encode(public_key.serialize_uncompressed());
    if uncompressed_hex_pk.starts_with("04") {
        uncompressed_hex_pk = uncompressed_hex_pk.split_off(2);
    }

    // pass the raw bytes to keccak256
    let uncompressed_raw_pk = hex::decode(uncompressed_hex_pk).unwrap();

    let mut hasher = sha3::Keccak256::new();
    hasher.input(uncompressed_raw_pk.as_slice());
    let hashed_addr = hex::encode(hasher.result().as_slice()).to_string();

    let result = &hashed_addr[hashed_addr.len() - 40..];
    let checksum_addr = "0x".to_owned() + eip_55_checksum(result).as_str();

    Ok(Addr::unchecked(checksum_addr))
}

fn eip_55_checksum(addr: &str) -> String {
    let mut checksum_hasher = sha3::Keccak256::new();
    checksum_hasher.input(&addr[addr.len() - 40..].as_bytes());
    let hashed_addr = hex::encode(checksum_hasher.result()).to_string();

    let mut checksum_buff = "".to_owned();
    let result_chars: Vec<char> = addr.chars()
        .into_iter()
        .collect();
    let keccak_chars: Vec<char> = hashed_addr.chars()
        .into_iter()
        .collect();
    for i in 0..addr.len() {
        let mut char = result_chars[i];
        if char.is_alphabetic() {
            let keccak_digit = keccak_chars[i]
                .to_digit(16)
                .unwrap();
            // if the corresponding hex digit >= 8, convert to uppercase
            if keccak_digit >= 8 {
                char = char.to_ascii_uppercase();
            }
        }
        checksum_buff += char.to_string().as_str();
    }

    checksum_buff
}

pub fn address_lto(network_id: char, public_key: String) -> Result<Addr, StdError> {
    if network_id != 'L' && network_id != 'T' {
        return Err(StdError::generic_err("unrecognized network_id"));
    }
    if bs58::decode(public_key.clone()).into_vec().is_err() {
        return Err(StdError::generic_err("invalid public key"));
    }

    // decode b58 of pubkey into byte array
    let public_key = bs58::decode(public_key).into_vec().unwrap();
    // get the ascii value from network char
    let network_id = network_id as u8;
    let pub_key_secure_hash = secure_hash(public_key.as_slice());
    // get the first 20 bytes of the securehash
    let address_bytes = &pub_key_secure_hash[0..20];
    let version = &1_u8.to_be_bytes();
    let checksum_input:Vec<u8> = [version, &[network_id], address_bytes].concat();

    // checksum is the first 4 bytes of secureHash of version, chain_id, and hash
    let checksum = &secure_hash(checksum_input.as_slice())
        .to_vec()[0..4];

    let addr_fields = [
        version,
        &[network_id],
        address_bytes,
        checksum
    ];

    let address: Vec<u8> = addr_fields.concat();
    Ok(Addr::unchecked(base58(address.as_slice())))
}

fn base58(input: &[u8]) -> String {
    bs58::encode(input).into_string()
}

fn secure_hash(m: &[u8]) -> Vec<u8> {
    let mut hasher = Blake2bVar::new(32).unwrap();
    hasher.update(m);
    let mut buf = [0u8; 32];
    hasher.finalize_variable(&mut buf).unwrap();

    // get the sha256 of blake
    let mut sha256_hasher = sha2::Sha256::new();
    Update::update(&mut sha256_hasher, buf.as_slice());
    let res = sha256_hasher.finalize();
    // let mut hasher = sha2::Sha256::new();
    // hasher.update(&buf);
    // let mut buf = hasher.finalize();
    res.to_vec()
}

pub fn get_random_color(hash: String) -> String {
    let (red, green, blue) = derive_rgb_values(hash);
    rgb_hex(red, green, blue)
}

pub fn derive_rgb_values(hash: String) -> (u8, u8, u8) {
    let mut decoded_hash = bs58::decode(&hash).into_vec().unwrap();
    decoded_hash.reverse();
    (decoded_hash[0], decoded_hash[1], decoded_hash[2])
}

pub fn rgb_hex(r: u8, g: u8, b: u8) -> String {
    format!("#{:02X}{:02X}{:02X}", r, g, b)
}

pub fn get_json_response(storage: MemoryStorage, response: Response) -> Result<JsValue, JsError> {
    let state_dump= IdbStateDump::from(storage);
    let ownable_state = to_string(&response)?;
    let response_map = js_sys::Map::new();
    response_map.set(
        &JsValue::from_str("mem"),
        &JsValue::from(serde_json::to_string(&state_dump)?)
    );
    response_map.set(
        &JsValue::from_str("result"),
        &JsValue::from(ownable_state)
    );
    Ok(JsValue::from(response_map))
}

pub struct IdbStorage {
    pub storage: MemoryStorage,
}

impl IdbStorage {
    pub fn load(idb: IdbStateDump) -> Self {
        let mut store = IdbStorage {
            storage: MemoryStorage::new(),
        };
        store.load_to_mem_storage(idb);
        store
    }

    pub fn load_to_mem_storage(&mut self, idb_state: IdbStateDump) {
        for (k, v) in idb_state.state_dump.into_iter() {
            self.storage.set(&k, &v);
        }
    }
}

#[serde_as]
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct IdbStateDump {
    // map of the indexed db key value pairs of the state object store
    #[serde_as(as = "Vec<(_, _)>")]
    pub state_dump: HashMap<Vec<u8>, Vec<u8>>,
}

impl IdbStateDump {
    pub fn from(store: MemoryStorage) -> IdbStateDump {
        let mut state: HashMap<Vec<u8>, Vec<u8>> = HashMap::new();

        for (key, value) in store.range(None,None, Order::Ascending) {
            state.insert(key, value);
        }
        IdbStateDump {
            state_dump: state,
        }
    }
}

// EmptyApi that is meant to conform the traits by the cosmwasm standard contract syntax. The functions of this implementation are not meant to be used or produce any sensible results.
#[derive(Copy, Clone)]
pub struct EmptyApi {
    /// Length of canonical addresses created with this API. Contracts should not make any assumtions
    /// what this value is.
    canonical_length: usize,
}

impl Default for EmptyApi {
    fn default() -> Self {
        EmptyApi {
            canonical_length: CANONICAL_LENGTH,
        }
    }
}

impl Api for EmptyApi {
    fn addr_validate(&self, human: &str) -> StdResult<Addr> {
        self.addr_canonicalize(human).map(|_canonical| ())?;
        Ok(Addr::unchecked(human))
    }

    fn addr_canonicalize(&self, human: &str) -> StdResult<CanonicalAddr> {
        // Dummy input validation. This is more sophisticated for formats like bech32, where format and checksum are validated.
        if human.len() < 3 {
            return Err(StdError::generic_err(
                "Invalid input: human address too short",
            ));
        }
        if human.len() > self.canonical_length {
            return Err(StdError::generic_err(
                "Invalid input: human address too long",
            ));
        }

        let mut out = Vec::from(human);

        // pad to canonical length with NULL bytes
        out.resize(self.canonical_length, 0x00);
        // // content-dependent rotate followed by shuffle to destroy
        // // the most obvious structure (https://github.com/CosmWasm/cosmwasm/issues/552)
        // let rotate_by = digit_sum(&out) % self.canonical_length;
        // out.rotate_left(rotate_by);
        // for _ in 0..SHUFFLES_ENCODE {
        //     out = riffle_shuffle(&out);
        // }
        Ok(out.into())
    }

    fn addr_humanize(&self, canonical: &CanonicalAddr) -> StdResult<Addr> {
        if canonical.len() != self.canonical_length {
            return Err(StdError::generic_err(
                "Invalid input: canonical address length not correct",
            ));
        }

        let tmp: Vec<u8> = canonical.clone().into();
        // // Shuffle two more times which restored the original value (24 elements are back to original after 20 rounds)
        // for _ in 0..SHUFFLES_DECODE {
        //     tmp = riffle_shuffle(&tmp);
        // }
        // // Rotate back
        // let rotate_by = digit_sum(&tmp) % self.canonical_length;
        // tmp.rotate_right(rotate_by);
        // Remove NULL bytes (i.e. the padding)
        let trimmed = tmp.into_iter().filter(|&x| x != 0x00).collect();
        // decode UTF-8 bytes into string
        let human = String::from_utf8(trimmed)?;
        Ok(Addr::unchecked(human))
    }

    fn secp256k1_verify(
        &self,
        _message_hash: &[u8],
        _signature: &[u8],
        _public_key: &[u8],
    ) -> Result<bool, VerificationError> {
        Err(VerificationError::unknown_err(0))
    }

    fn secp256k1_recover_pubkey(
        &self,
        _message_hash: &[u8],
        _signature: &[u8],
        _recovery_param: u8,
    ) -> Result<Vec<u8>, RecoverPubkeyError> {
        Err(RecoverPubkeyError::unknown_err(0))
    }

    fn ed25519_verify(
        &self,
        _message: &[u8],
        _signature: &[u8],
        _public_key: &[u8],
    ) -> Result<bool, VerificationError> {
        Ok(true)
    }

    fn ed25519_batch_verify(
        &self,
        _messages: &[&[u8]],
        _signatures: &[&[u8]],
        _public_keys: &[&[u8]],
    ) -> Result<bool, VerificationError> {
        Ok(true)
    }

    fn debug(&self, message: &str) {
        println!("{}", message);
    }
}

/// Empty Querier that is meant to conform the traits expected by the cosmwasm standard contract syntax. It should not be used whatsoever
#[derive(Default)]
pub struct EmptyQuerier {}

impl Querier for EmptyQuerier {
    fn raw_query(&self, _bin_request: &[u8]) -> cosmwasm_std::QuerierResult {
        todo!()
    }
}

// from github.com/CosmWasm/cw-nfts/blob/main/contracts/cw721-metadata-onchain
#[derive(Serialize, Deserialize, Clone, PartialEq, JsonSchema, Debug, Default)]
pub struct Metadata {
    pub image: Option<String>,
    pub image_data: Option<String>,
    pub external_url: Option<String>,
    pub description: Option<String>,
    pub name: Option<String>,
    // pub attributes: Option<Vec<Trait>>,
    pub background_color: Option<String>,
    pub animation_url: Option<String>,
    pub youtube_url: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, JsonSchema, Debug)]
#[serde(rename_all = "snake_case")]
pub struct ExternalEventMsg {
    // CAIP-2 format: <namespace + ":" + reference>
    // e.g. ethereum: eip155:1
    pub network: Option<String>,
    pub event_type: String,
    pub attributes: HashMap<String, String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct OwnableInfo {
    pub owner: Addr,
    pub issuer: Addr,
    pub ownable_type: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct NFT {
    pub network: String,    // eip155:1
    pub id: Uint128,
    pub address: String, // 0x341...
    pub lock_service: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct InfoResponse {
    pub owner: Addr,
    pub issuer: Addr,
    pub nft: Option<NFT>,
    pub ownable_type: Option<String>,
}
