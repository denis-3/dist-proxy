use std::fs;
use sha2::{ Digest, Sha256 };
use ethers_core::types::{ Signature, RecoveryMessage };
use std::str::FromStr;

#[derive(Debug)]
pub struct BlockHeaders {
	pub number: u128,
	pub timestamp: u128, // seconds since epoch
	pub prev_block_hash: String,
	pub block_hash: String
}

pub fn quick_sha256(data: &String) -> String {
	let mut hasher = Sha256::new();
	hasher.update(data.as_bytes());
	let result = hasher.finalize();
	format!("{:x}", result)
}

pub fn read_block_file(block_num: &u128) -> Result<String, String> {
	let attempt = fs::read_to_string("../data/blocks/".to_string() + &block_num.to_string() + ".txt");
	if attempt.is_err() {
		return Err(format!("{:?}", attempt));
	}

	Ok(attempt.unwrap())
}

pub fn read_block_headers(block_num: &u128) -> Result<BlockHeaders, String> {
	let raw_data = read_block_file(block_num)?;
	let raw_data_split = &raw_data.split('\n').collect::<Vec<_>>();
	let bh = BlockHeaders {
		number: raw_data_split[1].parse().unwrap(),
		timestamp: raw_data_split[2].parse().unwrap(),
		prev_block_hash: raw_data_split[3].to_string(),
		block_hash: raw_data_split[0].to_string()
	};

	Ok(bh)
}

pub fn read_block_hash(block_num: &u128) -> Result<String, String> {
	if block_num == &0 {
		return Ok(quick_sha256(&String::new()));
	}

	let bh = read_block_headers(block_num)?;

	Ok(bh.block_hash)
}

pub fn read_block_commands(block_num: &u128) -> Result<Vec<(String, String)>, String> {
	let raw_data = read_block_file(block_num)?;
	let mut raw_data_split = raw_data.split('\n').collect::<Vec<_>>();
	let _ = raw_data_split.drain(0..4);
	let mut commands: Vec<(String, String)> = vec![];

    for line in raw_data_split {
        let words = line.split(' ').collect::<Vec<_>>();
		let command_args = words[1..].join(" ");

		if words[0].is_empty() {
			continue;
		}

		commands.push((
			String::from(words[0]),
			command_args
		));
    }

	Ok(commands)
}

pub fn parse_command_string(com_str: &String) -> Result<Vec<String>, String> {
	if com_str.is_empty() {
		return Err(String::from("Zero-length string"));
	}

	// Command syntax:
	// C <Address> - Check in
	// A <Address> <Amount> <Eth tx hash> - Add balance
	// F <Address> <Hash> - add file hash
	let valid_commands: Vec<char> = vec!['A', 'C', 'F'];
    let data_command_char = com_str.chars().next();
    let valid_command_char = valid_commands.iter().any(|&c| {
        data_command_char == Some(c)
    });

	if !valid_command_char {
		return Err(String::from("Invalid command character."));
	}

	let data_split = com_str.split(&String::from(" "))
		.map(String::from)
		.collect::<Vec<String>>();
	Ok(data_split)
}

// recover eth signer to 0x.... string
pub fn recover_eth_signer(message: &str, sig: &str) -> Result<String, ()> {
	let msg_obj = RecoveryMessage::from(message);
	let sig_obj = Signature::from_str(sig);

	if sig_obj.is_err() {
		return Err(());
	}

	let sig_obj = sig_obj.unwrap();
	let res = sig_obj.recover(msg_obj);
	if let Ok(addr) = res {
		Ok(format!("{:?}", addr))
	} else {
		Err(())
	}
}

pub fn get_command_cost(command_letter: &String, _command_params: &[&str]) -> u128 {
	// check-in always costs 1
	if command_letter == "C" {
		1
	} else if command_letter == "A" {
		// no cost with adding balance
		return 0;
	} else {
		// other commands are 100
		return 100;
	}
}
