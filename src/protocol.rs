use std::io::{ Read, Write };
use std::fs;
use std::collections::HashMap;
use std::path::Path;
use std::io::BufReader;
use std::io::BufRead;
use std::ffi::OsStr;

mod helper;
pub use helper::{
	quick_sha256,
	read_block_hash,
	read_block_file,
	read_block_headers,
	read_block_commands,
	parse_command_string,
	recover_eth_signer,
	get_command_cost
};

#[derive(Debug)]
pub struct BlockHeaders {
	pub number: u128,
	pub timestamp: u128, // seconds since epoch
	pub prev_block_hash: String,
	pub block_hash: String
}

pub fn add_data_to_pblock(data: &str) -> Result<(), &str> {
	// simple checks
	if data.contains('\n') {
		return Err("Data contains \\n character.");
	} else if data.is_empty() {
		return Err("Zero-length data.");
	}

	// check if first character is an acceptable command
	if parse_command_string(&String::from(data)).is_err() {
		return Err("Error parsing command");
	}

	// todo: check if commands fit to certain standard

	let mut save_file = fs::OpenOptions::new()
		.create(true)
		.append(true)
		.read(true)
		.open("../data/blocks/_prospective.txt").unwrap();

	// check for duplicate data
	let reader = BufReader::new(save_file);
    for line in reader.lines().flatten() {
        if line.trim() == data.trim() {
            return Err("Data already exists.");
        }
    }

	// actual saving
	let fmt_data_str = data.trim().to_string() + "\n";
	save_file = fs::OpenOptions::new() // re-open file
		.create(true)
		.append(true)
		.open("../data/blocks/_prospective.txt").unwrap();
	let _ = save_file.write(fmt_data_str.as_bytes()).unwrap();

	Ok(())
}

pub fn finalize_pblock(pblock: &mut BlockHeaders) {
	let mut read_file = fs::File::open("../data/blocks/_prospective.txt").expect("Could not open file");
	let mut raw_content_data = String::new();
	let _ = read_file.read_to_string(&mut raw_content_data).unwrap();
	let mut raw_data = pblock.number.to_string() + "\n" +
		&pblock.timestamp.to_string() + "\n" + // timestamp
		&pblock.prev_block_hash.to_string() + "\n" +
		&raw_content_data;
	let this_block_hash = quick_sha256(&raw_data);
	raw_data = this_block_hash.to_string() + "\n" + &raw_data;

	let save_file_path_str = "../data/blocks/".to_string() + &pblock.number.to_string() + ".txt";
	// if save file already exists for new block then don't modify it
	if Path::new(&save_file_path_str).exists() {
		return;
	}

	let mut save_file = fs::File::create(save_file_path_str).unwrap();
	let _ = save_file.write(raw_data.as_bytes()).unwrap();
	save_file.flush().unwrap();

	// rest perspective block
	pblock.number += 1;
	pblock.prev_block_hash = this_block_hash;

	// reset prospective file
	let _ = fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open("../data/blocks/_prospective.txt").unwrap();
}

// returns what type of error it encountered along with block no.
pub fn verify_blocks(highest_block: &u128) -> Result<(), (u128, u128)> {
	if highest_block == &0 {
		return Ok(());
	}

	let mut balances: HashMap<String, u128> = HashMap::new();
	let mut nonces: HashMap<String, u128> = HashMap::new();

	let mut prev_bh = BlockHeaders {
		number: 0,
		timestamp: 0,
		prev_block_hash: String::new(),
		block_hash: quick_sha256(&String::new())
	};
	for n in 1..=*highest_block {
		let raw_data_result = read_block_file(&n);
		let this_bh_result = read_block_headers(&n);
		if raw_data_result.is_err() {
			// general reading error
			return Err((n, 1));
		}
		let raw_data = raw_data_result.unwrap();
		let this_bh = this_bh_result.unwrap();

		// check this block hash
		let computed_hash = quick_sha256(&raw_data[65..].to_string());
		if this_bh.block_hash != computed_hash.as_str() {
			// expected and actual block hash are different
			return Err((n, 2));
		}

		if this_bh.number != prev_bh.number + 1 {
			// incorrect block number header
			return Err((n, 3));
		}

		// timestamps must be strictly greater than for each new block
		if this_bh.timestamp <= prev_bh.timestamp {
			return Err((n, 4));
		}

		// check previous block hash
		if this_bh.prev_block_hash != prev_bh.block_hash {
			// previous block hash header is incorrect
			return Err((n, 5));
		}
		prev_bh.block_hash = computed_hash;
		prev_bh.number = this_bh.number;

		let this_commands = read_block_commands(&n).unwrap();
		for com in this_commands {
			// commands in block files have the form:
			// <Command Letter> <Command Args separated by space> <Nonce> <Signature>
			// args[0] is always address
			let args = com.1.split(' ').collect::<Vec<&str>>(); // Vec<&str> of agrs
			// verify signature
			let expected_nonce = nonces.get(args[0]).unwrap_or(&0).to_owned();
			let actual_nonce = args[args.len() - 2].parse::<u128>();
			if actual_nonce != Ok(expected_nonce) {
				// wrong nonce
				return Err((n, 10))
			}
			let sig = String::from(&com.0) + " " + &args[0..(args.len() - 1)].join(" ");
			let addr = recover_eth_signer(&sig, args[args.len() - 1]);
			if let Ok(result) = addr {
				if result != args[0] {
					// address mismatch (incorrect signature)
					return Err((n, 9));
				}
			} else {
				// error recovering signature
				return Err((n, 8));
			}
			// first argument is always address
			let mut current_bal = balances.get(args[0]).unwrap_or(&0).to_owned();
			let mut current_debt = 0;
			// process command
			if com.0 == "A" { // A for Add balance
				let parsed_bal = args[1].parse::<u128>();
				if let Ok(parsed_bal_ok) = parsed_bal {
					current_bal += parsed_bal_ok;
				} else {
					// error parsing command arg
					return Err((n, 6));
				}
			} else if com.0 == "C" || com.0 == "F" { // C for Check-in
													// F for add file
				current_debt += get_command_cost(&com.0, &args);
				// TODO: perhaps implemenet dynamic file pricing
			}

			if current_debt > current_bal {
				// not enough balance to pay debt
				return Err((n, 7));
			}
			// process debt and nonce
			current_bal -= current_debt;
			balances.insert(String::from(args[0]), current_bal);
			let expected_nonce = nonces.entry(String::from(args[0])).or_insert(0);
			*expected_nonce += 1;
		}
	}
	Ok(())
}

// It is very important to verify that the chain is valid before building balances and nonces
pub fn build_balances_and_nonces(highest_block: &u128) {
	let mut balances: HashMap<String, u128> = HashMap::new();
	let mut nonces: HashMap<String, u128> = HashMap::new();

	// process fund movement
	for n in 1..=*highest_block {
		let this_commands = read_block_commands(&n).unwrap();
		for com in this_commands {
			let args = com.1.split(' ').collect::<Vec<&str>>();
			// first argument is always address
			let mut current_bal = balances.get(args[0]).unwrap_or(&0).to_owned();
			if com.0 == "A" { // A for Add balance
				let parsed_bal = args[1].parse::<u128>();
				current_bal += parsed_bal.unwrap();
			} else if com.0 == "C" || com.0 == "F" { // C for Check-in, F for add file
				current_bal -= get_command_cost(&com.0, &args);
			}
			if current_bal > 0 {
				balances.insert(String::from(args[0]), current_bal);
			}

			let expected_nonce = nonces.entry(String::from(args[0])).or_insert(0);
			*expected_nonce += 1;
		}
	}
	let bal_keys: Vec<_> = balances.keys().cloned().collect();
	let mut raw_balances_data = String::new();
	for key in bal_keys {
		let bal = balances.get(&key).unwrap().to_owned();
		raw_balances_data += &(key + " " + bal.to_string().as_str() + "\n");
	}

	let nonce_keys: Vec<_> = nonces.keys().cloned().collect();
	let mut raw_nonces_data = String::new();
	for key in nonce_keys {
		let nonce = nonces.get(&key).unwrap().to_owned();
		raw_nonces_data += &(key + " " + nonce.to_string().as_str() + "\n");
	}

	let mut save_file = fs::OpenOptions::new()
        .write(true)
		.create(true)
        .truncate(true)
        .open("../data/balances.txt").unwrap();

	let mut save_file_2 = fs::OpenOptions::new()
        .write(true)
		.create(true)
        .truncate(true)
        .open("../data/nonces.txt").unwrap();

	let _ = save_file.write(raw_balances_data.as_bytes()).unwrap();
	let _ = save_file_2.write(raw_nonces_data.as_bytes()).unwrap();
}

pub fn find_highest_block_num() -> u128 {
	let mut highest_block_num = 0;

	// Find highest block num locally
	let block_entries = fs::read_dir("../data/blocks").expect("Unable to get blocks");

	for entry in block_entries {
		let entry_path = entry.unwrap().path();
		let is_file = entry_path.is_file();
		let entry_name = entry_path.file_stem().unwrap_or(OsStr::new("")).to_string_lossy();
		let entry_extension = entry_path.extension().unwrap_or(OsStr::new("")).to_string_lossy();
		let this_block_num: u128 = entry_name.parse().unwrap_or(0);
		if is_file && entry_extension == "txt" && this_block_num > highest_block_num {
			highest_block_num = this_block_num;
		}
	}

	highest_block_num
}

// it is important to verify chain validity before this
pub fn build_last_checkin(highest_block: &u128) -> Result<(), ()> {
	// last checkin block of address
	let mut last_checkins: HashMap<String, u128> = HashMap::new();

	for n in 1..=*highest_block {
		let coms = read_block_commands(&n).unwrap();
		for com in coms {
			if com.0 == "C" {
				let args = com.1.split(' ').collect::<Vec<&str>>();
				let addr = args[0].to_string();
				last_checkins.insert(addr, n);
			}
		}
	}

	let mut save_file = fs::OpenOptions::new()
        .write(true)
		.create(true)
        .truncate(true)
        .open("../data/last_checkins.txt").unwrap();

	for (key, value) in last_checkins {
		let s = save_file.write(format!("{} {}\n", key, value).as_bytes());
		if s.is_err() {
			return Err(());
		}
	}

	Ok(())
}
