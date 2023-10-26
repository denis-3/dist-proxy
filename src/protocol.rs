use std::io::{ Read, Write };
use std::fs;
use std::collections::HashMap;
use std::path::Path;
use std::io::BufReader;
use std::fs::File;
use std::io::BufRead;

mod helper;
pub use helper::{
	quick_sha256,
	read_block_hash,
	read_block_file,
	read_block_headers,
	read_block_commands,
	read_balance,
	parse_command_string
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
			return Err((n, 1));
		}
		let raw_data = raw_data_result.unwrap();
		let this_bh = this_bh_result.unwrap();

		// check this block hash
		let computed_hash = quick_sha256(&raw_data[65..].to_string());
		if this_bh.block_hash != computed_hash.as_str() {
			return Err((n, 2));
		}

		if this_bh.number != prev_bh.number + 1 {
			return Err((n, 3));
		}

		// timestamps must be strictly greater than for each new block
		if this_bh.timestamp <= prev_bh.timestamp {
			return Err((n, 4));
		}

		// check previous block hash
		if this_bh.prev_block_hash != prev_bh.block_hash {
			return Err((n, 5));
		}
		prev_bh.block_hash = computed_hash;
		prev_bh.number = this_bh.number;

		let this_commands = read_block_commands(&n).unwrap();
		for com in this_commands {
			let args = com.1.split(' ').collect::<Vec<&str>>();
			// first argument is always address
			let mut current_bal = balances.get(args[0]).unwrap_or(&0).to_owned();
			if com.0 == "A" { // A for Add balance
				let parsed_bal = args[1].parse::<u128>();
				if let Ok(parsed_bal_ok) = parsed_bal {
					current_bal += parsed_bal_ok;
				} else {
					return Err((n, 6));
				}
			} else if com.0 == "C" { // C for Check-in
				if current_bal < 1 {
					return Err((n, 7));
				}
				current_bal -= 1;
			}
			balances.insert(String::from(args[0]), current_bal);
		}
	}
	Ok(())
}

pub fn build_balances(highest_block: &u128) {
	if verify_blocks(highest_block).is_err() {
		panic!("Cannot build balances for invalid chain");
	}

	let mut balances: HashMap<String, u128> = HashMap::new();

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
			} else if com.0 == "C" { // C for Check-in
				current_bal -= 1;
			}
			if current_bal > 0 {
				balances.insert(String::from(args[0]), current_bal);
			}
		}
	}
	let keys: Vec<_> = balances.keys().cloned().collect();
	let mut raw_balances_data = String::new();
	for key in keys {
		let bal = balances.get(&key).expect("it didnt work").to_owned();
		raw_balances_data += &(key + " " + bal.to_string().as_str() + "\n");
	}

	let mut save_file = fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open("../data/balances.txt").unwrap();

	let _ = save_file.write(raw_balances_data.as_bytes()).unwrap();
}

pub fn read_balances_to_var(balances: &mut HashMap<String, u128>) -> Result<(), ()> {
	let file = File::open("../data/balances.txt").unwrap();

	let reader = BufReader::new(file);

	// read each line in balances file
    for line in reader.lines().flatten() {
        let parts: Vec<&str> = line.split(' ').collect();
        if parts.len() == 2 {
            let key = parts[0].to_string();
            let value_maybe = parts[1].to_string().parse();
			if let Ok(value) = value_maybe {
				balances.insert(key, value);
			} else {
				return Err(());
			}
        } else {
			// err on invalid line
			return Err(());
		}
    }

	Ok(())
}

pub fn find_highest_block_num() -> u128 {
	let mut highest_block_num = 0;

	// Find highest block num locally
	let block_entries = fs::read_dir("../data/blocks").expect("Unable to get blocks");

	for entry in block_entries {
		let entry_path = entry.unwrap().path();
		let is_file = entry_path.is_file();
		let entry_name = entry_path.file_stem().expect("No entry name").to_string_lossy();
		let entry_extension = entry_path.extension().expect("No entry extension").to_string_lossy();
		if entry_name == "_prospective" && entry_extension == "txt" {
			continue;
		}
		let this_block_num: u128 = entry_name.parse().expect("Only number.txt files allowed in /data/block");
		if is_file && entry_extension == "txt" && this_block_num > highest_block_num {
			highest_block_num = this_block_num;
		}
	}

	highest_block_num
}

// fn get_data_from_block(block_num: u128, data_hash: String) -> Result<String, String> {
// 	let raw_data = read_block_file(&block_num);
// 	let raw_data_split = &raw_data.split("\n").collect::<Vec<_>>();
// 	let content_data = raw_data_split[6..].join("\n");
// 	let data_count = raw_data_split[3].parse().unwrap();
// 	let mut pointer_pos = 0;
//
// 	for _i in 0..data_count {
// 		let this_data_hash = &content_data[pointer_pos..=(pointer_pos + 63)];
// 		let mut stop_forward_look_flag = false;
// 		pointer_pos += 65;
// 		let mut pointer_offset = 0;
// 		while stop_forward_look_flag == false {
// 			let this_char = content_data.chars().nth(pointer_pos + pointer_offset).unwrap();
// 			// check each character until it is not numeric
// 			if !this_char.is_numeric() {
// 				stop_forward_look_flag = true;
// 			} else {
// 				pointer_offset += 1;
// 			}
// 		}
// 		let this_data_size: usize = content_data[pointer_pos..(pointer_pos + pointer_offset)]
// 			.parse().unwrap();
// 		pointer_pos += pointer_offset + 1;
// 		if this_data_hash == data_hash {
// 			return Ok(content_data[pointer_pos..(pointer_pos + this_data_size)].to_string());
// 		}
// 		pointer_pos += this_data_size + 1;
// 	}
//
// 	return Err("Data hash not found in block".to_string());
// }

// fn main() {
// 	let mut highest_block_num = find_highest_block_num();
//
// 	println!("Highest block number: {}", highest_block_num);
//
// 	let mut pblock = BlockHeaders {
// 		number: highest_block_num + 1,
// 		timestamp: 0, // minutes since epoch
// 		prev_block_hash: read_block_hash(&highest_block_num),
// 		block_hash: String::new()
// 	};
//
// 	add_data_to_pblock("A RANDOM123 3");
// 	add_data_to_pblock("A RANDOM456 1");
// 	add_data_to_pblock("C RANDOM123 1");
//
// 	finalize_pblock(&mut pblock);
//
// 	let valid_result = verify_blocks(&(pblock.number - 1));
// 	println!("Block validity check: {:?}", valid_result);
//
// 	build_balances(&(pblock.number - 1));
//
// 	println!("Balance of RANDOM123: {}", read_balance(&String::from("RANDOM123")));
// 	println!("Balance of RANDOM465: {}", read_balance(&String::from("RANDOM456")));
// 	println!("Balance of MISSING123: {}", read_balance(&String::from("MISSING123")));
// }
