use std::fs;
use sha2::{ Digest, Sha256 };

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
		// let mut this_command = Vec::new();
		// this_command.push((words[0].to_string(), words[1].to_string()));
		if words.len() == 2 {
			commands.push((words[0].to_string(), words[1].to_string()));
		} else if words.len() == 3 {
			commands.push((
				words[0].to_string(),
				words[1].to_string() + " " + words[2]
			));
		} else if words.len() == 4 {
			commands.push((
				words[0].to_string(),
				words[1].to_string() + " " + words[2] + " " + words[3]
			));
		}
    }

	Ok(commands)
}

pub fn read_balance(owner: &String) -> u128 {
	let raw_data = fs::read_to_string("../data/balances.txt").unwrap();
	let raw_data_split = raw_data.split('\n').collect::<Vec<_>>();

	for line in raw_data_split {
		if line.starts_with(owner) {
			let line_split = line.split(' ').collect::<Vec<_>>();
			return line_split[1].parse().expect("Sad");
		}
	}

	0
}

pub fn parse_command_string(com_str: &String) -> Result<Vec<String>, String> {
	if com_str.len() == 0 {
		return Err(String::from("Zero-length string"));
	}

	let valid_commands: Vec<char> = vec!['A', 'C'];
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
	return Ok(data_split);
}

// pub fn read_prev_block_hash(block_num: u128) -> String {
// 	if block_num == 0 {
// 		return quick_sha256(&String::new());
// 	}
//
// 	let mut read_file = fs::File::open("../data/blocks/".to_string() + &block_num.to_string() + ".txt").unwrap();
// 	let mut raw_data = String::new();
// 	let _ = read_file.read_to_string(&mut raw_data).unwrap();
//
// 	// prev blockhash is always second set of 64 chars
// 	return raw_data[64..=128].to_string();
// }
