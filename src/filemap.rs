use std::fs;
use std::io::Seek;
use std::io::Read;
use std::io::Write;

// -- Key-value pair storage in files -- \\
// Only maps string to u128

#[derive(Clone, Copy)]
pub struct FileMap<'a> {
	pub file_path: &'a str,
	iter_key_number: usize
}

impl FileMap<'_> {
	pub fn new(file_path: &str, overwrite_existing_file: bool) -> Result<FileMap, ()> {
		let s = fs::OpenOptions::new()
	        .write(true)
			.read(true)
			.create(true)
	        .truncate(overwrite_existing_file)
	        .open(file_path);

		if s.is_err() {
			return Err(());
		}

		s.unwrap();

		Ok(
			FileMap {
				file_path,
				iter_key_number: 0
			}
		)
	}

	// gets value for key and key's position in file
	// Ok() return is tuple of value, position
	pub fn get_value_and_position(&self, key: &str) -> Result<(u128, usize), String> {
		if key.is_empty() || key.len() > 100 {
			return Err(String::from("Key empty or too large."));
		} else if key.contains('|') {
			return Err(String::from("Key cannot contain vertical bar character."))
		}
		let file_metadata = fs::metadata(self.file_path).unwrap();
		let file_len: usize = file_metadata.len().try_into().unwrap();

		let mut file = fs::OpenOptions::new()
	        .read(true)
	        .open(self.file_path).unwrap();

		let mut read_size: usize = 100;
		let mut cursor_pos = 0;
		while cursor_pos < file_len {
			if cursor_pos + read_size >= file_len {
				read_size = file_len - cursor_pos;
			}
			let s = file.seek(std::io::SeekFrom::Start(cursor_pos as u64));
			if s.is_err() {
				return Err(String::from("Error setting file cursor"));
			}
			let mut buffer = vec![0; read_size];
			let s = file.read_exact(&mut buffer);
			if s.is_err() {
				return Err(String::from("Error reading file."));
			}
			let mut line_buff = vec![];
			for (n, char_code) in buffer.iter().enumerate() {
				// detect newline char
				if char_code == &10u8 {
					cursor_pos += n + 1;
					break;
				}
				line_buff.push(buffer[n]);
			}
			let line_str = std::str::from_utf8(&line_buff).unwrap_or("");
			let search_str = format!("{} ", key);
			if line_str.starts_with(&search_str) {
				let splitted = line_str.split(' ').collect::<Vec<&str>>();
				let num_value = splitted[1].parse::<u128>();
				if num_value.is_err() {
					return Err(String::from("Error parsing string to u128"));
				} else if let Ok(result) = num_value {
					return Ok((result, cursor_pos - line_buff.len()));
				}
			}
		}
		Err(String::from("Key does not exist"))
	}

	pub fn get(&self, key: &str) -> Result<u128, String> {
		let res = self.get_value_and_position(key)?;
		Ok(res.0)
	}

	// change value of key without looking for the key (assuming key exists)
	pub fn insert_given_position(&self, key: &str, value: u128, old_data: (u128, usize)) -> Result<(), String> {
		let to_insert = format!("{} {}\n", key, value);

		let mut file = fs::OpenOptions::new().write(true).open(self.file_path).unwrap();
		let filler = "|".repeat(format!("{} {}", key, old_data.0).len());
		let s = file.seek(std::io::SeekFrom::Start((old_data.1 - 1) as u64));
		if s.is_err() {
			return Err(String::from("Error setting file cursor."));
		}
		let s = file.write(filler.as_bytes());
		if s.is_err() {
			return Err(String::from("Error writing file."));
		}

		let mut file = fs::OpenOptions::new().write(true).append(true).open(self.file_path).unwrap();
		// insert new data at the end of file
		let s = file.write(to_insert.as_bytes());
		if s.is_err() {
			return Err(String::from("Error writing file."));
		}

		Ok(())
	}

	pub fn insert(&self, key: &str, value: u128) -> Result<(), String> {
		// if key already exists, replace past data with filler
		let past_data_maybe = self.get_value_and_position(key);
		if let Ok(old_data) = past_data_maybe {
			return self.insert_given_position(key, value, old_data);
		}

		let mut file = fs::OpenOptions::new().write(true).append(true).open(self.file_path).unwrap();
		let to_insert = format!("{} {}\n", key, value);
		// insert new data at the end of file
		let s = file.write(to_insert.as_bytes());
		if s.is_err() {
			return Err(String::from("Error writing file."));
		}

		Ok(())
	}

	pub fn update<F>(&self, key: &str, upd_closure: F) -> Result<(), String>
	where F: Fn(u128) -> u128, {
		let old_data = self.get_value_and_position(key)?;
		let new_value = upd_closure(old_data.0);
		self.insert_given_position(key, new_value, old_data)
	}

	// cleans vertical bar characters from file
	pub fn clean_file(&self) -> Result<(), String> {
		let mut file = fs::OpenOptions::new().read(true).write(true).open(self.file_path).unwrap();
		let file_metadata = fs::metadata(self.file_path).unwrap();
		let file_len: usize = file_metadata.len().try_into().unwrap();
		let mut offset = 0;
		// do it by-character
		for n in 0..file_len {
			let s = file.seek(std::io::SeekFrom::Start(n as u64));
			if s.is_err() {
				return Err(String::from("Error setting file cursor."));
			}

			let mut buffer = vec![0];
			if n < file_len - 1 {
				buffer.push(0);
			}
			let s = file.read_exact(&mut buffer);
			if s.is_err() {
				return Err(String::from("Error reading file."));
			}

			// look for vertical bar | character
			if buffer[0] == 124 {
				offset += 1;
				// if there is a newline char after | char, remove it as well
				if buffer.len() > 1 && buffer[1] == 10 {
					offset += 1;
				}
				continue;
			}

			let write_cursor = if offset > n {
				0
			} else {
				n - offset
			};

			let s = file.seek(std::io::SeekFrom::Start(write_cursor as u64));
			if s.is_err() {
				return Err(String::from("Error setting file cursor."));
			}

			let s = file.write(&buffer);
			if s.is_err() {
				return Err(String::from("Error writing file."));
			}
		}
		// remove trailing characters
		let s = file.set_len((file_len - offset) as u64);
		if s.is_err() {
			return Err(String::from("Error truncating file."));
		}

		Ok(())
	}
}

impl Iterator for FileMap<'_> {
	type Item = (String, u128);

	fn next(&mut self) -> Option<Self::Item> {
		let mut file = fs::OpenOptions::new().read(true).open(self.file_path).unwrap();
		let file_metadata = fs::metadata(self.file_path).unwrap();
		let file_len: usize = file_metadata.len().try_into().unwrap();
		let mut key_counter = 0;
		let mut cursor_pos = 0;
		let mut read_size = 100;

		while cursor_pos < file_len {
			if read_size + cursor_pos >= file_len {
				read_size = file_len - cursor_pos;
			}
			let s = file.seek(std::io::SeekFrom::Start(cursor_pos as u64));
			if s.is_err() {
				panic!("Error setting file cursor.");
			}

			let mut buffer = vec![0; read_size];
			let s = file.read_exact(&mut buffer);
			if s.is_err() {
				panic!("Error reading file.");
			}

			if buffer.contains(&10) {
				let splitted = std::str::from_utf8(&buffer).unwrap().split("\n").collect::<Vec<&str>>();
				cursor_pos += splitted[0].len();
				// do not increase key counter for invalid lines with | character
				if splitted[0].contains("|") {
					continue;
				}
				if key_counter == self.iter_key_number {
					let key_value = splitted[0].split(" ").collect::<Vec<&str>>();
					if key_value.len() == 1 {
						self.iter_key_number = 0;
						return None;
					}
					let key = String::from(key_value[0]);
					let value: u128 = key_value[1].parse().expect("Could not parse value");
					self.iter_key_number += 1;
					return Some((key, value));
				}
				key_counter += 1;
			} else {
				cursor_pos += read_size;
			}
		}

		self.iter_key_number = 0;
		None
	}
}
