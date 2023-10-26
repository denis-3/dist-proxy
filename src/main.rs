use warp::{ Filter };
use warp::http::{ StatusCode };
use serde_derive::{ Deserialize, Serialize };
use std::process;
use std::time::{ SystemTime, UNIX_EPOCH };
use std::sync::{ Arc, Mutex };
use std::env;
use url::Url;
use std::io::Write;
use std::io;
use std::fs;
use std::collections::HashMap;

mod protocol;
use protocol::{
	BlockHeaders,
	add_data_to_pblock,
	find_highest_block_num,
	verify_blocks,
	build_balances,
	read_balance,
	read_block_hash,
	finalize_pblock,
	read_block_file,
	read_balances_to_var,
	parse_command_string
};

#[derive(Debug, Deserialize, Serialize, Clone)]
struct JsonRequest {
    param: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct JsonResponse {
	result: String
}

const JSON_BODY_LIMIT: u64 = 1024;
const ETH_RPC_URL: &str = "https://ethereum-holesky.publicnode.com";

// body can be None for non-post requests
async fn reqwest_url(url: &String, method: &str, body: Option<&serde_json::Value>) -> Result<String, String> {
    let client = reqwest::Client::new();
    let response_maybe= if method == "get" {
		client.get(url).send().await
	} else if method == "post" {
		if body == None {
			unimplemented!("No post request without body");
		}
		client.post(url).json(&body.unwrap()).send().await
	} else {
		unimplemented!("Bad http request type: {}", method);
	};

	if response_maybe.is_err() {
		return Err(String::from("Request failed"));
	}
	let response = response_maybe.unwrap();

    if response.status().is_success() {
        let body_maybe = response.text().await;
		if body_maybe.is_err() {
			return Err(String::from("Parsing request body failed"));
		}
		let body = body_maybe.unwrap();
        Ok(body)
    } else {
        Err(String::from("Non-200 status code from reqwest"))
    }
}

// checks if a peer is in sync with this node
async fn validate_peer(url: &String, highest_block_num: &u128) -> Result<(), ()> {
	let peer_route_1 = url.to_string() + "/network/block-number";
	let req_1_maybe = reqwest_url(&peer_route_1, "get", None).await;
	if req_1_maybe.is_err() {
		return Err(());
	}
	let req_1_response: JsonResponse = serde_json::from_str(req_1_maybe.unwrap().as_str()).unwrap();
	if req_1_response.result != highest_block_num.to_string() {
		return Err(());
	}

	Ok(())
}

async fn download_block_from_peer(url: &String, block_num: &u128) -> Result<(), String> {
	let route_str = url.to_string() + "/network/raw-block?param=" + block_num.to_string().as_str();
	let req = reqwest_url(&route_str, "get", None).await;
	if let Err(err_data) = req {
		return Err(err_data.to_string());
	}
	let data = req.unwrap();
	let json_data: JsonResponse = serde_json::from_str(data.as_str()).unwrap();
	let file_path = String::from("../data/blocks/") + block_num.to_string().as_str() + ".txt";
	let mut write_file = std::fs::OpenOptions::new()
		.create(true)
        .write(true)
        .truncate(true)
        .open(file_path).unwrap();

	let _ = write_file.write(json_data.result.as_bytes()).unwrap();
	Ok(())
}

fn is_valid_url(input: &str) -> bool {
    Url::parse(input).is_ok()
}

#[tokio::main]
async fn main() {
	// clear prospective block
	let _ = fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open("../data/blocks/_prospective.txt").unwrap();

	let highest_block_num = Arc::new(Mutex::new(0_u128)); // the highest block that exists
	let peers = Arc::new(Mutex::new(Vec::<String>::new()));
	let reqwest_in_action = Arc::new(Mutex::new(false));
	let balances: Arc<Mutex<HashMap<String, u128>>> = Arc::new(Mutex::new(HashMap::new()));

	println!("Starting protocol...");
	println!("	Finding highest block no...");
	{
		let hbn_ref = highest_block_num.clone();
		let mut hbn_editable = hbn_ref.lock().unwrap();
		*hbn_editable = find_highest_block_num();

		if *hbn_editable == 0 {
			println!("It appears that you do not have the blockchain downloaded, would you like to download it? (Y/N)");
			let mut input = String::new();
			io::stdin()
				.read_line(&mut input)
				.expect("Failed to read input");
			if input.trim() == "Y" {
				println!("Starting blockchain download...");
				println!("Enter the URL of a node to download from:");
				let mut peer_url = String::new();
				io::stdin()
					.read_line(&mut peer_url)
					.expect("Failed to read input");
				let peer_hbn_route = peer_url.clone() + "/network/block-number";
				let peer_hbn_raw = reqwest_url(&peer_hbn_route, "get", None).await.unwrap();
				let peer_hbn_json: JsonResponse = serde_json::from_str(peer_hbn_raw.as_str()).unwrap();
				let peer_hbn: u128 = peer_hbn_json.result.parse().unwrap();
				for i in 1..=peer_hbn {
					println!("Downloading block {} of {}...", i, &hbn_editable);
					download_block_from_peer(&peer_url, &i).await.unwrap();
				}
				*hbn_editable = peer_hbn;
				println!("Finished downloading peer blocks");
			} else {
				println!("Not downloading blockchain");
			}
		}

		println!("	Verifying chain...");
		{
			let chain_validity = verify_blocks(&hbn_editable);
			if let Err(chain_err_data) = chain_validity {
				panic!("Chain is invalid, block {} is suspect with error code {}!", chain_err_data.0, chain_err_data.1);
			}
		}
		println!("	Building balances...");
		build_balances(&hbn_editable);
		let balances_ref = balances.clone();
		let mut bals_editable = balances_ref.lock().unwrap();
		let bals_read_result = read_balances_to_var(&mut bals_editable);
		if bals_read_result.is_err() {
			panic!("Error reading balances from file to HashMap.");
		}
	}
	println!("	Spawning block builder...");
	// block "mining" ticker
	let peers_ref_g = peers.clone(); // global peers reference
	let ria_ref_g = reqwest_in_action.clone(); // reqwest-in-action reference
	let hbn_ref_g = highest_block_num.clone(); // highest block num reference
	let bals_ref_g = balances.clone(); // all balances reference
	let _ = tokio::spawn(async move {
		let duration = tokio::time::Duration::from_secs(1);
		let mut interval = tokio::time::interval(duration);
        loop {
            interval.tick().await;
			let s = SystemTime::now()
				.duration_since(UNIX_EPOCH)
				.expect("Current time is before Epoch.")
				.as_secs();
			if s % 60 == 0 {
				// build block on the minute
				println!("Building new block...");
				let mut hbn_editable = hbn_ref_g.lock().unwrap();
				let mut this_pblock = BlockHeaders {
					number: *hbn_editable + 1,
					timestamp: s as u128,
					prev_block_hash: read_block_hash(&hbn_editable).unwrap(),
					block_hash: String::new()
				};
				finalize_pblock(&mut this_pblock);
				*hbn_editable += 1;
				// build and save balances
				build_balances(&hbn_editable);
				let mut bals_editable = bals_ref_g.lock().unwrap();
				let bals_read_result = read_balances_to_var(&mut bals_editable);
				if bals_read_result.is_err() {
					panic!("Error reading balances from file to HashMap.");
				}
			} else if s % 60 == 5 {
				// check peers shortly after block build
				let peers_list = peers_ref_g.lock().unwrap().clone();
				{
					let mut ria_editable = ria_ref_g.lock().unwrap();
					*ria_editable = true;
				}
				let hbn_readable = *hbn_ref_g.lock().unwrap();
				for i in (0..peers_list.len()).rev() {
					let peer_name = &peers_list[i];
					let validate_result = validate_peer(peer_name, &hbn_readable).await;
					// remove peer if it doesn't match data with this node
					if validate_result.is_err() {
						let mut peers_editable = peers_ref_g.lock().unwrap();
						peers_editable.remove(i);
					}
				}
				let mut ria_editable = ria_ref_g.lock().unwrap();
				*ria_editable = false;
			}
        }
    });

	println!("Starting webserver...");
	println!("	Instantaniating routes...");
	let warp_share_peers_vec = warp::any().map(move || Arc::clone(&peers));
	let warp_share_ria_bool = warp::any().map(move || Arc::clone(&reqwest_in_action));
	let warp_share_hbn_u128 = warp::any().map(move || Arc::clone(&highest_block_num));
	let warp_share_bals_hashmap = warp::any().map(move || Arc::clone(&balances));

	let cors = warp::cors()
	    .allow_any_origin()
	    .allow_headers(vec!["content-type"])
	    .allow_methods(vec!["POST", "GET", "DELETE"]);

	let read_block_hash_route = warp::get()
		.and(warp::path!("network" / "block-hash"))
		.and(warp::query())
		.map(move |query: JsonRequest| {
			let try_parse = query.param.parse::<u128>();
			let mut res = JsonResponse {
				result: String::new()
			};
			// TODO: add error handling here
			if try_parse.is_err() {
				return warp::reply::with_status(
					warp::reply::json(&res), StatusCode::OK
				);
			}

			let block_no = try_parse.unwrap();
			let block_hash_maybe = read_block_hash(&block_no);

			if let Ok(block_hash) = block_hash_maybe {
				res.result = block_hash;
				warp::reply::with_status(
					warp::reply::json(&res), StatusCode::OK
				)
			} else {
				res.result = String::from("No block hash found.");
				warp::reply::with_status(
					warp::reply::json(&res), StatusCode::BAD_REQUEST
				)
			}
		});

	let read_block_no_route = warp::get()
		.and(warp::path!("network" / "block-number"))
		.and(warp_share_hbn_u128.clone())
		.map(move |hbn_ref: Arc<Mutex<u128>>| {
			let hbn_readable = *hbn_ref.lock().unwrap();
			let res = JsonResponse {
				result: hbn_readable.to_string()
			};
			warp::reply::json(&res)
		});

	let read_balance_route = warp::get()
		.and(warp::path!("network" / "balance"))
		.and(warp::query())
		.map(|query: JsonRequest| {
			let res = JsonResponse {
				result: read_balance(&query.param).to_string()
			};

			warp::reply::json(&res)
		});

	let read_raw_block_route = warp::get()
		.and(warp::path!("network" / "raw-block"))
		.and(warp::query())
		.map(|query: JsonRequest| {
			let mut res = JsonResponse {
				result: String::from("param must be a number")
			};
			let block_num = query.param.parse::<u128>();
			if block_num.is_err() {
				return warp::reply::with_status(warp::reply::json(&res), StatusCode::BAD_REQUEST);
			}
			let read_result = read_block_file(&block_num.unwrap());
			if read_result.is_err() {
				res.result = String::from("Block file for this block number does not exist.");
				return warp::reply::with_status(warp::reply::json(&res), StatusCode::NOT_FOUND);
			}
			let read_data = read_result.unwrap();
			res.result = read_data;
			warp::reply::with_status(warp::reply::json(&res), StatusCode::OK)
		});

	let add_data_route = warp::post()
		.and(warp::path!("network" / "add-data"))
        .and(warp::body::json())
		.and(warp_share_bals_hashmap.clone())
		.and(warp_share_ria_bool.clone())
	    .map(|body: JsonRequest, bals_ref: Arc<Mutex<HashMap<String, u128>>>, ria_ref: Arc<Mutex<bool>>| {
			let parsed_data = parse_command_string(&body.param);
			if let Err(err_data) = parsed_data {
				let early_res = JsonResponse {
					result: err_data
				};

				return warp::reply::with_status(
					warp::reply::json(&early_res), StatusCode::BAD_REQUEST
				);
			} else if let Ok(com_data) = parsed_data {
				if com_data[0] == "C" {
					let bals_editable = bals_ref.lock().unwrap();
					if bals_editable.get(&com_data[1]).unwrap_or(&0) == &0_u128 {
						let early_res = JsonResponse {
							result: String::from("Not enough balance to check-in.")
						};

						return warp::reply::with_status(
							warp::reply::json(&early_res), StatusCode::BAD_REQUEST
						);
					}
				} else if com_data[0] == "A" {
					// check if the eth event exists for minting tokens
					let txn_hash = com_data[3].clone();
					let _ = tokio::spawn(async move {
						{
							let mut ria_editable = ria_ref.lock().unwrap();
							*ria_editable = true;
						}

						let eth_query_res = reqwest_url(&String::from(ETH_RPC_URL), "post", Some(&serde_json::json!({
							"id": 1,
							"jsonrpc": "2.0",
							"method": "eth_getTransactionReceipt",
							"params": [txn_hash]
						}))).await;

						if let Ok(query_data) = eth_query_res {
							let query_data_clean: String = query_data
								.chars()
								.filter(|&c| !c.is_whitespace())
								.collect();
							let check_str_1 = "\"address\":\"0xaf9ca8186f57bf3b9cd84521d256958471c4972b\"";
							// check for the right receiving address
							let check_str_2 = format!("000000000000{}\"]", com_data[1]);
							// check for the amount
							let receive_amt: u128 = com_data[2].parse().unwrap_or(0);
							let check_str_3 = format!("0000000000000000000{:x}\"", receive_amt);
							println!("Received data from RPC: \n{}", query_data);
							if !query_data_clean.contains(&check_str_1) ||
								!query_data_clean.contains(&check_str_2) ||
								!query_data_clean.contains(&check_str_3) {
									return;
								}
							let _ = add_data_to_pblock(&body.param);
						}

						let mut ria_editable = ria_ref.lock().unwrap();
						*ria_editable = false;
					});

					let early_res = JsonResponse {
						result: String::from("Your request is being processed.")
					};

					return warp::reply::with_status(
						warp::reply::json(&early_res), StatusCode::ACCEPTED
					);
				}
			}

			let func_result = add_data_to_pblock(&body.param);
			let mut status_code = StatusCode::OK;
			let result = String::from(if let Err(func_err) = func_result {
				status_code = StatusCode::CONFLICT;
				func_err
			} else { "Data added." });

			let res = JsonResponse {
				result: result
			};

			warp::reply::with_status(
				warp::reply::json(&res), status_code
			)
	    });

	let peer_connect_route = warp::post()
		.and(warp::path!("peer" / "connect"))
		.and(warp::body::json())
		.and(warp_share_peers_vec.clone())
		.and(warp_share_ria_bool.clone())
		.and(warp_share_hbn_u128.clone())
	    .map(move |body: JsonRequest,
			peers_ref: Arc<Mutex<Vec<String>>>,
			ria_ref: Arc<Mutex<bool>>,
			hbn_ref: Arc<Mutex<u128>>| {
			// TODO: prevent peers from duplicating in vec
			let mut res = JsonResponse {
				result: String::from("param is not a valid URL.")
			};

			// validity checks
			if !is_valid_url(&body.param) {
				return warp::reply::with_status(
					warp::reply::json(&res), StatusCode::BAD_REQUEST
				);
			}

			// do this in code block so that the peer connect thread has access to vec
			{
				let peers_editable = peers_ref.lock().unwrap();
				if peers_editable.len() >= 5 {
					res.result = String::from("Max peers reached.");
					return warp::reply::with_status(
						warp::reply::json(&res), StatusCode::CONFLICT
					);
				}
			}
			let ria_editable = ria_ref.lock().unwrap();

			if *ria_editable {
				res.result = String::from("Currently performing other task, try again later.");
				return warp::reply::with_status(
					warp::reply::json(&res), StatusCode::CONFLICT
				);
			}

			let peer_name = body.param.clone();
			let ria_ref_clone = ria_ref.clone();
			let _ = tokio::spawn(async move {
				// perform connection process for potential peer
				{
					let mut ria_editable = ria_ref_clone.lock().unwrap();
					*ria_editable = true;
				}
				let hbn_readable = *hbn_ref.lock().unwrap();
				let connect_result = validate_peer(&peer_name, &hbn_readable).await;
				if connect_result.is_err() {
					return;
				}
				let mut peers_editable = peers_ref.lock().unwrap();
				peers_editable.push(body.param);
				let mut ria_editable = ria_ref_clone.lock().unwrap();
				*ria_editable = false;
			});

			res.result = String::from("Received connection request.");

			warp::reply::with_status(
				warp::reply::json(&res), StatusCode::ACCEPTED
			)
	    });

	let peer_check_route = warp::get()
		.and(warp::path!("peer" / "check-connection"))
		.and(warp::query())
		.and(warp_share_peers_vec.clone())
		.map(move |query: JsonRequest, peers_ref: Arc<Mutex<Vec<String>>>| {
			let peers_editable = peers_ref.lock().unwrap();
			let is_connected = peers_editable.iter().any(|e| e == query.param.as_str());
			let res = JsonResponse {
				result: is_connected.to_string()
			};

			warp::reply::json(&res)
		});

	let shutdown_route = warp::delete()
		.and(warp::path!("control" / "shutdown"))
		.map(|| {
			println!("Received server shutdown command...");
			process::exit(0);
			""
		});

	let routes = warp::post()
	.and(
		warp::body::content_length_limit(JSON_BODY_LIMIT).and(
			add_data_route
			.or(peer_connect_route)
		)
	).or(
		read_balance_route
		.or(shutdown_route)
		.or(read_block_hash_route)
		.or(read_raw_block_route)
		.or(read_block_no_route)
		.or(peer_check_route)
	);
	// TODO: add 404 page here

	let env_args = env::args().collect::<Vec<_>>();
	let port: u16 = if env_args.len() > 1 {
		env_args[1].parse().unwrap_or(4114)
	} else {
		// default port
		4114
	};

	println!("	Serving on port {}...", port);
    warp::serve(routes.with(cors))
        .run(([127, 0, 0, 1], port))
        .await;
}
