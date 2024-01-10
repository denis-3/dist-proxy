# Upchain (Distributed Proxy for Backup Servers)
Upchain is a decentralized network for managing automated backup servers. Coming soon...

## Installation
1. Please install Rust by following the instructions here: https://www.rust-lang.org/learn/get-started
2. Create a folder named `data` as a sibling of the top-level folder of this repo. In this `data` folder, create a folder named `blocks`.
3. Run `cargo run` in the folder of this repo. This will compile and execute the source code in `/src`.

The resulting directory structure should be like this:
```
/folder
|
|\__data
|  |
|  \__blocks
|
 \__dist-proxy
   |
   \...
```

## Usage
At first it will ask you to download the blockchain. You can type `Y`/`N` (then hit `enter`) based on if any nodes are available to download from. Then, every minute the node will generate a block based on incoming data.
