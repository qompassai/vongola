# Single binary

You can also run Vongola as a standalone binary using rust's `cargo` or downloading it directly from [https://github.com/qompassai/vongola/releases](https://github.com/qompassai/vongola/releases) for you system.

## Cargo


To install (and compile) Vongola for your system, first ensure you have the latest Rust version:



### 1. Rust is not installed&#x20;

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

### 2. Rust is already installed

```bash
rustup update
```

### 3. Install the binary

```bash
cargo install vongola 
```

You can now  run Vongola as a user binary:

```bash
touch vongola.hcl
# add routing configuration to your vongola.hcl file

vongola -c ./
```



## Downloading the binary

Ensure you are download the right one from the [Releases page on Github](https://github.com/qompassai/vongola/releases) and once you download it, make sure it has the right permissions to execute, e.g.:

```bash
# Replace {VERSION} with the version you want
# Replace {PLATFORM} with the one for your system
curl -O -L https://github.com/qompassai/vongola/releases/download/{VERSION}/{PLATFORM}.tar.gz
tar -czvf {PLATFORM}.tar.gz

chmod +x ./vongola
```

Once that is done you can check if the binary is functional:

```
vongola --help
```
