# /qompassai/vongola/makefile
# Qompass AI Vongola Makefile
lint:
	cargo clippy -- -D clippy::pedantic -D clippy::perf -D clippy::complexity -D clippy::style -D clippy::correctness -D clippy::suspicious
lint.fix:
	cargo clippy --fix --allow-dirty --allow-staged
test:
	cargo test --all-features
build.release:
	cargo zigbuild --release
build.dev:
	cargo zigbuild
dev:
	cargo watch -c -x run -d 1 -i data -i dist
