# #################################################################
# /qompassai/vongola/Makefile
# Qompass AI Makefile
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Qompass AI
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

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
