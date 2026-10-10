// #################################################################
// /qompassai/vongola/crates/vongola/src/wasm/js_plugin.rs
// Qompass AI Js Plugin
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Qompass AI
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// use std::sync::Arc;

// // use wasmer::{imports, Instance, Module, Store, ValueType};
// use wasmtime::{Engine, Linker, Store};
// use wasmtime_wasi::{
//     preview1::{self, WasiP1Ctx},
//     WasiCtxBuilder,
// };

#[allow(dead_code)]
struct SessionTest {}

impl SessionTest {
    #[allow(dead_code)]
    pub fn new() -> Self { Self {} }

    #[allow(dead_code)]
    pub fn get_header(_key: &str) -> String { String::from("test") }
}

// #[allow(dead_code)]
// pub async fn load_plugin() -> anyhow::Result<()> {
//     let mut config = wasmtime::Config::new();
//     config.wasm_reference_types(true);
//     config.debug_info(false);
//     config.async_support(true);

//     let engine = Engine::new(&config)?;
//     let wasi_ctx = WasiCtxBuilder::new()
//         .inherit_stdio()
//         .inherit_stdout()
//         .build_p1();

//     let mut linker: Linker<WasiP1Ctx> = Linker::new(&engine);
//     preview1::add_to_linker_async(&mut linker, |t| t)?;
//     let mut store = Store::new(&engine, wasi_ctx);

//     let module = wasmtime::Module::from_binary(
//         &engine,
//         include_bytes!("../../../../mid-test/target/wasm32-wasip1/release/
// mid_test.wasm"),     )?;

//     // instance

//     let instance = linker.instantiate_async(&mut store, &module).await?;

//     let req_filter_fn = instance.get_func(&mut store,
// "on_request_filter").unwrap();

//     let scope = wasmtime::RootScope::new(&mut store);
//     let session = wasmtime::ExternRef::new(scope,
// Arc::new(SessionTest::new()))?;

//     // call function with ref
//     let mut ret: Vec<wasmtime::Val> = vec![wasmtime::Val::I32(0)];
//     req_filter_fn
//         .call_async(&mut store, &[session.into()], &mut ret)
//         .await?;

//     Ok(())
// }

// #[cfg(test)]
// mod tests {
//     use super::*;

//     #[tokio::test]
//     async fn test_load_plugin() {
//         load_plugin().await.unwrap();

//         assert_eq!(1, 1)
//     }
// }
