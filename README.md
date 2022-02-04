# rust-openssl-hkdf

Additional wrapper to add support for HKDF using [rust-openssl](https://github.com/sfackler/rust-openssl). Used as a temporary bridge until rust-openssl releases a new official version that supports this functionality. openssl-sys currently supports hkdf and is the basis of this crate. See rust-openssl PR [here](https://github.com/sfackler/rust-openssl/pull/1498). 

See [Documentation](https://crates.io/crates/openssl-hkdf) for usage.

## License

```
Copyright 2021 Tom Leavy

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```
