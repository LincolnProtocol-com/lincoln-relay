# Third-party notices

The first-party JavaScript in `src/`, `scripts/` and `docker/` is licensed under Apache-2.0, as stated in each file's SPDX header and in [LICENSE](LICENSE).

The relay installs these npm packages at build time. They are not vendored here and keep their own licenses:

| Package | Version | License | Use |
| --- | --- | --- | --- |
| snarkjs | 0.7.5 | GPL-3.0 ([COPYING](LICENSES/snarkjs-GPL-3.0-COPYING.txt)) | Groth16 verification and key checks |
| @openzeppelin/contracts | 5.0.2 | MIT ([text](LICENSES/OpenZeppelin-MIT.txt)) | Contract sources for release recompilation |
| solc | 0.8.28 | GPL-3.0 | Release recompilation |
| viem | 2.22.14 | MIT | Chain access, ABI, signatures |
| maci-crypto | 2.5.0 | MIT | Poseidon hashing |
| @zk-kit/lean-imt | 2.2.4 | MIT | Merkle trees |

The runtime image also copies the `cast` binary from the pinned Foundry image (MIT OR Apache-2.0). A Docker image built from this repository therefore contains GPL-3.0 components; distribute it accordingly.

The full dependency tree and versions are pinned in `package-lock.json`.
