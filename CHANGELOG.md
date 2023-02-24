# [0.12.0](https://github.com/zkp-ld/jsonld-signatures-bbs/compare/v0.9.0...v0.12.0) (2023-02-24)


### Bug Fixes

* adapt to the API change of bbs-signature ([22cc246](https://github.com/zkp-ld/jsonld-signatures-bbs/commit/22cc246f23850a167a56a48b35c1d7a448d1663b))
* adapt to the API change of bbs-signature ([b320a11](https://github.com/zkp-ld/jsonld-signatures-bbs/commit/b320a11cc16c8daf4faceab33f943264628cae5c))
* add revealed statements into challenge hash inputs ([864bcc7](https://github.com/zkp-ld/jsonld-signatures-bbs/commit/864bcc7cbf6c80b800ab7c0db4e2e74fd1c211d7))
* add VerifyProofResult to types/index ([9c905b8](https://github.com/zkp-ld/jsonld-signatures-bbs/commit/9c905b89d7f21e06963cdce22edd1bb21f85e9a1))
* avoid incorrect nonce handling ([75a2511](https://github.com/zkp-ld/jsonld-signatures-bbs/commit/75a2511544f226891ad3a854c224f469fac060f0))
* bug fix ([e22f213](https://github.com/zkp-ld/jsonld-signatures-bbs/commit/e22f21345aff72285f42132bcb169cc21855a73d))
* bug fix ([270c61f](https://github.com/zkp-ld/jsonld-signatures-bbs/commit/270c61f88e261c4b073eab240402a18b93459f89))
* catch uncaught error due to inconsistent reveal document ([1796d0d](https://github.com/zkp-ld/jsonld-signatures-bbs/commit/1796d0d3346b17fcee123fc8f33d461494d27862))
* change revealed indicies structure (close [#3](https://github.com/zkp-ld/jsonld-signatures-bbs/issues/3)) ([186d56d](https://github.com/zkp-ld/jsonld-signatures-bbs/commit/186d56dda68f64fd228d25550362bcbf149eb5c1))
* change scope of private logger method for debug ([8f067b3](https://github.com/zkp-ld/jsonld-signatures-bbs/commit/8f067b3d71f83f52c95b44714c56c4d30859ace9))
* change scope of private logger method for debug ([3b9e7fa](https://github.com/zkp-ld/jsonld-signatures-bbs/commit/3b9e7fa084dc4f1b2de0c47cc44c1ffc6f7e7c55))
* change the way of converting blank node ids ([#129](https://github.com/zkp-ld/jsonld-signatures-bbs/issues/129)) ([8e85b0f](https://github.com/zkp-ld/jsonld-signatures-bbs/commit/8e85b0f1ddcee2d4a17f7dc8d4e5fff55c989df6)), closes [#128](https://github.com/zkp-ld/jsonld-signatures-bbs/issues/128)
* constructor of BbsBlsSignatureProofTermwise2020 ([8f46514](https://github.com/zkp-ld/jsonld-signatures-bbs/commit/8f465141245355086db6015436866063f13202a3))
* correct handling blank nodes ([557d747](https://github.com/zkp-ld/jsonld-signatures-bbs/commit/557d747f6e6af94008932e9026b35f9abe62a6d5))
* correct issuer's did ([6bad302](https://github.com/zkp-ld/jsonld-signatures-bbs/commit/6bad302ff6621e149382fd214742f2293f266e56))
* fix serialization error ([fe2f98e](https://github.com/zkp-ld/jsonld-signatures-bbs/commit/fe2f98e810c140d3611fb0bafd7fd50cd1c5b8d1))
* invalid verification of derived document with no proof ([fb2985c](https://github.com/zkp-ld/jsonld-signatures-bbs/commit/fb2985c3157ed6d45437ddd069aed17765eac006))
* make result in VerifyProofMultiResult be optional ([5332bfb](https://github.com/zkp-ld/jsonld-signatures-bbs/commit/5332bfbb280920148ff3e25130f6feb458eb4450))
* resolve conflicts ([ed90177](https://github.com/zkp-ld/jsonld-signatures-bbs/commit/ed90177cbc838240dc268882cb0ceaf5d674ec5f))
* typo in tests ([8cb39d5](https://github.com/zkp-ld/jsonld-signatures-bbs/commit/8cb39d54925cb8ff0cb3bd9b38fb9dc29d85fe9f))
* update BbsBlsSignatureTermwise2020 ([3e5e90d](https://github.com/zkp-ld/jsonld-signatures-bbs/commit/3e5e90d59b03d8044602139bb2ae06f836598eb8))
* update BbsBlsSignatureTermwise2020 ([a8ebda9](https://github.com/zkp-ld/jsonld-signatures-bbs/commit/a8ebda93b76ce9a5842ff9cf29725fa743c703ee))
* update Termwise variation ([cb5d371](https://github.com/zkp-ld/jsonld-signatures-bbs/commit/cb5d371574ea7128fd1a207ec97fc0ab6f9ce36f))
* verification result ([e087fec](https://github.com/zkp-ld/jsonld-signatures-bbs/commit/e087fec4794b7560ecea9a68b6dca74a17bd5096))


* Upgrade dependencies (#5) ([b42823b](https://github.com/zkp-ld/jsonld-signatures-bbs/commit/b42823bfc720f47f2d0c15302a3d9518c2e5bb29)), closes [#5](https://github.com/zkp-ld/jsonld-signatures-bbs/issues/5)


### Features

* add another URI prefix for anonymous ID ([a4d56f2](https://github.com/zkp-ld/jsonld-signatures-bbs/commit/a4d56f2d352f168a8411c0338a66e6803f807efb))
* add another URI prefix for anonymous literal ([ac72cd9](https://github.com/zkp-ld/jsonld-signatures-bbs/commit/ac72cd918d40725c28296ae709b165dea4ec36a6))
* add BbsBlsSignatureTermwise2020 ([507867c](https://github.com/zkp-ld/jsonld-signatures-bbs/commit/507867cdcbae28b86bb77c07268c1411c27d9256))
* add BbsBlsSignatureTermwise2020 ([c5783a3](https://github.com/zkp-ld/jsonld-signatures-bbs/commit/c5783a38bab6604fa6dfbb403588c4c699639f08))
* add blsCreateProofMulti ([74453a1](https://github.com/zkp-ld/jsonld-signatures-bbs/commit/74453a19ae6398fb64c63447e691a82ac43d9c4c))
* Add console.log for debugging ([02738c9](https://github.com/zkp-ld/jsonld-signatures-bbs/commit/02738c93228c8b35965c1caa0ef7349536d22dae))
* Add console.log for debugging ([b9208cc](https://github.com/zkp-ld/jsonld-signatures-bbs/commit/b9208cc27f25ec07716c233a0ef929d26e36d136))
* add JSON-LD-Signatures-like APIs ([cf938ac](https://github.com/zkp-ld/jsonld-signatures-bbs/commit/cf938ac316c8d23e65c42f286f5976f43d52c52e))
* add rdf-canonize dependency ([f29486a](https://github.com/zkp-ld/jsonld-signatures-bbs/commit/f29486a17eae148e7ad9ebc3ef95922dd2b82a5d))
* add rdf-canonize dependency ([c9e5b9a](https://github.com/zkp-ld/jsonld-signatures-bbs/commit/c9e5b9ad2f632a0bb2a9a2bdb7181db0cf9f1409))
* add verifyProofMulti ([9456771](https://github.com/zkp-ld/jsonld-signatures-bbs/commit/9456771baa2d4081101b186d4a6f255d12aef2e4))
* allow the use of publicKeyJwk to derive and verify proof ([#145](https://github.com/zkp-ld/jsonld-signatures-bbs/issues/145)) ([0cec1f1](https://github.com/zkp-ld/jsonld-signatures-bbs/commit/0cec1f1b99792abfbfbfd0beca0f03f80008efd6))
* allow the use of publicKeyJwk to verify signature ([27a9b90](https://github.com/zkp-ld/jsonld-signatures-bbs/commit/27a9b9007730e29e4a40e0f588db011ee92311b3))
* anonymized derivedProof ([f1f5c01](https://github.com/zkp-ld/jsonld-signatures-bbs/commit/f1f5c01da1b2a0bd5598a4d5e144b9e34201b1ed))
* bnid anonymization & UUID-based anon ID ([df45b0b](https://github.com/zkp-ld/jsonld-signatures-bbs/commit/df45b0baa7296b37ab3b2d928a9b74104921ec95))
* bump bbs-signatures dependency ([#131](https://github.com/zkp-ld/jsonld-signatures-bbs/issues/131)) ([0644298](https://github.com/zkp-ld/jsonld-signatures-bbs/commit/06442984574d45f2fc87ceb5a34e353f03015688))
* change anonID ([a1d68a9](https://github.com/zkp-ld/jsonld-signatures-bbs/commit/a1d68a926919a66009cda688aa29ccd7bb3288cd))
* enable validation ([9d99f0f](https://github.com/zkp-ld/jsonld-signatures-bbs/commit/9d99f0fa277df4fcda10ac37bfa24556690b95b0))
* import customized bbs-signatures and bls12381-key-pair ([e4ae477](https://github.com/zkp-ld/jsonld-signatures-bbs/commit/e4ae47706e008bfcbaadbfcfec03c9e47e8beb89))
* rename the suite and remove backward compatibility ([f7976b2](https://github.com/zkp-ld/jsonld-signatures-bbs/commit/f7976b2be54f0145aa26503ef310477301d2f4f4))
* set the proof value on the derived proof ([3580973](https://github.com/zkp-ld/jsonld-signatures-bbs/commit/3580973081d5e9ad8dbae167d538e3ff8ce260b2))
* support multiple proofs per credential ([f694eb6](https://github.com/zkp-ld/jsonld-signatures-bbs/commit/f694eb63723ed93e15b0c4f9504edcfa4d69b0bf))
* support range proofs (experimental) ([2b94fef](https://github.com/zkp-ld/jsonld-signatures-bbs/commit/2b94fefc0177c1c4cc388d8f70c7c775c1a6a498))
* update Termwise variation ([9aa75ee](https://github.com/zkp-ld/jsonld-signatures-bbs/commit/9aa75ee42c4a4e647d6a6ef66994fc731f448187))
* update verifyProofMulti ([e772d55](https://github.com/zkp-ld/jsonld-signatures-bbs/commit/e772d55d26997d14ee49603a656c672227da072c))


### BREAKING CHANGES

* `expansionMap` option is obsoleted

* build: upgrade dependencies; remove all the expansionMap options

* refactor: remove unused codes

* build: add eslint-formatter-table

* test: modify a bad suffix (for currently skipped test)

* test: remove `name` from jest.config



# [0.11.0](https://github.com/mattrglobal/jsonld-signatures-bbs/compare/v0.10.0...v0.11.0) (2021-08-06)

### Features

- allow the use of publicKeyJwk to derive and verify proof ([#145](https://github.com/mattrglobal/jsonld-signatures-bbs/issues/145)) ([0cec1f1](https://github.com/mattrglobal/jsonld-signatures-bbs/commit/0cec1f1b99792abfbfbfd0beca0f03f80008efd6))

# [0.10.0](https://github.com/mattrglobal/jsonld-signatures-bbs/compare/v0.9.0...v0.10.0) (2021-05-26)

### BREAKING CHANGES

Support for NodeJS v10 has been deprecated due to it now being [EOL](https://nodejs.org/en/about/releases/)

### Bug Fixes

- change the way of converting blank node ids ([#129](https://github.com/mattrglobal/jsonld-signatures-bbs/issues/129)) ([8e85b0f](https://github.com/mattrglobal/jsonld-signatures-bbs/commit/8e85b0f1ddcee2d4a17f7dc8d4e5fff55c989df6)), closes [#128](https://github.com/mattrglobal/jsonld-signatures-bbs/issues/128)

### Features

- bump bbs-signatures dependency ([#131](https://github.com/mattrglobal/jsonld-signatures-bbs/issues/131)) ([0644298](https://github.com/mattrglobal/jsonld-signatures-bbs/commit/06442984574d45f2fc87ceb5a34e353f03015688)), closes [#119](https://github.com/mattrglobal/jsonld-signatures-bbs/issues/119) and [#102](https://github.com/mattrglobal/jsonld-signatures-bbs/issues/119)

# [0.9.0](https://github.com/mattrglobal/jsonld-signatures-bbs/compare/v0.8.0...v0.9.0) (2021-04-05)

### Features

- use local context instead of security v3 ([#116](https://github.com/mattrglobal/jsonld-signatures-bbs/issues/116)) ([e8c6b9c](https://github.com/mattrglobal/jsonld-signatures-bbs/commit/e8c6b9c3d30afea3eade7ffa45954c17190aa41c))

# [0.8.0](https://github.com/mattrglobal/jsonld-signatures-bbs/compare/v0.7.0...v0.8.0) (2021-02-24)

### Bug Fixes

- addresses bug with blank nodes that was breaking nested reveals ([#96](https://github.com/mattrglobal/jsonld-signatures-bbs/issues/96)) ([6c347fd](https://github.com/mattrglobal/jsonld-signatures-bbs/commit/6c347fd9f17940842509ef3e04051cfaccc83361)), closes [#91](https://github.com/mattrglobal/jsonld-signatures-bbs/issues/91)
- update blsCreateProof expected response to promise ([#98](https://github.com/mattrglobal/jsonld-signatures-bbs/issues/98)) ([2523b47](https://github.com/mattrglobal/jsonld-signatures-bbs/commit/2523b47f6399873ed1916e518721a273bf3872b0))

### Features

- **sample:** update to v0.7.0 release ([#80](https://github.com/mattrglobal/jsonld-signatures-bbs/issues/80)) ([38747e6](https://github.com/mattrglobal/jsonld-signatures-bbs/commit/38747e61c2b1a4bd763cdf995535dfc589c28b2d))
- add nonce parameter to deriveProof method ([#100](https://github.com/mattrglobal/jsonld-signatures-bbs/issues/100)) ([8d414d9](https://github.com/mattrglobal/jsonld-signatures-bbs/commit/8d414d97f99226194301c4bbf2d565cfedcaf43a))
- adds support for providing a proofDocument with multiple proofs ([#82](https://github.com/mattrglobal/jsonld-signatures-bbs/issues/82)) ([1bb9a17](https://github.com/mattrglobal/jsonld-signatures-bbs/commit/1bb9a17254810a7eef3181cec0a2ad60a726246d)), closes [#79](https://github.com/mattrglobal/jsonld-signatures-bbs/issues/79)
- bump bbs-signatures package version ([#107](https://github.com/mattrglobal/jsonld-signatures-bbs/issues/107)) ([edf78a7](https://github.com/mattrglobal/jsonld-signatures-bbs/commit/edf78a77c05723175d2cc17ee8ff523e648a78dc))
- export types ([#78](https://github.com/mattrglobal/jsonld-signatures-bbs/issues/78)) ([c66d438](https://github.com/mattrglobal/jsonld-signatures-bbs/commit/c66d43823c11a38e3d9f13242f726d5f0371d3fd))
- migrate to async api ([#106](https://github.com/mattrglobal/jsonld-signatures-bbs/issues/106)) ([01000b4](https://github.com/mattrglobal/jsonld-signatures-bbs/commit/01000b4bf48932a47d7c8c889d2201f8e8085d46))
- migrate to using security context ([2673a0a](https://github.com/mattrglobal/jsonld-signatures-bbs/commit/2673a0a077c232ca5be61b93339be547e5341635))

### BREAKING CHANGES

- The type IRI for BBS signatures now stems from the https://w3id.org/security namespace, meaning all future signing and verifications using the signature suite will now use that namespace rather than the placeholder namespace that was being used. Note - this means verifying signatures and proofs issued with older versions of this library will not work.

# [0.7.0](https://github.com/mattrglobal/jsonld-signatures-bbs/compare/v0.6.0...v0.7.0) (2020-08-28)

### Bug Fixes

- json-ld context issue ([a911440](https://github.com/mattrglobal/jsonld-signatures-bbs/commit/a9114404dede2a736cf37ca2588b62ad5d6a4492))

### Features

- add the ability to specify the key pair class when creating suites([#66](https://github.com/mattrglobal/jsonld-signatures-bbs/issues/66)) ([1fb03cf](https://github.com/mattrglobal/jsonld-signatures-bbs/commit/1fb03cf2b2a26ba1c79e8b4eaa836bc24c3763e7))
- update sample to use latest package version ([cdd9b39](https://github.com/mattrglobal/jsonld-signatures-bbs/commit/cdd9b3932e2d5022c9ecc78573e232bcc1d3cdfc))
- update to use bbs-signatures ([#73](https://github.com/mattrglobal/jsonld-signatures-bbs/issues/73)) ([540ccec](https://github.com/mattrglobal/jsonld-signatures-bbs/commit/540ccecbe6f755db7975615cdd23e6b88ee16b3f))
- use bbs-signatures library ([#61](https://github.com/mattrglobal/jsonld-signatures-bbs/issues/61)) ([dbbd4e5](https://github.com/mattrglobal/jsonld-signatures-bbs/commit/dbbd4e569169781cd56dabc6d1290578cd773560))

# [0.6.0](https://github.com/mattrglobal/jsonld-signatures-bbs/compare/v0.5.0...v0.6.0) (2020-05-26)

### Features

- update bbs dependency ([20d6f62](https://github.com/mattrglobal/jsonld-signatures-bbs/commit/20d6f622a5270704f3e5744c2790ce6042c37491))
- update sample ([#49](https://github.com/mattrglobal/jsonld-signatures-bbs/issues/49)) ([73fdf98](https://github.com/mattrglobal/jsonld-signatures-bbs/commit/73fdf98a63a00702f71a9df87dff9f9bcf6fe22a))

# [0.5.0](https://github.com/mattrglobal/jsonld-signatures-bbs/compare/v0.4.0...v0.5.0) (2020-05-09)

### Features

- use from key pair method ([#47](https://github.com/mattrglobal/jsonld-signatures-bbs/issues/47)) ([2998710](https://github.com/mattrglobal/jsonld-signatures-bbs/commit/29987106344191819bac3073d913e39927183813))

# [0.4.0](https://github.com/mattrglobal/jsonld-signatures-bbs/compare/v0.3.0...v0.4.0) (2020-05-04)

### Features

- add simple sample ([#41](https://github.com/mattrglobal/jsonld-signatures-bbs/issues/41)) ([8bb49ce](https://github.com/mattrglobal/jsonld-signatures-bbs/commit/8bb49ce2e76bf9be432c8b538bd04b440ec65add))
- update node-bbs-signatures version ([#44](https://github.com/mattrglobal/jsonld-signatures-bbs/issues/44)) ([1a85b83](https://github.com/mattrglobal/jsonld-signatures-bbs/commit/1a85b8326a6fca08184665672a44816cc4ff7bff))

# [0.3.0](https://github.com/mattrglobal/jsonld-signatures-bbs/compare/v0.2.0...v0.3.0) (2020-04-30)

### Bug Fixes

- use expandContext in jsonld.frame operation ([ce5cb3e](https://github.com/mattrglobal/jsonld-signatures-bbs/commit/ce5cb3ec2bd33c747980c8725c191e5866ec31c6))

### Features

- add deriveProof api ([a1024f7](https://github.com/mattrglobal/jsonld-signatures-bbs/commit/a1024f7001236a6e3a12e4c13e90e2f444f8047f))

# [0.2.0](https://github.com/mattrglobal/jsonld-signatures-bbs/compare/v0.1.0...v0.2.0) (2020-04-28)

### Bug Fixes

- linting ([0f4d7e7](https://github.com/mattrglobal/jsonld-signatures-bbs/commit/0f4d7e7ddae9f5d62ce495f58c478ca0873fff90))
- remove un-used lodash dependency ([08f5820](https://github.com/mattrglobal/jsonld-signatures-bbs/commit/08f582058cfe35b3943c55203ed95f7c21113e53))
- update lock file ([74f993e](https://github.com/mattrglobal/jsonld-signatures-bbs/commit/74f993e1b7d404f54cfa442bafead6a607b570c9))

### Features

- add bbs proofs support ([c41b09f](https://github.com/mattrglobal/jsonld-signatures-bbs/commit/c41b09f9865a88ad062db89f90d427f7a6a99690))
- update bbs-signatures dep ([#29](https://github.com/mattrglobal/jsonld-signatures-bbs/issues/29)) ([402a4a7](https://github.com/mattrglobal/jsonld-signatures-bbs/commit/402a4a7fe1936a685bfc828b72de02994a2a4200))
- update proofs api, wip ([b92151e](https://github.com/mattrglobal/jsonld-signatures-bbs/commit/b92151efa52c297683bb3c2371638fd7d8045499))
- use json-ld framing instead of object intersection ([87fa989](https://github.com/mattrglobal/jsonld-signatures-bbs/commit/87fa98955e166226a26f12388838fcbc1910fe20))

# 0.1.0 (2020-04-27)

Initial release
