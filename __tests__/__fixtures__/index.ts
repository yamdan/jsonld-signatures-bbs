/*
 * Copyright 2020 - MATTR Limited
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import { customLoader } from "./customDocumentLoader";

import exampleBls12381KeyPair from "./data/exampleBls12381KeyPair.json";
import exampleBls12381KeyPairJwk from "./data/exampleBls12381KeyPairJwk.json";
import exampleEd25519KeyPair from "./data/did_example_b34ca6cd37bbf23_test.json";
import testDocument from "./data/test_document.json";
import testRevealDocument from "./data/test_reveal_document.json";
import testRevealDocumentWithUnknownAttributes from "./data/test_reveal_document_with_unknown_attributes.json";
import testSignedDocument from "./data/test_signed_document.json";
import testSignedDocumentMultiProofs from "./data/test_signed_document_multi_proofs.json";
import testSignedDocumentMultiDifProofs from "./data/test_signed_document_multi_dif_proofs.json";
import testSignedDocumentEd25519 from "./data/test_signed_document_ed25519.json";
import testVcDocument from "./data/test_vc.json";
import testVcDocumentJwk from "./data/test_vc_jwk.json";
import testSignedVcDocument from "./data/test_signed_vc.json";
import testSignedVcDocumentJwk from "./data/test_signed_vc_jwk.json";
import testRevealVcDocument from "./data/test_vc_reveal_document.json";
import testRevealVcDocumentInvalid from "./data/test_vc_reveal_document_invalid.json";
import testRevealAllVcDocument from "./data/test_vc_reveal_all_document.json";
import testRevealVcDocumentJwk from "./data/test_vc_reveal_document_jwk.json";
import testRevealAllDocument from "./data/test_reveal_all_document.json";
import testNestedRevealDocument from "./data/test_nested_reveal_document.json";
import testNestedRevealFullDocument from "./data/test_nested_reveal_full_document.json";
import testNestedVcDocument from "./data/test_nested_vc_document.json";
import testSignedNestedVcDocument from "./data/test_signed_nested_vc_document.json";
import testAnonymousVcDocument from "./data/test_anonymous_vc.json";
import testAnonymousVcComplexDocument from "./data/test_anonymous_vc_complex.json";
import testRevealAnonymousVcDocument from "./data/test_anonymous_vc_reveal_document.json";
import testRevealAnonymousVcComplexDocument from "./data/test_anonymous_vc_complex_reveal_document.json";
import testNestedAnonymousVcDocument from "./data/test_nested_anonymous_vc_document.json";
import expExampleBls12381KeyPair from "./data/exp_exampleBls12381KeyPair.json";
import expExampleBls12381KeyPair2 from "./data/exp_exampleBls12381KeyPair2.json";
import expExampleBls12381KeyPair3 from "./data/exp_exampleBls12381KeyPair3.json";
import expVCDocument from "./data/exp_vc.json";
import expVCDocument2 from "./data/exp_vc2.json";
import expVCDocument3 from "./data/exp_vc3.json";
import expVCDocumentWithArray from "./data/exp_vc_with_array.json";
import expRevealDocument from "./data/exp_reveal_document.json";
import expRevealDocument2 from "./data/exp_reveal_document2.json";
import expRevealDocument3 from "./data/exp_reveal_document3.json";
import expVCDocumentForRangeProof from "./data/exp_vc_rangeproof.json";
import expVCDocumentForRangeProof2 from "./data/exp_vc_rangeproof2.json";
import expVCDocumentForRangeProofInvalid from "./data/exp_vc_rangeproof_invalid.json";
import expRevealDocumentWithoutRangeProof from "./data/exp_reveal_document_rangeproof0.json";
import expRevealDocumentForRangeProof from "./data/exp_reveal_document_rangeproof1.json";
import expRevealDocumentForRangeProof2 from "./data/exp_reveal_document_rangeproof2.json";

export {
  exampleBls12381KeyPair,
  exampleBls12381KeyPairJwk,
  exampleEd25519KeyPair,
  testDocument,
  testRevealDocument,
  testRevealDocumentWithUnknownAttributes,
  testRevealVcDocumentJwk,
  testSignedDocument,
  testSignedDocumentMultiProofs,
  testSignedDocumentMultiDifProofs,
  testSignedDocumentEd25519,
  testVcDocument,
  testVcDocumentJwk,
  testRevealAllDocument,
  testSignedVcDocument,
  testSignedVcDocumentJwk,
  testRevealVcDocument,
  testRevealVcDocumentInvalid,
  testRevealAllVcDocument,
  testNestedRevealDocument,
  testNestedRevealFullDocument,
  testNestedVcDocument,
  testSignedNestedVcDocument,
  customLoader,
  testAnonymousVcDocument,
  testRevealAnonymousVcDocument,
  testNestedAnonymousVcDocument,
  expExampleBls12381KeyPair,
  expExampleBls12381KeyPair2,
  expExampleBls12381KeyPair3,
  expVCDocument,
  expVCDocument2,
  expVCDocument3,
  expVCDocumentWithArray,
  expRevealDocument,
  expRevealDocument2,
  expRevealDocument3,
  testAnonymousVcComplexDocument,
  testRevealAnonymousVcComplexDocument,
  expVCDocumentForRangeProof,
  expVCDocumentForRangeProof2,
  expVCDocumentForRangeProofInvalid,
  expRevealDocumentWithoutRangeProof,
  expRevealDocumentForRangeProof,
  expRevealDocumentForRangeProof2
};
