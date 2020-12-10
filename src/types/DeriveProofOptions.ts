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

import { Options } from "jsonld";
import { Document, JsonLdObj } from "jsonld/jsonld-spec";
import { BbsBlsSignatureProof2020 } from "src/BbsBlsSignatureProof2020";
import { LinkedDataSignature } from "./LinkedDataSignature";
import { Proof } from "./Proof";
import DocumentLoader = Options.DocumentLoader;
import ExpansionMap = Options.ExpansionMap;

/**
 * Options for creating a proof
 */
export interface DeriveProofOptions {
  /**
   * Document outlining what statements to reveal
   */
  readonly revealDocument: JsonLdObj;
  /**
   * The document featuring the proof to derive from
   */
  readonly document: Document;
  /**
   * The proof for the document
   */
  readonly proof: Proof;
  /**
   * Optional custom document loader
   */
  documentLoader?: DocumentLoader;
  /**
   * Optional expansion map
   */
  expansionMap?: ExpansionMap;
  /**
   * Nonce to include in the derived proof
   */
  readonly nonce?: Uint8Array;
  /**
   * Indicates whether to compact the resulting proof
   */
  readonly skipProofCompaction?: boolean;

  /**
   * Defines the type of the suite which can be used to derive a Proof
   * currently a LinkedDataProof suite doesn't support usage of deriveProof
   * therefore this is strongly typed to BbsBlsSignatureProof2020.
   * Once LinkedDataProof generically supports the API in the interface then
   * this can be switched to LinkedDataProof.
   */
  readonly suite: BbsBlsSignatureProof2020;
}
