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

/* eslint-disable @typescript-eslint/no-explicit-any */
/**
 * Options for creating a proof for multiple credentials
 */
export interface DeriveProofMultiOptions {
  /**
   * Input documents, proofs, and reveal documents
   */
  readonly inputDocuments: DeriveProofMultiInputDocs[];
  /**
   * Optional custom document loader
   */
  // eslint-disable-next-line @typescript-eslint/ban-types
  documentLoader?: Function;
  /**
   * Nonce to include in the derived proof
   */
  readonly nonce?: Uint8Array;
  /**
   * Indicates whether to compact the resulting proof
   */
  readonly skipProofCompaction?: boolean;
  /**
   * URIs to be hiddened in the resulting proof
   */
  readonly hiddenUris?: string[];
}

export interface DeriveProofMultiInputDocs {
  /**
   * Document outlining what statements to reveal
   */
  readonly revealDocument: any;
  /**
   * The document featuring the proof to derive from
   */
  readonly document: any;
  /**
   * The proof for the document
   */
  readonly proof: any;
}
