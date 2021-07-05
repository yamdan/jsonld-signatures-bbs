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

import { suites } from "jsonld-signatures";

/* eslint-disable @typescript-eslint/no-explicit-any */
/**
 * Options for creating a proof
 */
export interface SkolemizeOptions {
  /**
   * The signature suite
   */
  readonly suite: suites.LinkedDataProof;
  /**
   * Optional custom document loader
   */
  documentLoader?: Function;
  /**
   * Optional expansion map
   */
  expansionMap?: Function;
  /**
   * Indicates whether to compact the resulting proof
   */
  readonly skipProofCompaction?: boolean;
}

export interface SkolemizeResult {
  /**
   * Skolemized document (JSON-LD)
   */
  compactInputProofDocument: string;
  /**
   * Skolemized document (array of quads)
   */
  transformedInputDocumentStatements: string[];
  /**
   * document statements (array of quads)
   */
  documentStatements: string[];
  /**
   * proof statements (array of quads)
   */
  proofStatements: string[];
}

export interface RevealOptions {
  /**
   * The signature suite
   */
  readonly suite: suites.LinkedDataProof;
  /**
   * Optional custom document loader
   */
  documentLoader?: Function;
  /**
   * Optional expansion map
   */
  expansionMap?: Function;
}

export interface RevealResult {
  /**
   * Revealed document (JSON-LD)
   */
  revealDocumentResult: any;
  /**
   * Revealed document statements (array of quads)
   */
  revealDocumentStatements: string[];
}
