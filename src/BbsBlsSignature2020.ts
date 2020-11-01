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
import jsonld from "jsonld";
import { suites, SECURITY_CONTEXT_URL } from "jsonld-signatures";
import {
  SignatureSuiteOptions,
  CreateProofOptions,
  CanonizeOptions,
  CreateVerifyDataOptions,
  VerifyProofOptions,
  VerifySignatureOptions,
  SuiteSignOptions
} from "./types";
import {
  w3cDate,
  getNumberOfBytesForBits,
  setBitInByteArray
} from "./utilities";
import { Bls12381G2KeyPair } from "@mattrglobal/bls12381-key-pair";

/**
 * The prefix identifier used to label blank nodes during JSON-LD operations
 */
const TRANSIENT_BLANK_NODE_ISSUER_PREFIX = "urn:bnid:";

/**
 * A BBS+ signature suite for use with BLS12-381 key pairs
 */
export class BbsBlsSignature2020 extends suites.LinkedDataProof {
  /**
   * Default constructor
   * @param options {SignatureSuiteOptions} options for constructing the signature suite
   */
  constructor(options: SignatureSuiteOptions = {}) {
    const {
      verificationMethod,
      signer,
      key,
      date,
      useNativeCanonize,
      LDKeyClass
    } = options;
    // validate common options
    if (
      verificationMethod !== undefined &&
      typeof verificationMethod !== "string"
    ) {
      throw new TypeError('"verificationMethod" must be a URL string.');
    }
    super({
      type:
        "https://w3c-ccg.github.io/ldp-bbs2020/context/v1#BbsBlsSignature2020"
    });

    this.proof = {
      "@context": "https://w3c-ccg.github.io/ldp-bbs2020/context/v1",
      type: "BbsBlsSignature2020"
    };

    this.LDKeyClass = LDKeyClass ?? Bls12381G2KeyPair;
    this.signer = signer;
    this.verificationMethod = verificationMethod;
    this.proofSignatureKey = "proofValue";
    if (key) {
      if (verificationMethod === undefined) {
        this.verificationMethod = key.id;
      }
      this.key = key;
      if (typeof key.signer === "function") {
        this.signer = key.signer();
      }
      if (typeof key.verifier === "function") {
        this.verifier = key.verifier();
      }
    }
    if (date) {
      this.date = new Date(date);
      if (isNaN(this.date)) {
        throw TypeError(`"date" "${date}" is not a valid date.`);
      }
    }
    this.useNativeCanonize = useNativeCanonize;
  }

  /**
   * @param options {CreateProofOptions} options for creating the proof
   *
   * @returns {Promise<object>} Resolves with the created proof object.
   */
  async createProof(options: CreateProofOptions): Promise<object> {
    const {
      purpose,
      documentLoader,
      expansionMap,
      compactProof,
      requiredRevealDocumentFrame
    } = options;

    let { document } = options;

    let proof;
    if (this.proof) {
      // use proof JSON-LD document passed to API
      proof = await jsonld.compact(this.proof, SECURITY_CONTEXT_URL, {
        documentLoader,
        expansionMap,
        compactToRelative: false
      });
    } else {
      // create proof JSON-LD document
      proof = { "@context": SECURITY_CONTEXT_URL };
    }

    // ensure proof type is set
    proof.type = this.type;

    // set default `now` date if not given in `proof` or `options`
    let date = this.date;
    if (proof.created === undefined && date === undefined) {
      date = new Date();
    }

    // ensure date is in string format
    if (date !== undefined && typeof date !== "string") {
      date = w3cDate(date);
    }

    // add API overrides
    if (date !== undefined) {
      proof.created = date;
    }

    if (this.verificationMethod !== undefined) {
      proof.verificationMethod = this.verificationMethod;
    }

    // allow purpose to update the proof; the `proof` is in the
    // SECURITY_CONTEXT_URL `@context` -- therefore the `purpose` must
    // ensure any added fields are also represented in that same `@context`
    proof = await purpose.update(proof, {
      document,
      suite: this,
      documentLoader,
      expansionMap
    });

    // Create the identifier issuer
    // Note - we have to use an issuer that will persist in things
    // like framing operations and expanding and compacting
    const issuer = new jsonld.util.IdentifierIssuer(
      TRANSIENT_BLANK_NODE_ISSUER_PREFIX
    );

    console.log(JSON.stringify(document, null, 2));

    // 1. Expand the input document
    let expandedDocument = await jsonld.expand(document, {
      documentLoader,
      expansionMap
    });

    console.log(JSON.stringify(expandedDocument, null, 2));

    // 2. Label all blank nodes on the expanded document
    expandedDocument = jsonld.util.relabelBlankNodes(expandedDocument, {
      issuer
    });

    // 3. Canonicalize the expanded and labeled document and proof to N-Quads
    const verifyData = await this.createVerifyData({
      document: expandedDocument,
      proof,
      documentLoader,
      expansionMap,
      compactProof
    });

    console.log(JSON.stringify(expandedDocument, null, 2));
    console.log(JSON.stringify(verifyData, null, 2));

    // 4. Initialize the requiredReveal BitArray to all zeros
    const requiredRevealByteArray = new Uint8Array(
      getNumberOfBytesForBits(verifyData.length)
    );

    if (requiredRevealDocumentFrame) {
      // 5. Frame input document with the required reveal frame
      const requiredRevealDocument = await jsonld.frame(
        expandedDocument,
        requiredRevealDocumentFrame,
        { documentLoader }
      );

      // 6. Canonicalize the required reveal frame result to N-Quads
      const requiredRevealStatements = await this.createVerifyDocumentData(
        requiredRevealDocument,
        {
          documentLoader,
          expansionMap,
          compactProof
        }
      );

      // 7. Obtain the indicies the required reveal N-Quads occupy in verify data
      // 8. Set the relevant bits in the requiredReveal BitArray corresponding to the obtained indicies
      requiredRevealStatements.forEach(item => {
        const position = verifyData.indexOf(item);
        setBitInByteArray(true, position, requiredRevealByteArray);
      });
    }

    //TODO review this?
    const proofData = await this.createVerifyProofData(proof, {
      documentLoader,
      expansionMap
    });

    // TODO here we have to transform the node identifiers to blank nodes
    const verifyDataBytes = verifyData.map(item => new Buffer(item));

    // Set the indicies of the proof statements as these must always be revealed
    proofData.forEach(item => {
      const position = verifyData.indexOf(item);
      setBitInByteArray(true, position, requiredRevealByteArray);
    });

    const requiredRevealBuffer = new Buffer(requiredRevealByteArray.buffer);

    verifyDataBytes.push(requiredRevealBuffer);

    proof[
      "https://w3c-ccg.github.io/ldp-bbs2020/context/v1#requiredReveal"
    ] = requiredRevealBuffer.toString("base64");

    // sign data
    proof = await this.sign({
      verifyData: verifyDataBytes,
      document,
      proof,
      documentLoader,
      expansionMap
    });

    return proof;
  }

  /**
   * @param options {object} options for verifying the proof.
   *
   * @returns {Promise<{object}>} Resolves with the verification result.
   */
  async verifyProof(options: VerifyProofOptions): Promise<object> {
    const { proof, document, documentLoader, expansionMap, purpose } = options;

    try {
      // create data to verify
      const verifyData = (
        await this.createVerifyData({
          document,
          proof,
          documentLoader,
          expansionMap,
          compactProof: false
        })
      ).map(item => new Uint8Array(Buffer.from(item)));

      // fetch verification method
      const verificationMethod = await this.getVerificationMethod({
        proof,
        document,
        documentLoader,
        expansionMap
      });

      // verify signature on data
      const verified = await this.verifySignature({
        verifyData,
        verificationMethod,
        document,
        proof,
        documentLoader,
        expansionMap
      });
      if (!verified) {
        throw new Error("Invalid signature.");
      }

      // ensure proof was performed for a valid purpose
      const { valid, error } = await purpose.validate(proof, {
        document,
        suite: this,
        verificationMethod,
        documentLoader,
        expansionMap
      });
      if (!valid) {
        throw error;
      }

      return { verified: true };
    } catch (error) {
      return { verified: false, error };
    }
  }

  async canonize(input: any, options: CanonizeOptions): Promise<string> {
    const { documentLoader, expansionMap, skipExpansion } = options;
    return jsonld.canonize(input, {
      algorithm: "URDNA2015",
      format: "application/n-quads",
      documentLoader,
      expansionMap,
      skipExpansion,
      useNative: this.useNativeCanonize
    });
  }

  async canonizeProof(proof: any, options: CanonizeOptions): Promise<string> {
    const { documentLoader, expansionMap } = options;
    proof = { ...proof };
    delete proof[this.proofSignatureKey];
    return this.canonize(proof, {
      documentLoader,
      expansionMap,
      skipExpansion: false
    });
  }

  /**
   * @param document {CreateVerifyDataOptions} options to create verify data
   *
   * @returns {Promise<{string[]>}.
   */
  async createVerifyData(options: CreateVerifyDataOptions): Promise<string[]> {
    const { proof, document, documentLoader, expansionMap } = options;

    const proofStatements = await this.createVerifyProofData(proof, {
      documentLoader,
      expansionMap
    });
    const documentStatements = await this.createVerifyDocumentData(document, {
      documentLoader,
      expansionMap
    });

    // concatenate c14n proof options and c14n document
    return proofStatements.concat(documentStatements);
  }

  /**
   * @param proof to canonicalize
   * @param options to create verify data
   *
   * @returns {Promise<{string[]>}.
   */
  async createVerifyProofData(
    proof: any,
    { documentLoader, expansionMap }: any
  ): Promise<string[]> {
    const c14nProofOptions = await this.canonizeProof(proof, {
      documentLoader,
      expansionMap
    });

    return c14nProofOptions.split("\n").filter(_ => _.length > 0);
  }

  /**
   * @param document to canonicalize
   * @param options to create verify data
   *
   * @returns {Promise<{string[]>}.
   */
  async createVerifyDocumentData(
    document: any,
    { documentLoader, expansionMap }: any
  ): Promise<string[]> {
    const c14nDocument = await this.canonize(document, {
      documentLoader,
      expansionMap
    });

    return c14nDocument.split("\n").filter(_ => _.length > 0);
  }

  /**
   * @param document {object} to be signed.
   * @param proof {object}
   * @param documentLoader {function}
   * @param expansionMap {function}
   */
  async getVerificationMethod({ proof, documentLoader }: any): Promise<any> {
    let { verificationMethod } = proof;

    if (typeof verificationMethod === "object") {
      verificationMethod = verificationMethod.id;
    }

    if (!verificationMethod) {
      throw new Error('No "verificationMethod" found in proof.');
    }

    // Note: `expansionMap` is intentionally not passed; we can safely drop
    // properties here and must allow for it
    const result = await jsonld.frame(
      verificationMethod,
      {
        "@context": SECURITY_CONTEXT_URL,
        "@embed": "@always",
        id: verificationMethod
      },
      {
        documentLoader,
        compactToRelative: false,
        expandContext: SECURITY_CONTEXT_URL
      }
    );
    if (!result) {
      throw new Error(`Verification method ${verificationMethod} not found.`);
    }

    // ensure verification method has not been revoked
    if (result.revoked !== undefined) {
      throw new Error("The verification method has been revoked.");
    }

    return result;
  }

  /**
   * @param options {SuiteSignOptions} Options for signing.
   *
   * @returns {Promise<{object}>} the proof containing the signature value.
   */
  async sign(options: SuiteSignOptions): Promise<object> {
    const { verifyData, proof } = options;

    if (!(this.signer && typeof this.signer.sign === "function")) {
      throw new Error(
        "A signer API with sign function has not been specified."
      );
    }

    const proofValue: Uint8Array = await this.signer.sign({
      data: verifyData
    });

    proof[this.proofSignatureKey] = Buffer.from(proofValue).toString("base64");

    return proof;
  }

  /**
   * @param verifyData {VerifySignatureOptions} Options to verify the signature.
   *
   * @returns {Promise<boolean>}
   */
  async verifySignature(options: VerifySignatureOptions): Promise<boolean> {
    const { verificationMethod, verifyData, proof } = options;
    let { verifier } = this;

    if (!verifier) {
      const key = await this.LDKeyClass.from(verificationMethod);
      verifier = key.verifier(key, this.alg, this.type);
    }

    return await verifier.verify({
      data: verifyData,
      signature: new Uint8Array(
        Buffer.from(proof[this.proofSignatureKey] as string, "base64")
      )
    });
  }
}
