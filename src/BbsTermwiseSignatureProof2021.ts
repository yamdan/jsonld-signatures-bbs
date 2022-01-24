/* eslint-disable @typescript-eslint/no-explicit-any */
import jsonld from "jsonld";
import { suites } from "jsonld-signatures";
import { randomBytes } from "@stablelib/random";
import { v4 as uuidv4 } from "uuid";
import {
  blsCreateProofMulti,
  blsVerifyProofMulti
} from "@yamdan/bbs-signatures";
import { Bls12381G2KeyPair } from "@yamdan/bls12381-key-pair";

import {
  DidDocumentPublicKey,
  CreateVerifyDataOptions,
  CanonizeOptions,
  CanonicalizeOptions,
  CanonicalizeResult,
  DeriveProofMultiOptions,
  VerifyProofMultiOptions,
  VerifyProofMultiResult,
  DeriveProofOptions,
  VerifyProofOptions,
  VerifyProofResult
} from "./types";
import { BbsTermwiseSignature2021 } from "./BbsTermwiseSignature2021";
import { Statement, RDFTerm } from "./Statement";
import { SECURITY_CONTEXT_URLS, RANGE_URI } from "./utilities";

class URIAnonymizer {
  private prefix = "urn:anon:";
  private regexp = /^<urn:anon:([^>]+)>/;

  private equivs: Map<string, [string, [number, number][]]> = new Map();

  constructor();
  constructor(equivs: Map<string, [string, [number, number][]]>);
  constructor(equivs?: Map<string, [string, [number, number][]]>) {
    if (equivs) {
      this.equivs = equivs;
    }
  }

  anonymizeJsonld(doc: any): any {
    const anonymizeDocument = (doc: any): void => {
      for (const [k, v] of Object.entries(doc)) {
        if (typeof v === "object") {
          anonymizeDocument(v);
        } else if (typeof v === "string") {
          const anid = this.equivs.get(`<${v}>`);
          if (anid !== undefined) {
            doc[k] = `${this.prefix}${anid[0]}`;
          }
        }
      }
    };

    const res = { ...doc }; // copy input
    anonymizeDocument(res);
    return res;
  }

  anonymizeStatement(s: Statement): Statement {
    for (const [uri, value] of this.equivs) {
      s = s.replace(uri.slice(1, -1), `${this.prefix}${value[0]}`);
    }
    return s;
  }

  extractAnonID(t: string): string | null {
    const found = t.match(this.regexp);
    if (found === null) return null;
    return found[1];
  }
}

export class BbsTermwiseSignatureProof2021 extends suites.LinkedDataProof {
  constructor({ useNativeCanonize, key, LDKeyClass, type }: any = {}) {
    super({
      type: "BbsTermwiseSignatureProof2021"
    });

    this.proof = {
      "@context": SECURITY_CONTEXT_URLS,
      type: "BbsTermwiseSignatureProof2021"
    };

    this.mappedDerivedProofType = "BbsTermwiseSignature2021";
    this.supportedDeriveProofType =
      BbsTermwiseSignatureProof2021.supportedDerivedProofType;
    this.LDKeyClass = LDKeyClass ?? Bls12381G2KeyPair;
    this.proofSignatureKey = "proofValue";
    this.key = key;
    this.useNativeCanonize = useNativeCanonize;
    this.Suite = BbsTermwiseSignature2021;
  }

  // ported from
  // https://github.com/transmute-industries/verifiable-data/blob/main/packages/bbs-bls12381-signature-2020/src/BbsBlsSignatureProof2020.ts
  ensureSuiteContext({ document }: any): void {
    const contextUrl = "https://www.zkp-ld.org/bbs-termwise-2021.jsonld";
    if (
      document["@context"] === contextUrl ||
      (Array.isArray(document["@context"]) &&
        document["@context"].includes(contextUrl))
    ) {
      // document already includes the required context
      return;
    }
    throw new TypeError(
      `The document to be signed must contain this suite's @context, ` +
        `"${contextUrl}".`
    );
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

    delete proof.nonce;
    delete proof.proofValue;

    return this.canonize(proof, {
      documentLoader,
      expansionMap,
      skipExpansion: false
    });
  }

  /**
   * @param document {CreateVerifyDataOptions} options to create verify data
   *
   * @returns {Promise<Statement[]>}.
   */
  async createVerifyData(
    options: CreateVerifyDataOptions
  ): Promise<Statement[]> {
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
   * @param nQuads {string} canonized RDF N-Quads as a string
   *
   * @returns {Statement[]} an array of statements
   */
  getStatements(nQuads: string): Statement[] {
    return nQuads
      .split("\n")
      .filter((_) => _.length > 0)
      .map((s: string) => new Statement(s));
  }

  /**
   * @param proof to canonicalize
   * @param options to create verify data
   *
   * @returns {Promise<Statement[]>}.
   */
  async createVerifyProofData(
    proof: any,
    { documentLoader, expansionMap }: any
  ): Promise<Statement[]> {
    const c14nProofOptions = await this.canonizeProof(proof, {
      documentLoader,
      expansionMap
    });

    return this.getStatements(c14nProofOptions);
  }

  /**
   * @param document to canonicalize
   * @param options to create verify data
   *
   * @returns {Promise<Statement[]>}.
   */
  async createVerifyDocumentData(
    document: any,
    { documentLoader, expansionMap }: any
  ): Promise<Statement[]> {
    const c14nDocument = await this.canonize(document, {
      documentLoader,
      expansionMap
    });

    return this.getStatements(c14nDocument);
  }

  /**
   * @param document {object} to be signed.
   * @param proof {object}
   * @param documentLoader {function}
   * @param expansionMap {function}
   */
  async getVerificationMethod({
    proof,
    documentLoader
  }: any): Promise<DidDocumentPublicKey> {
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
        // adding jws-2020 context to allow publicKeyJwk
        "@context": [
          "https://w3id.org/security/v2",
          "https://w3id.org/security/suites/jws-2020/v1"
        ],
        "@embed": "@always",
        id: verificationMethod
      },
      {
        documentLoader,
        compactToRelative: false,
        expandContext: SECURITY_CONTEXT_URLS
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
   * Get canonical N-Quads from JSON-LD
   *
   * @param document to canonicalize
   * @param proof to canonicalize
   * @param options to create verify data
   *
   * @returns {Promise<CanonicalizeResult>} canonicalized statements
   */
  async canonicalize(
    document: string,
    proof: string,
    options: CanonicalizeOptions
  ): Promise<CanonicalizeResult> {
    const { suite, documentLoader, expansionMap, skipProofCompaction } =
      options;

    // Get the input document statements
    const documentStatements: Statement[] =
      await suite.createVerifyDocumentData(document, {
        documentLoader,
        expansionMap,
        compactProof: !skipProofCompaction
      });

    // Get the proof statements
    const proofStatements: Statement[] = await suite.createVerifyProofData(
      proof,
      {
        documentLoader,
        expansionMap,
        compactProof: !skipProofCompaction
      }
    );

    return { documentStatements, proofStatements };
  }

  /**
   * Calculate revealed indicies
   *
   * @param fullStatements full document statements
   * @param partialStatements revealed document statements
   * @param offset offset to index
   *
   * @returns {number[]} revealed statementwise indicies
   */
  getIndicies(
    fullStatements: Statement[],
    partialStatements: Statement[],
    offset: number
  ): number[] {
    // Reveal the statements indicated from the reveal document
    const preDocumentRevealedIndicies = partialStatements.map((x) =>
      fullStatements.findIndex((y) => x.toString() === y.toString())
      );
    if (preDocumentRevealedIndicies.includes(-1)) {
        throw new Error(
          "Some statements in the reveal document not found in original proof"
        );
      }
    const documentRevealedIndicies = preDocumentRevealedIndicies.map(
      (idx) => idx + offset
    );

    // Check there is not a mismatch
    if (documentRevealedIndicies.length !== partialStatements.length) {
      throw new Error(
        "Some statements in the reveal document not found in original proof"
      );
    }

    return documentRevealedIndicies;
  }

  /**
   * Expand indicies to fit termwise encoding
   *   e.g., [0,       2,         5          ]  (statementwise)
   *      -> [0,1,2,3, 8,9,10,11, 20,21,22,23]  (termwise)
   *
   * @param {number[]} statementIndicies statementwise indicies
   *
   * @returns {number[]} termwise indicies
   */
  statementIndiciesToTermIndicies(statementIndicies: number[]): number[] {
    const NUM_OF_TERMS_IN_STATEMENT = 4;
    return statementIndicies.flatMap((index) =>
      [...Array(NUM_OF_TERMS_IN_STATEMENT).keys()].map(
        (i) => index * NUM_OF_TERMS_IN_STATEMENT + i
      )
    );
  }

  statementToUint8(statementArray: Statement[][]): Uint8Array {
    return new Uint8Array(
      Buffer.from(
        statementArray
          .map((statements) =>
            statements.map((statement) => statement.toString()).join("")
          )
          .join("")
      )
    );
  }

  /**
   * Derive a proof from a proof and reveal document
   *
   * @param options {object} options for deriving a proof.
   *
   * @returns {Promise<object>} Resolves with the derived proof object.
   */
  // eslint-disable-next-line @typescript-eslint/ban-types
  async deriveProof(options: DeriveProofOptions): Promise<object> {
    const {
      document,
      proof,
      revealDocument,
      documentLoader,
      expansionMap,
      skipProofCompaction,
      nonce,
      hiddenUris
    } = options;

    const derivedProofs = await this.deriveProofMulti({
      inputDocuments: [
        {
          document,
          proof,
          revealDocument
        }
      ],
      documentLoader,
      expansionMap,
      skipProofCompaction,
      nonce,
      hiddenUris
    });

    return derivedProofs[0];
  }

  /**
   * Derive proofs from multiple proofs and reveal documents
   *
   * @param options {object} options for deriving proofs.
   *
   * @returns {Promise<object[]>} Resolves with the array of derived proofs object.
   */
  // eslint-disable-next-line @typescript-eslint/ban-types
  async deriveProofMulti(options: DeriveProofMultiOptions): Promise<object[]> {
    const {
      inputDocuments,
      documentLoader,
      expansionMap,
      skipProofCompaction,
      hiddenUris = [],
      nonce: givenNonce
    } = options;

    // Create a nonce if one is not supplied
    const nonce = givenNonce || randomBytes(50);

    const termsArray: Uint8Array[][] = [];
    const revealedStatementIndiciesArray: number[][] = [];
    const revealedTermIndiciesArray: number[][] = [];
    const issuerPublicKeyArray: Buffer[] = [];
    const signatureArray: Buffer[] = [];
    const revealedDocuments: any = [];
    const derivedProofs: any = [];
    const revealedStatementsArray: Statement[][] = [];

    const equivs: Map<string, [string, [number, number][]]> = new Map(
      hiddenUris.map((uri) => [`<${uri}>`, [uuidv4(), []]])
    );

    const anonymizer = new URIAnonymizer(equivs);

    const numberOfProofs: number[] = inputDocuments.map(
      ({ proof: givenProof }) =>
        Array.isArray(givenProof) ? givenProof.length : 1
    );
    const proofIndexOffset: number[] = numberOfProofs.map((_, i) =>
      numberOfProofs.slice(0, i).reduce((a, b) => a + b, 0)
    );

    let docIndex = 0;
    for (const {
      document,
      proof: givenProof,
      revealDocument
    } of inputDocuments) {
      // make array from (array | object)
      const proofs = Array.isArray(givenProof) ? givenProof : [givenProof];

      // Initialize the signature suite
      const suite = new this.Suite();

      // Canonicalize document: get N-Quads from JSON-LD
      const documentStatements: Statement[] =
        await suite.createVerifyDocumentData(document, {
          documentLoader,
          expansionMap,
          compactProof: !skipProofCompaction
        });

      // Skolemize: transform any blank node identifiers for the input
      // document statements into actual node identifiers
      // e.g., _:c14n0 -> urn:bnid:<docIndex>:_:c14n0
      // where <docIndex> corresponds to the index of document in inputDocuments array
      const skolemizedStatements = documentStatements.map((statement) =>
        statement.skolemize(docIndex)
      );
      const skolemizedDocument: string = await jsonld.fromRDF(
        skolemizedStatements.join("\n")
      );

      // Prepare an equivalence class for each blank node identifier
      new Set(
        skolemizedStatements
          .flatMap((item: Statement) => item.toTerms())
          .filter((term) => term.match(/^<urn:bnid:[0-9]+:_:c14n[0-9]+>$/))
      ).forEach((skolemizedBnid) => {
        equivs.set(skolemizedBnid, [uuidv4(), []]);
      });

      // Reveal: extract revealed parts using JSON-LD Framing
      const preRevealedDocument = await jsonld.frame(
        skolemizedDocument,
        revealDocument,
        { documentLoader }
      );
      const revealedDocument = anonymizer.anonymizeJsonld(preRevealedDocument);
      revealedDocuments.push(revealedDocument);

      // Prepare anonymizedStatements: N-Quads statements
      // where each specified URI and bnid is replaced by anonymous ID, i.e., urn:anon:<UUIDv4>
      const anonymizedStatements = skolemizedStatements.map((statement) =>
        anonymizer.anonymizeStatement(statement)
      );
      const anonymizedDocument: string = await jsonld.fromRDF(
        anonymizedStatements.join("\n")
      );

      // Process multiple proofs in an input document
      let proofIndex = 0;
      for (const proof of proofs) {
        // Validate that the input proof document has a proof compatible with this suite
        if (
          !BbsTermwiseSignatureProof2021.supportedDerivedProofType.includes(
            proof.type
          )
        ) {
          throw new TypeError(
            `proof document proof incompatible, expected proof types of ${JSON.stringify(
              BbsTermwiseSignatureProof2021.supportedDerivedProofType
            )} received ${proof.type}`
          );
        }

        // Extract the original BBS signature from the input proof
        const signature = Buffer.from(proof[this.proofSignatureKey], "base64");
        signatureArray.push(signature);

        // Canonicalize proof: get N-Quads from JSON-LD
        const proofStatements: Statement[] = await suite.createVerifyProofData(
          proof,
          {
            documentLoader,
            expansionMap,
            compactProof: !skipProofCompaction
          }
        );

        // Concat proof and document to get terms to be signed
        const terms = proofStatements
          .concat(documentStatements)
          .flatMap((item: Statement) => item.toTerms());
        termsArray.push(
          terms.map((term: string) => new Uint8Array(Buffer.from(term)))
        );

        // Prepare anonymizedRevealedStatements: N-Quads revealed statements to be verified by verifier
        // where each specified URI and bnid is replaced by anonymous ID, i.e., urn:anon:<UUIDv4>
        const revealedStatements = await this.createVerifyDocumentData(
          revealedDocument,
          {
            suite,
            documentLoader,
            expansionMap,
            skipProofCompaction
          }
        );
        revealedStatementsArray.push(revealedStatements);

        // Calculate revealed statement indicies
        //   to be embedded in the derived proof to be passed to the Verifier
        const revealedProofStatementIndicies = Array.from(
          Array(proofStatements.length).keys()
        );
        const revealedStatementIndicies = revealedProofStatementIndicies.concat(
          this.getIndicies(
            anonymizedStatements,
            revealedStatements,
            proofStatements.length
          )
          );
        revealedStatementIndiciesArray.push(revealedStatementIndicies);

        // Calculate revealed term indicies
        //   to be input to blsCreateProof to generate zkproof
        const revealedTermIndicies = this.statementIndiciesToTermIndicies(
          revealedStatementIndicies
        );
        revealedTermIndiciesArray.push(revealedTermIndicies);

        // Push each term index of hidden URIs that are not removed by revealing process (JSON-LD framing)
        // to equivalence class
        proofStatements
          .concat(skolemizedStatements)
          .flatMap((item: Statement) => item.toTerms())
          .forEach((term, termIndex) => {
            if (equivs.has(term) && revealedTermIndicies.includes(termIndex)) {
              const e = equivs.get(term) as [string, [number, number][]];
              e[1].push([proofIndex + proofIndexOffset[docIndex], termIndex]);
            }
          });

        // Fetch the verification method
        const verificationMethod = await this.getVerificationMethod({
          proof,
          document,
          documentLoader,
          expansionMap
        });

        // Construct a key pair class from the returned verification method
        const issuerPublicKey = verificationMethod.publicKeyJwk
          ? await this.LDKeyClass.fromJwk(verificationMethod)
          : await this.LDKeyClass.from(verificationMethod);
        issuerPublicKeyArray.push(issuerPublicKey.publicKeyBuffer);

        // Initialize the derived proof
        let derivedProof;
        if (this.proof) {
          // use proof JSON-LD document passed to API
          derivedProof = await jsonld.compact(
            this.proof,
            SECURITY_CONTEXT_URLS,
            {
              documentLoader,
              expansionMap,
              compactToRelative: false
            }
          );
        } else {
          // Create proof JSON-LD document
          derivedProof = { "@context": SECURITY_CONTEXT_URLS };
        }
        // Ensure proof type is set
        derivedProof.type = this.type;
        // Set the relevant proof elements on the derived proof from the input proof
        derivedProof.verificationMethod = proof.verificationMethod;
        derivedProof.proofPurpose = proof.proofPurpose;
        derivedProof.created = proof.created;
        // Set the nonce on the derived proof
        derivedProof.nonce = Buffer.from(nonce).toString("base64");
        // Embed the revealed statement indicies into the head of proofValue
        derivedProof.proofValue =
          Buffer.from(JSON.stringify(revealedStatementIndicies)).toString(
            "base64"
          ) + ".";
        derivedProofs.push(derivedProof);

        proofIndex++;
      }

      docIndex++;
    }

    const equivsArray: [number, number][][] = [...equivs.values()].map(
      (v) => v[1]
    );

    // merge revealed statements into nonce (should be separated as claims?)
    const revealedStatementsByte = this.statementToUint8(
      revealedStatementsArray
    );
    const mergedNonce = new Uint8Array(
      nonce.length + revealedStatementsByte.length
    );
    mergedNonce.set(nonce);
    mergedNonce.set(revealedStatementsByte, nonce.length);

    // Compute the proof
    const derivedProofValues = await blsCreateProofMulti({
      signature: signatureArray.map((signature) => new Uint8Array(signature)),
      publicKey: issuerPublicKeyArray.map(
        (issuerPublicKey: Buffer) => new Uint8Array(issuerPublicKey)
      ),
      messages: termsArray,
      nonce: mergedNonce,
      revealed: revealedTermIndiciesArray,
      equivs: equivsArray
    });

    // Set the proof value on the derived proof
    const results = [];
    for (const numberOfProof of numberOfProofs) {
      const revealedDocument = revealedDocuments.shift();
      const derivedProofsPerDoc = [];

      for (let _ = 0; _ < numberOfProof; _++) {
        const derivedProof = derivedProofs.shift();
        const derivedProofValue = derivedProofValues.shift();
        if (!derivedProofValue) {
          throw new Error(
            "invalid proofValue generated by blsCreateProofMulti"
          );
        }
        derivedProof.proofValue +=
          Buffer.from(derivedProofValue).toString("base64");
        derivedProofsPerDoc.push(derivedProof);
      }

      results.push({
        document: revealedDocument,
        proof:
          derivedProofsPerDoc.length === 1
            ? derivedProofsPerDoc[0]
            : derivedProofsPerDoc
      });
    }

    return results;
  }

  /**
   * @param options {object} options for verifying the proof.
   *
   * @returns {Promise<{object}>} Resolves with the verification result.
   */
  async verifyProof(options: VerifyProofOptions): Promise<VerifyProofResult> {
    const { document, documentLoader, expansionMap, purpose, proof } = options;

    const result = await this.verifyProofMulti({
      inputDocuments: [
        {
          document,
          proof
        }
      ],
      documentLoader,
      expansionMap,
      purpose
    });

    if (result.results) {
      return result.results[0];
    } else {
      return { verified: result.verified, error: result.error };
    }
  }

  /**
   * @param options {object} options for verifying the proof.
   *
   * @returns {Promise<{object}>} Resolves with the verification result.
   */
  async verifyProofMulti(
    options: VerifyProofMultiOptions
  ): Promise<VerifyProofMultiResult> {
    const { inputDocuments, documentLoader, expansionMap, purpose } = options;

    const messagesArray: Uint8Array[][] = [];
    const proofArray: Uint8Array[] = [];
    const issuerPublicKeyArray: Uint8Array[] = [];
    const equivs: Map<string, [number, number][]> = new Map();
    const revealedStatementsArray: Statement[][] = [];
    const revealedTermIndiciesArray: number[][] = [];

    const anonymizer = new URIAnonymizer();

    const numberOfProofs: number[] = inputDocuments.map(
      ({ proof: givenProof }) =>
        Array.isArray(givenProof) ? givenProof.length : 1
    );
    const proofIndexOffset: number[] = numberOfProofs.map((_, i) =>
      numberOfProofs.slice(0, i).reduce((a, b) => a + b, 0)
    );

    let previous_nonce: string | undefined;

    try {
      let docIndex = 0;
      for (const { document, proof: givenProof } of inputDocuments) {
        // make array from (array | object)
        const proofs = Array.isArray(givenProof) ? givenProof : [givenProof];

        // Empty proofs should be rejected
        if (proofs.length === 0) {
          throw new Error(
            "documents to be verified must have at least one proof"
          );
        }

        // Canonicalize document: get N-Quads from JSON-LD
        const revealedStatements: Statement[] =
          await this.createVerifyDocumentData(document, {
            documentLoader,
            expansionMap
          });

        // Process multiple proofs in an input document
        let proofIndex = 0;
        for (const proof of proofs) {
          // keep document N-Quads statements per proof to calculate challenge hash later
          revealedStatementsArray.push(revealedStatements);

          if (previous_nonce && proof.nonce !== previous_nonce) {
            throw new Error("all of the nonces must have the same values");
          }
          previous_nonce = proof.nonce;

          // Extract revealed indicies and zkproof from proofValue
          const [revealedStatementIndiciesEncoded, proofValue] =
            proof.proofValue.split(".");
          const revealedStatementIndicies: number[] = JSON.parse(
            Buffer.from(revealedStatementIndiciesEncoded, "base64").toString()
          );

          proofArray.push(new Uint8Array(Buffer.from(proofValue, "base64")));

          // Revert proof.type from BbsTermwiseSignatureProof2021 to BbsTermwiseSignature2021 for verification
          proof.type = this.mappedDerivedProofType;

          // Canonicalize proof: get N-Quads from JSON-LD
          const proofStatements: Statement[] = await this.createVerifyProofData(
            proof,
            {
              documentLoader,
              expansionMap
            }
          );

          // obtain termwise indicies
          const revealedTermIndicies = this.statementIndiciesToTermIndicies(
            revealedStatementIndicies
          ).sort((a, b) => a - b);
          revealedTermIndiciesArray.push(revealedTermIndicies);

          // Reorder statements
          const statements = proofStatements.concat(revealedStatements);
          const reorderedStatements = revealedStatementIndicies
            .map<[number, Statement]>((termIndex, origIndex) => [
              termIndex,
              statements[origIndex]
            ])
            .sort(([termIndexA], [termIndexB]) => termIndexA - termIndexB)
            .map(([, statement]) => statement);

          // concat proof and document to be verified
          const terms = reorderedStatements.flatMap((item: Statement) =>
            item.toTerms()
          );

          messagesArray.push(
            terms.map((term: string) => new Uint8Array(Buffer.from(term)))
          );

          // extract blinding indicies from anonIDs
          terms.forEach((term, termIndex) => {
            const found = anonymizer.extractAnonID(term);
            if (found !== null) {
              if (equivs.has(found)) {
                equivs
                  .get(found)
                  ?.push([
                    proofIndex + proofIndexOffset[docIndex],
                    revealedTermIndicies[termIndex]
                  ]);
              } else {
                equivs.set(found, [
                  [
                    proofIndex + proofIndexOffset[docIndex],
                    revealedTermIndicies[termIndex]
                  ]
                ]);
              }
            }
          });

          // Fetch the verification method
          const verificationMethod = await this.getVerificationMethod({
            proof,
            document,
            documentLoader,
            expansionMap
          });

          // Ensure proof was performed for a valid purpose
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

          // Construct a key pair class from the returned verification method
          const key = verificationMethod.publicKeyJwk
            ? await this.LDKeyClass.fromJwk(verificationMethod)
            : await this.LDKeyClass.from(verificationMethod);

          issuerPublicKeyArray.push(new Uint8Array(key.publicKeyBuffer));

          proofIndex++;
        }

        docIndex++;
      }

      const equivsArray: [number, number][][] = [...equivs.entries()]
        .sort()
        .map((e) => e[1]);

      // merge revealed statements into nonce (should be separated as claims?)
      const revealedStatementsByte = this.statementToUint8(
        revealedStatementsArray
      );
      const nonce = new Uint8Array(
        Buffer.from(previous_nonce as string, "base64")
      );
      const mergedNonce = new Uint8Array(
        nonce.length + revealedStatementsByte.length
      );
      mergedNonce.set(nonce);
      mergedNonce.set(revealedStatementsByte, nonce.length);

      // Verify the proof
      const verified = await blsVerifyProofMulti({
        proof: proofArray,
        publicKey: issuerPublicKeyArray,
        messages: messagesArray,
        nonce: mergedNonce,
        revealed: revealedTermIndiciesArray,
        equivs: equivsArray
      });

      return verified;
    } catch (error: any) {
      return { verified: false, error };
    }
  }

  static proofType = [
    "BbsTermwiseSignatureProof2021",
    "https://www.zkp-ld.org/security#BbsTermwiseSignatureProof2021"
  ];

  static supportedDerivedProofType = [
    "BbsTermwiseSignature2021",
    "https://www.zkp-ld.org/security#BbsTermwiseSignature2021"
  ];
}
