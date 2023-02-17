/* eslint-disable @typescript-eslint/no-explicit-any */
import jsonld from "jsonld";
import { suites } from "jsonld-signatures";
import { Bls12381G2KeyPair } from "@zkp-ld/bls12381-key-pair";

import {
  SignatureSuiteOptions,
  CreateProofOptions,
  CanonizeOptions,
  CreateVerifyDataOptions,
  VerifyProofOptions,
  VerifySignatureOptions,
  SuiteSignOptions,
  DidDocumentPublicKey
} from "./types";
import { w3cDate, SECURITY_CONTEXT_URLS } from "./utilities";
import { Statement } from "./Statement";

export class BbsTermwiseSignature2021 extends suites.LinkedDataProof {
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
      type: "BbsTermwiseSignature2021"
    });

    this.proof = {
      "@context": ["https://zkp-ld.org/bbs-termwise-2021.jsonld"],
      type: "BbsTermwiseSignature2021"
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
    this.Statement = Statement;
  }

  // ported from
  // https://github.com/transmute-industries/verifiable-data/blob/main/packages/bbs-bls12381-signature-2020/src/BbsBlsSignature2020.ts
  ensureSuiteContext({ document }: any): void {
    const contextUrl = "https://zkp-ld.org/bbs-termwise-2021.jsonld";
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

  /**
   * @param options {CreateProofOptions} options for creating the proof
   *
   * @returns {Promise<object>} Resolves with the created proof object.
   */
  // eslint-disable-next-line @typescript-eslint/ban-types
  async createProof(options: CreateProofOptions): Promise<object> {
    const { document, purpose, documentLoader, compactProof } = options;

    let proof;
    if (this.proof) {
      // use proof JSON-LD document passed to API
      proof = await jsonld.compact(this.proof, SECURITY_CONTEXT_URLS, {
        documentLoader,
        compactToRelative: false
      });
    } else {
      // create proof JSON-LD document
      proof = { "@context": SECURITY_CONTEXT_URLS };
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
    // SECURITY_CONTEXT_URLS `@context` -- therefore the `purpose` must
    // ensure any added fields are also represented in that same `@context`
    proof = await purpose.update(proof, {
      document,
      suite: this,
      documentLoader
    });

    // create data to sign
    const verifyData = (
      await this.createVerifyData({
        document,
        proof,
        documentLoader,
        compactProof
      })
    ).flatMap((statement) => statement.serialize());

    // sign data
    proof = await this.sign({
      verifyData,
      document,
      proof,
      documentLoader
    });

    return proof;
  }

  /**
   * @param options {object} options for verifying the proof.
   *
   * @returns {Promise<{object}>} Resolves with the verification result.
   */
  // eslint-disable-next-line @typescript-eslint/ban-types
  async verifyProof(options: VerifyProofOptions): Promise<object> {
    const { proof, document, documentLoader, purpose } = options;

    try {
      // create data to verify
      const verifyData = (
        await this.createVerifyData({
          document,
          proof,
          documentLoader,
          compactProof: false
        })
      ).flatMap((statement) => statement.serialize());

      // fetch verification method
      const verificationMethod = await this.getVerificationMethod({
        proof,
        document,
        documentLoader
      });

      // verify signature on data
      const verified = await this.verifySignature({
        verifyData,
        verificationMethod,
        document,
        proof,
        documentLoader
      });
      if (!verified) {
        throw new Error("Invalid signature.");
      }

      // ensure proof was performed for a valid purpose
      const { valid, error } = await purpose.validate(proof, {
        document,
        suite: this,
        verificationMethod,
        documentLoader
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
    const { documentLoader, skipExpansion } = options;
    return jsonld.canonize(input, {
      algorithm: "URDNA2015",
      format: "application/n-quads",
      documentLoader,
      skipExpansion,
      useNative: this.useNativeCanonize
    });
  }

  async canonizeProof(proof: any, options: CanonizeOptions): Promise<string> {
    const { documentLoader } = options;
    proof = { ...proof };
    delete proof[this.proofSignatureKey];
    return this.canonize(proof, {
      documentLoader,
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
    const { proof, document, documentLoader } = options;

    const proofStatements = await this.createVerifyProofData(proof, {
      documentLoader
    });
    const documentStatements = await this.createVerifyDocumentData(document, {
      documentLoader
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
      .map((s: string) => new this.Statement(s));
  }

  /**
   * @param proof to canonicalize
   * @param options to create verify data
   *
   * @returns {Promise<Statement[]>}.
   */
  async createVerifyProofData(
    proof: any,
    { documentLoader }: any
  ): Promise<Statement[]> {
    const c14nProofOptions = await this.canonizeProof(proof, {
      documentLoader
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
    { documentLoader }: any
  ): Promise<Statement[]> {
    const c14nDocument = await this.canonize(document, {
      documentLoader
    });

    return this.getStatements(c14nDocument);
  }

  /**
   * @param document {object} to be signed.
   * @param proof {object}
   * @param documentLoader {function}
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
   * @param options {SuiteSignOptions} Options for signing.
   *
   * @returns {Promise<{object}>} the proof containing the signature value.
   */
  // eslint-disable-next-line @typescript-eslint/ban-types
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
      // Construct a key pair class from the returned verification method
      const key = verificationMethod.publicKeyJwk
        ? await this.LDKeyClass.fromJwk(verificationMethod)
        : await this.LDKeyClass.from(verificationMethod);
      verifier = key.verifier(key, this.alg, this.type);
    }

    return await verifier.verify({
      data: verifyData,
      signature: new Uint8Array(
        Buffer.from(proof[this.proofSignatureKey] as string, "base64")
      )
    });
  }

  static proofType = [
    "BbsTermwiseSignature2021",
    "https://zkp-ld.org/security#BbsTermwiseSignature2021"
  ];
}
