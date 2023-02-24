import jsigs from "jsonld-signatures";

import {
  exampleBls12381KeyPair,
  testRevealDocument,
  testSignedDocument,
  customLoader,
  testSignedVcDocument,
  testRevealVcDocument,
  testRevealAllVcDocument,
  testRevealAllDocument,
  testSignedNestedVcDocument,
  testNestedRevealFullDocument,
  testNestedRevealDocument,
  testRevealVcDocumentInvalid,
  testRevealDocumentWithUnknownAttributes
} from "./__fixtures__";
import {
  Bls12381G2KeyPair,
  BbsTermwiseSignatureProof2021,
  BbsTermwiseSignature2021
} from "../src/index";
import { getProofs } from "../src/utilities";

const key = new Bls12381G2KeyPair(exampleBls12381KeyPair);

describe("BbsTermwiseSignatureProof2021", () => {
  it("should derive and verify proof revealing all statements", async () => {
    const suite = new BbsTermwiseSignatureProof2021({
      useNativeCanonize: false,
      key
    });

    // holder
    const { proofs, document } = await getProofs({
      document: testSignedDocument,
      proofType: BbsTermwiseSignatureProof2021.supportedDerivedProofType,
      documentLoader: customLoader
    });
    const derivedProof: any = await suite.deriveProof({
      document,
      proof: proofs,
      revealDocument: testRevealAllDocument, // fully revealing
      documentLoader: customLoader
    });
    expect(derivedProof).toBeDefined();
    const derived = { ...derivedProof.document, proof: derivedProof.proof };

    // verifier
    const { proofs: derivedProofs, document: derivedDocument } =
      await getProofs({
        document: derived,
        proofType: BbsTermwiseSignatureProof2021.proofType,
        documentLoader: customLoader
      });
    const result = await suite.verifyProof({
      document: derivedDocument,
      proof: derivedProofs,
      documentLoader: customLoader,
      purpose: new jsigs.purposes.AssertionProofPurpose()
    });
    expect(result.verified).toBeTruthy();
  });

  it("should derive and verify proof", async () => {
    const suite = new BbsTermwiseSignatureProof2021({
      useNativeCanonize: false,
      key
    });

    // holder
    const { proofs, document } = await getProofs({
      document: testSignedDocument,
      proofType: BbsTermwiseSignatureProof2021.supportedDerivedProofType,
      documentLoader: customLoader
    });
    const derivedProof: any = await suite.deriveProof({
      document,
      proof: proofs,
      revealDocument: testRevealDocument, // partially revealing
      documentLoader: customLoader
    });
    expect(derivedProof).toBeDefined();
    const derived = { ...derivedProof.document, proof: derivedProof.proof };

    // verifier
    const { proofs: derivedProofs, document: derivedDocument } =
      await getProofs({
        document: derived,
        proofType: BbsTermwiseSignatureProof2021.proofType,
        documentLoader: customLoader
      });
    const result = await suite.verifyProof({
      document: derivedDocument,
      proof: derivedProofs,
      documentLoader: customLoader,
      purpose: new jsigs.purposes.AssertionProofPurpose()
    });
    expect(result.verified).toBeTruthy();
  });

  it("should derive and verify proof with reveal document including unknown attributes", async () => {
    const suite = new BbsTermwiseSignatureProof2021({
      useNativeCanonize: false,
      key
    });

    // holder
    const { proofs, document } = await getProofs({
      document: testSignedDocument,
      proofType: BbsTermwiseSignatureProof2021.supportedDerivedProofType,
      documentLoader: customLoader
    });
    const derivedProof: any = await suite.deriveProof({
      document,
      proof: proofs,
      revealDocument: testRevealDocumentWithUnknownAttributes, // reveal doc including unknown attributes
      documentLoader: customLoader
    });
    expect(derivedProof).toBeDefined();
    const derived = { ...derivedProof.document, proof: derivedProof.proof };

    // verifier
    const { proofs: derivedProofs, document: derivedDocument } =
      await getProofs({
        document: derived,
        proofType: BbsTermwiseSignatureProof2021.proofType,
        documentLoader: customLoader
      });
    const result = await suite.verifyProof({
      document: derivedDocument,
      proof: derivedProofs,
      documentLoader: customLoader,
      purpose: new jsigs.purposes.AssertionProofPurpose()
    });
    expect(result.verified).toBeTruthy();
  });

  it("should not verify derived document without proof", async () => {
    const suite = new BbsTermwiseSignatureProof2021({
      useNativeCanonize: false,
      key
    });

    // holder
    const { proofs, document } = await getProofs({
      document: testSignedDocument,
      proofType: BbsTermwiseSignatureProof2021.supportedDerivedProofType,
      documentLoader: customLoader
    });
    const derivedProof: any = await suite.deriveProof({
      document,
      proof: proofs,
      revealDocument: testRevealDocument,
      documentLoader: customLoader
    });
    expect(derivedProof).toBeDefined();
    const derived = { ...derivedProof.document, proof: derivedProof.proof };

    // verifier
    const { proofs: derivedProofs, document: derivedDocument } =
      await getProofs({
        document: derived,
        proofType: BbsTermwiseSignatureProof2021.proofType,
        documentLoader: customLoader
      });
    const result = await suite.verifyProof({
      document: derivedDocument,
      proof: [], // remove proof
      documentLoader: customLoader,
      purpose: new jsigs.purposes.AssertionProofPurpose()
    });
    expect(result.verified).toBeFalsy();
    expect(result.error).toHaveProperty("name", "Error");
    expect(result.error).toHaveProperty(
      "message",
      "documents to be verified must have at least one proof"
    );
  });

  it("should not verify modified proof with bad prefix", async () => {
    const suite = new BbsTermwiseSignatureProof2021({
      useNativeCanonize: false,
      key
    });

    // holder
    const { proofs, document } = await getProofs({
      document: testSignedDocument,
      proofType: BbsTermwiseSignatureProof2021.supportedDerivedProofType,
      documentLoader: customLoader
    });
    const derivedProof: any = await suite.deriveProof({
      document,
      proof: proofs,
      revealDocument: testRevealDocument,
      documentLoader: customLoader
    });
    expect(derivedProof).toBeDefined();
    const modifiedProof = {
      ...derivedProof.document,
      proof: {
        ...derivedProof.proof,
        proofValue: "BAD" + derivedProof.proof.proofValue // bad prefix
      }
    };

    // verifier
    const { proofs: derivedProofs, document: derivedDocument } =
      await getProofs({
        document: modifiedProof,
        proofType: BbsTermwiseSignatureProof2021.proofType,
        documentLoader: customLoader
      });
    const result = await suite.verifyProof({
      document: derivedDocument,
      proof: derivedProofs,
      documentLoader: customLoader,
      purpose: new jsigs.purposes.AssertionProofPurpose()
    });
    expect(result.verified).toBeFalsy();
    expect(result.error).toHaveProperty("name", "Error");
    expect(result.error).toHaveProperty("message", "invalid proofValue");
  });

  it.skip("should not verify modified proof with bad suffix", async () => {
    // Temporarily Skipped:
    // Any suffix added to Base64-encoded proofValue is currently just ignored
    // as long as it does not affect the result of `Buffer.from()`
    // ref: https://github.com/nodejs/node/issues/8569

    const suite = new BbsTermwiseSignatureProof2021({
      useNativeCanonize: false,
      key
    });

    // holder
    const { proofs, document } = await getProofs({
      document: testSignedDocument,
      proofType: BbsTermwiseSignatureProof2021.supportedDerivedProofType,
      documentLoader: customLoader
    });
    const derivedProof: any = await suite.deriveProof({
      document,
      proof: proofs,
      revealDocument: testRevealDocument,
      documentLoader: customLoader
    });
    expect(derivedProof).toBeDefined();
    const modifiedProof = {
      ...derivedProof.document,
      proof: {
        ...derivedProof.proof,
        proofValue: derivedProof.proof.proofValue + "=====" // bad suffix
      }
    };

    // verifier
    const { proofs: derivedProofs, document: derivedDocument } =
      await getProofs({
        document: modifiedProof,
        proofType: BbsTermwiseSignatureProof2021.proofType,
        documentLoader: customLoader
      });
    const result = await suite.verifyProof({
      document: derivedDocument,
      proof: derivedProofs,
      documentLoader: customLoader,
      purpose: new jsigs.purposes.AssertionProofPurpose()
    });
    expect(result.verified).toBeFalsy();
    expect(result.error).toHaveProperty("name", "Error");
    expect(result.error).toHaveProperty("message", "invalid proofValue");
  });

  it("should not verify partial derived proof with incompatible suite", async () => {
    const suite = new BbsTermwiseSignatureProof2021({
      useNativeCanonize: false,
      key
    });

    // holder
    const { proofs, document } = await getProofs({
      document: testSignedDocument,
      proofType: BbsTermwiseSignatureProof2021.supportedDerivedProofType,
      documentLoader: customLoader
    });

    let derivedProof: any = await suite.deriveProof({
      document,
      proof: proofs,
      revealDocument: testRevealDocument,
      documentLoader: customLoader
    });
    expect(derivedProof).toBeDefined();
    const modifiedProof = {
      ...derivedProof.document,
      proof: {
        ...derivedProof.proof,
        type: "IncompatibleSignatureProof9999" // incompatible suite
      }
    };

    // verifier
    const { proofs: derivedProofs, document: derivedDocument } =
      await getProofs({
        document: modifiedProof,
        proofType: BbsTermwiseSignatureProof2021.proofType,
        documentLoader: customLoader
      });
    const result = await suite.verifyProof({
      document: derivedDocument,
      proof: derivedProofs,
      documentLoader: customLoader,
      purpose: new jsigs.purposes.AssertionProofPurpose()
    });
    expect(result.verified).toBeFalsy();
    expect(result.error).toHaveProperty("name", "Error");
    expect(result.error).toHaveProperty(
      "message",
      "documents to be verified must have at least one proof"
    );
  });

  it("should not verify partial derived proof with incompatible suite (even if getProofs is not used)", async () => {
    const suite = new BbsTermwiseSignatureProof2021({
      useNativeCanonize: false,
      key
    });

    // holder
    const { proofs, document } = await getProofs({
      document: testSignedDocument,
      proofType: BbsTermwiseSignatureProof2021.supportedDerivedProofType,
      documentLoader: customLoader
    });

    let derivedProof: any = await suite.deriveProof({
      document,
      proof: proofs,
      revealDocument: testRevealDocument,
      documentLoader: customLoader
    });
    expect(derivedProof).toBeDefined();

    const modifiedProof = {
      ...derivedProof.document,
      proof: {
        ...derivedProof.proof,
        type: "IncompatibleSignatureProof9999" // incompatible suite
      }
    };

    // verifier
    const result = await suite.verifyProof({
      document: modifiedProof.document,
      proof: modifiedProof.proof,
      documentLoader: customLoader,
      purpose: new jsigs.purposes.AssertionProofPurpose()
    });
    expect(result.verified).toBeFalsy();
    expect(result.error).toHaveProperty("name", "TypeError");
    expect(result.error).toHaveProperty(
      "message",
      'incompatible proof type: expected proof types of ["BbsTermwiseSignatureProof2021","https://zkp-ld.org/security#BbsTermwiseSignatureProof2021"] received IncompatibleSignatureProof9999'
    );
  });

  it("should not derive proof with document featuring unsigned info", async () => {
    const suite = new BbsTermwiseSignatureProof2021();

    const input = {
      ...testSignedDocument,
      unsignedClaim: true
    };

    const { proofs, document } = await getProofs({
      document: input,
      proofType: BbsTermwiseSignature2021.proofType,
      documentLoader: customLoader
    });

    await expect(
      suite.deriveProof({
        document,
        proof: proofs,
        revealDocument: testRevealAllDocument,
        documentLoader: customLoader
      })
    ).rejects.toThrowError("Failed to create proof");
  });

  it("should not derive proof with document featuring modified info", async () => {
    const suite = new BbsTermwiseSignatureProof2021();

    const input = {
      ...testSignedDocument,
      email: "bad@example.com"
    };

    const { proofs, document } = await getProofs({
      document: input,
      proofType: BbsTermwiseSignature2021.proofType,
      documentLoader: customLoader
    });

    await expect(
      suite.deriveProof({
        document,
        proof: proofs,
        revealDocument: testRevealAllDocument,
        documentLoader: customLoader
      })
    ).rejects.toThrowError("Failed to create proof");
  });

  it("should not derive proof with document featuring missing info", async () => {
    const suite = new BbsTermwiseSignatureProof2021();

    type TestSignedDocumentType = {
      "@context": string[];
      "@type": string;
      firstName: string;
      lastName: string;
      jobTitle: string;
      telephone: string;
      email?: string;
      proof: {
        type: string;
        created: string;
        proofPurpose: string;
        proofValue: string;
        verificationMethod: string;
      };
    };

    const input: TestSignedDocumentType = {
      ...testSignedDocument
    };

    delete input.email;

    const { proofs, document } = await getProofs({
      document: input,
      proofType: BbsTermwiseSignature2021.proofType,
      documentLoader: customLoader
    });

    await expect(
      suite.deriveProof({
        document,
        proof: proofs,
        revealDocument: testRevealAllDocument,
        documentLoader: customLoader
      })
    ).rejects.toThrowError("Failed to create proof");
  });

  it("should derive and verify proof revealing all statements from vc", async () => {
    const suite = new BbsTermwiseSignatureProof2021({
      useNativeCanonize: false,
      key
    });

    // holder
    const { proofs, document } = await getProofs({
      document: testSignedVcDocument,
      proofType: BbsTermwiseSignatureProof2021.supportedDerivedProofType,
      documentLoader: customLoader
    });
    const derivedProof: any = await suite.deriveProof({
      document,
      proof: proofs,
      revealDocument: testRevealAllVcDocument, // fully revealing
      documentLoader: customLoader
    });
    expect(derivedProof).toBeDefined();
    const derived = { ...derivedProof.document, proof: derivedProof.proof };

    // verifier
    const { proofs: derivedProofs, document: derivedDocument } =
      await getProofs({
        document: derived,
        proofType: BbsTermwiseSignatureProof2021.proofType,
        documentLoader: customLoader
      });
    const result = await suite.verifyProof({
      document: derivedDocument,
      proof: derivedProofs,
      documentLoader: customLoader,
      purpose: new jsigs.purposes.AssertionProofPurpose()
    });
    expect(result.verified).toBeTruthy();
  });

  it("should derive and verify from vc", async () => {
    const suite = new BbsTermwiseSignatureProof2021({
      useNativeCanonize: false,
      key
    });

    // holder
    const { proofs, document } = await getProofs({
      document: testSignedVcDocument,
      proofType: BbsTermwiseSignatureProof2021.supportedDerivedProofType,
      documentLoader: customLoader
    });
    const derivedProof: any = await suite.deriveProof({
      document,
      proof: proofs,
      revealDocument: testRevealVcDocument, // partially revealing
      documentLoader: customLoader
    });
    expect(derivedProof).toBeDefined();
    const derived = { ...derivedProof.document, proof: derivedProof.proof };

    // verifier
    const { proofs: derivedProofs, document: derivedDocument } =
      await getProofs({
        document: derived,
        proofType: BbsTermwiseSignatureProof2021.proofType,
        documentLoader: customLoader
      });
    const result = await suite.verifyProof({
      document: derivedDocument,
      proof: derivedProofs,
      documentLoader: customLoader,
      purpose: new jsigs.purposes.AssertionProofPurpose()
    });
    expect(result.verified).toBeTruthy();
  });

  it("should not derive proof from vc with invalid reveal document", async () => {
    const suite = new BbsTermwiseSignatureProof2021({
      useNativeCanonize: false,
      key
    });

    const { proofs, document } = await getProofs({
      document: testSignedVcDocument,
      proofType: BbsTermwiseSignatureProof2021.supportedDerivedProofType,
      documentLoader: customLoader
    });
    await expect(
      suite.deriveProof({
        document,
        proof: proofs,
        revealDocument: testRevealVcDocumentInvalid, // invalid reveal document
        documentLoader: customLoader
      })
    ).rejects.toThrowError("Invalid JSON-LD syntax; invalid @id in frame.");
  });

  it("should derive and verify a fully revealed derived proof that uses nesting from a vc", async () => {
    const suite = new BbsTermwiseSignatureProof2021({
      useNativeCanonize: false,
      key
    });

    // holder
    const { proofs, document } = await getProofs({
      document: testSignedNestedVcDocument,
      proofType: BbsTermwiseSignatureProof2021.supportedDerivedProofType,
      documentLoader: customLoader
    });
    const derivedProof: any = await suite.deriveProof({
      document,
      proof: proofs,
      revealDocument: testNestedRevealFullDocument, // fully revealing
      documentLoader: customLoader
    });
    expect(derivedProof).toBeDefined();
    const derived = { ...derivedProof.document, proof: derivedProof.proof };

    // verifier
    const { proofs: derivedProofs, document: derivedDocument } =
      await getProofs({
        document: derived,
        proofType: BbsTermwiseSignatureProof2021.proofType,
        documentLoader: customLoader
      });
    const result = await suite.verifyProof({
      document: derivedDocument,
      proof: derivedProofs,
      documentLoader: customLoader,
      purpose: new jsigs.purposes.AssertionProofPurpose()
    });
    expect(result.verified).toBeTruthy();
  });

  it("should derive and verify a partially revealed derived proof that uses nesting from a vc", async () => {
    const suite = new BbsTermwiseSignatureProof2021({
      useNativeCanonize: false,
      key
    });

    // holder
    const { proofs, document } = await getProofs({
      document: testSignedNestedVcDocument,
      proofType: BbsTermwiseSignatureProof2021.supportedDerivedProofType,
      documentLoader: customLoader
    });
    const derivedProof: any = await suite.deriveProof({
      document,
      proof: proofs,
      revealDocument: testNestedRevealDocument, // partially revealing
      documentLoader: customLoader
    });
    expect(derivedProof).toBeDefined();
    const derived = { ...derivedProof.document, proof: derivedProof.proof };

    // verifier
    const { proofs: derivedProofs, document: derivedDocument } =
      await getProofs({
        document: derived,
        proofType: BbsTermwiseSignatureProof2021.proofType,
        documentLoader: customLoader
      });
    const result = await suite.verifyProof({
      document: derivedDocument,
      proof: derivedProofs,
      documentLoader: customLoader,
      purpose: new jsigs.purposes.AssertionProofPurpose()
    });
    expect(result.verified).toBeTruthy();
  });
});
