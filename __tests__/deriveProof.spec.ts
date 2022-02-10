import {
  testRevealDocument,
  testRevealAllDocument,
  testSignedDocument,
  customLoader,
  testSignedVcDocument,
  testRevealVcDocument,
  testSignedDocumentMultiProofs,
  testSignedDocumentMultiDifProofs,
  testSignedDocumentEd25519,
  testNestedRevealDocument,
  testNestedRevealFullDocument,
  testSignedNestedVcDocument,
  testSignedVcDocumentJwk,
  testRevealVcDocumentJwk
} from "./__fixtures__";

import { BbsTermwiseSignatureProof2021, deriveProof } from "../src/index";

import jsigs from "jsonld-signatures";

describe("BbsTermwiseSignatureProof2021", () => {
  it("should derive proof revealing all statements", async () => {
    const result = await deriveProof(
      testSignedDocument,
      testRevealAllDocument,
      {
        suite: new BbsTermwiseSignatureProof2021(),
        documentLoader: customLoader
      }
    );
    expect(result).toBeDefined();
  });

  it("should derive proof revealing partial statements", async () => {
    const result = await deriveProof(testSignedDocument, testRevealDocument, {
      suite: new BbsTermwiseSignatureProof2021(),
      documentLoader: customLoader
    });
    expect(result).toBeDefined();
  });

  it("should derive proof from vc", async () => {
    const result = await deriveProof(
      testSignedVcDocument,
      testRevealVcDocument,
      {
        suite: new BbsTermwiseSignatureProof2021(),
        documentLoader: customLoader
      }
    );
    expect(result).toBeDefined();
  });

  it("should derive proofs from a document featuring multiple supporting proofs", async () => {
    const result = await deriveProof(
      testSignedDocumentMultiProofs,
      testRevealDocument,
      {
        suite: new BbsTermwiseSignatureProof2021(),
        documentLoader: customLoader
      }
    );
    expect(result).toBeDefined();
    expect(result.proof.length).toBe(2);
  });

  it("should derive proofs from a document featuring multiple different proofs with at least 1 supporting proof", async () => {
    const result = await deriveProof(
      testSignedDocumentMultiDifProofs,
      testRevealDocument,
      {
        suite: new BbsTermwiseSignatureProof2021(),
        documentLoader: customLoader
      }
    );
    expect(result).toBeDefined();

    // this returns a document with only a single proof so it should be an object rather than an array
    expect(Array.isArray(result.proof)).toBe(false);
  });

  it.skip("should derive proofs from multiple proof documents and be able to verify them using jsonld-signatures library", async () => {
    // Note: verification of a derived proof **with multiple signatures**
    // is no longer consistent with jsigs.verify API.
    // The original jsigs.verify verifies each proof in a **mutually independent** fashion,
    // whereas our extension requires all the proofs to be verified **at the same time**
    // (in order to achieve ZKP generation and verification.)
    // Thus we gave up using jsigs.verify for derived proof verification
    // and just skip this test, which will be removed later.

    const result = await deriveProof(
      testSignedDocumentMultiProofs,
      testRevealDocument,
      {
        suite: new BbsTermwiseSignatureProof2021(),
        documentLoader: customLoader
      }
    );

    const derivedProofVerified = await jsigs.verify(result, {
      suite: new BbsTermwiseSignatureProof2021(),
      purpose: new jsigs.purposes.AssertionProofPurpose(),
      documentLoader: customLoader
    });

    expect(result).toBeDefined();
    expect(result.proof.length).toBe(2);
    expect(derivedProofVerified.verified).toBeTruthy();
  });

  it("should derive proof from a nested document with a nested frame with all properties revealed", async () => {
    const result = await deriveProof(
      testSignedNestedVcDocument,
      testNestedRevealFullDocument,
      {
        suite: new BbsTermwiseSignatureProof2021(),
        documentLoader: customLoader
      }
    );

    expect(result).toBeDefined();
    expect(result.credentialSubject.degree.type).toBeDefined();
    expect(result.credentialSubject.degree.name).toBeDefined();
  });

  it("should derive proof and verify using jsonld-signatures library", async () => {
    const derivedProof = await deriveProof(
      testSignedVcDocumentJwk,
      testRevealVcDocumentJwk,
      {
        suite: new BbsTermwiseSignatureProof2021(),
        documentLoader: customLoader
      }
    );

    // testing if derive result includes less fields
    expect(
      Object.keys(testSignedVcDocumentJwk.credentialSubject).length
    ).toEqual(12);
    expect(Object.keys(derivedProof.credentialSubject).length).toEqual(5);

    // verifying proof is valid
    const derivedProofVerified = await jsigs.verify(derivedProof, {
      suite: new BbsTermwiseSignatureProof2021(),
      purpose: new jsigs.purposes.AssertionProofPurpose(),
      documentLoader: customLoader
    });

    expect(derivedProofVerified.verified).toBeTruthy();
  });

  it("should derive proofs from a nested document with a nested frame with selectively revealed properties", async () => {
    const result = await deriveProof(
      testSignedNestedVcDocument,
      testNestedRevealDocument,
      {
        suite: new BbsTermwiseSignatureProof2021(),
        documentLoader: customLoader
      }
    );

    expect(result).toBeDefined();
    expect(result.credentialSubject.degree.name).toBeDefined();
  });

  it("should throw an error when proofDocument is the wrong type", async () => {
    await expect(
      deriveProof(
        [testSignedDocument, testSignedDocument], // array instead of object
        testRevealDocument,
        {
          suite: new BbsTermwiseSignatureProof2021(),
          documentLoader: customLoader
        }
      )
    ).rejects.toThrowError("proofDocument should be an object not an array.");
  });

  it("should throw an error when proofDocument doesn't include a compatible suite", async () => {
    await expect(
      deriveProof(testSignedDocumentEd25519, testRevealDocument, {
        suite: new BbsTermwiseSignatureProof2021(),
        documentLoader: customLoader
      })
    ).rejects.toThrowError(
      "There were not any proofs provided that can be used to derive a proof with this suite."
    );
  });
});
