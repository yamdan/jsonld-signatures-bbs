import jsigs from "jsonld-signatures";

import {
  exampleBls12381KeyPair,
  exampleBls12381KeyPairJwk,
  testDocument,
  testSignedDocument,
  customLoader,
  testVcDocument,
  testVcDocumentJwk,
  testSignedVcDocument,
  testSignedVcDocumentJwk,
  testSignedDocumentMultiProofs,
  testNestedVcDocument,
  testSignedNestedVcDocument
} from "./__fixtures__";
import { Bls12381G2KeyPair, BbsTermwiseSignature2021 } from "../src/index";

const key = new Bls12381G2KeyPair(exampleBls12381KeyPair);
const jwkey = new Bls12381G2KeyPair(exampleBls12381KeyPairJwk);

describe("BbsTermwiseSignature2021", () => {
  it("should sign with jsigs", async () => {
    const signed = await jsigs.sign(testDocument, {
      suite: new BbsTermwiseSignature2021({ key }),
      purpose: new jsigs.purposes.AssertionProofPurpose(),
      documentLoader: customLoader
    });
    expect(signed).toBeDefined();
  });

  it("should verify with jsigs", async () => {
    const verificationResult = await jsigs.verify(testSignedDocument, {
      suite: new BbsTermwiseSignature2021(),
      purpose: new jsigs.purposes.AssertionProofPurpose(),
      documentLoader: customLoader
    });

    expect(verificationResult).toBeDefined();
    expect(verificationResult.verified).toBeTruthy();
  });

  it("should not verify bad sig with jsigs", async () => {
    const testBadSignedDocument = {
      ...testSignedDocument,
      proof: {
        ...testSignedDocument.proof,
        proofValue: "BAD" + testSignedDocument.proof.proofValue // bad proof
      }
    };
    const verificationResult = await jsigs.verify(testBadSignedDocument, {
      suite: new BbsTermwiseSignature2021(),
      purpose: new jsigs.purposes.AssertionProofPurpose(),
      documentLoader: customLoader
    });
    expect(verificationResult).toBeDefined();
    expect(verificationResult.verified).toBeFalsy();
    expect(verificationResult.error.errors[0]).toHaveProperty("name", "Error");
    expect(verificationResult.error.errors[0]).toHaveProperty(
      "message",
      "Invalid signature."
    );
  });

  it("should not verify bad sig with incompatible suite with jsigs", async () => {
    const testBadSignedDocumentWithIncompatibleSuite = {
      ...testSignedDocument,
      proof: {
        ...testSignedDocument.proof,
        type: "IncompatibleSignature9999" // incompatible suite
      }
    };
    const verificationResult = await jsigs.verify(
      testBadSignedDocumentWithIncompatibleSuite,
      {
        suite: new BbsTermwiseSignature2021(),
        purpose: new jsigs.purposes.AssertionProofPurpose(),
        documentLoader: customLoader
      }
    );
    expect(verificationResult).toBeDefined();
    expect(verificationResult.verified).toBeFalsy();
    expect(verificationResult.error.errors[0]).toHaveProperty(
      "name",
      "NotFoundError"
    );
    expect(verificationResult.error.errors[0]).toHaveProperty(
      "message",
      "Did not verify any proofs; insufficient proofs matched the acceptable suite(s) and required purpose(s)."
    );
  });

  it("should not verify with additional unsigned information with jsigs", async () => {
    const modifiedDocument = {
      ...testSignedDocument,
      unsignedClaim: "oops"
    };

    const verificationResult = await jsigs.verify(modifiedDocument, {
      suite: new BbsTermwiseSignature2021(),
      purpose: new jsigs.purposes.AssertionProofPurpose(),
      documentLoader: customLoader
    });
    expect(verificationResult).toBeDefined();
    expect(verificationResult.verified).toBeFalsy();
    expect(verificationResult.error.errors[0]).toHaveProperty("name", "Error");
    expect(verificationResult.error.errors[0]).toHaveProperty(
      "message",
      "Invalid signature."
    );
  });

  it("should not verify with modified statement", async () => {
    const modifiedDocument = {
      ...testSignedDocument,
      email: "someOtherEmail@example.com"
    };

    const verificationResult = await jsigs.verify(modifiedDocument, {
      suite: new BbsTermwiseSignature2021(),
      purpose: new jsigs.purposes.AssertionProofPurpose(),
      documentLoader: customLoader
    });
    expect(verificationResult).toBeDefined();
    expect(verificationResult.verified).toBeFalsy();
    expect(verificationResult.error.errors[0]).toHaveProperty("name", "Error");
    expect(verificationResult.error.errors[0]).toHaveProperty(
      "message",
      "Invalid signature."
    );
  });

  it("should sign verifiable credential with jsigs", async () => {
    const signed = await jsigs.sign(testVcDocument, {
      suite: new BbsTermwiseSignature2021({ key }),
      purpose: new jsigs.purposes.AssertionProofPurpose(),
      documentLoader: customLoader
    });
    expect(signed).toBeDefined();
  });

  it("should verify verifiable credential with jsigs", async () => {
    const verificationResult = await jsigs.verify(testSignedVcDocument, {
      suite: new BbsTermwiseSignature2021(),
      purpose: new jsigs.purposes.AssertionProofPurpose(),
      documentLoader: customLoader
    });
    expect(verificationResult).toBeDefined();
    expect(verificationResult.verified).toBeTruthy();
  });

  it("should sign verifiable credential with JWK and jsigs", async () => {
    const signed = await jsigs.sign(testVcDocumentJwk, {
      suite: new BbsTermwiseSignature2021({ key: jwkey }),
      purpose: new jsigs.purposes.AssertionProofPurpose(),
      documentLoader: customLoader
    });
    expect(signed).toBeDefined();
  });

  it("should verify verifiable credential with JWK and jsigs", async () => {
    const verificationResult = await jsigs.verify(testSignedVcDocumentJwk, {
      suite: new BbsTermwiseSignature2021(),
      purpose: new jsigs.purposes.AssertionProofPurpose(),
      documentLoader: customLoader
    });
    expect(verificationResult).toBeDefined();
    expect(verificationResult.verified).toBeTruthy();
  });

  it("should verify document with multiple proofs", async () => {
    const verificationResult = await jsigs.verify(
      testSignedDocumentMultiProofs,
      {
        suite: new BbsTermwiseSignature2021(),
        purpose: new jsigs.purposes.AssertionProofPurpose(),
        documentLoader: customLoader
      }
    );
    expect(verificationResult).toBeDefined();
    expect(verificationResult.verified).toBeTruthy();
  });

  it("should not verify document with multiple proofs all of which is modified", async () => {
    const testSignedDocumentMultiBadProofs = {
      ...testSignedDocumentMultiProofs,
      proof: [
        {
          ...testSignedDocumentMultiProofs.proof[0],
          proofValue: "BAD" + testSignedDocumentMultiProofs.proof[0].proofValue // bad proof
        },
        {
          ...testSignedDocumentMultiProofs.proof[1],
          proofValue: "BAD" + testSignedDocumentMultiProofs.proof[1].proofValue // bad proof
        }
      ]
    };

    const verificationResult = await jsigs.verify(
      testSignedDocumentMultiBadProofs,
      {
        suite: new BbsTermwiseSignature2021(),
        purpose: new jsigs.purposes.AssertionProofPurpose(),
        documentLoader: customLoader
      }
    );
    expect(verificationResult).toBeDefined();
    expect(verificationResult.verified).toBeFalsy();
    expect(verificationResult.error.errors[0]).toHaveProperty("name", "Error");
    expect(verificationResult.error.errors[0]).toHaveProperty(
      "message",
      "Invalid signature."
    );
    expect(verificationResult.error.errors[1]).toHaveProperty("name", "Error");
    expect(verificationResult.error.errors[1]).toHaveProperty(
      "message",
      "Invalid signature."
    );
  });

  it.skip("should not verify document with multiple proofs all but one of which is modified", async () => {
    // Temporarily Skipped:
    // While this looks like an unexpected behaviour for me, it is accepted by `jsonld-signatures`.
    // See https://github.com/yamdan/jsonld-signatures-bbs/issues/2

    const testSignedDocumentMultiBadProofs = {
      ...testSignedDocumentMultiProofs,
      proof: [
        {
          ...testSignedDocumentMultiProofs.proof[0]
        },
        {
          ...testSignedDocumentMultiProofs.proof[1],
          proofValue: "BAD" + testSignedDocumentMultiProofs.proof[1].proofValue // bad proof
        }
      ]
    };

    const verificationResult = await jsigs.verify(
      testSignedDocumentMultiBadProofs,
      {
        suite: new BbsTermwiseSignature2021(),
        purpose: new jsigs.purposes.AssertionProofPurpose(),
        documentLoader: customLoader
      }
    );
    expect(verificationResult).toBeDefined();
    expect(verificationResult.verified).toBeFalsy();
    expect(verificationResult.error.errors[0]).toHaveProperty("name", "Error");
    expect(verificationResult.error.errors[0]).toHaveProperty(
      "message",
      "Invalid signature."
    );
    expect(verificationResult.error.errors[1]).toHaveProperty("name", "Error");
    expect(verificationResult.error.errors[1]).toHaveProperty(
      "message",
      "Invalid signature."
    );
  });

  it("should sign nested verifiable credential with jsigs", async () => {
    const signed = await jsigs.sign(testNestedVcDocument, {
      suite: new BbsTermwiseSignature2021({ key }),
      purpose: new jsigs.purposes.AssertionProofPurpose(),
      documentLoader: customLoader
    });
    expect(signed).toBeDefined();
  });

  it("should verify nested verifiable credential with jsigs", async () => {
    const verificationResult = await jsigs.verify(testSignedNestedVcDocument, {
      suite: new BbsTermwiseSignature2021(),
      purpose: new jsigs.purposes.AssertionProofPurpose(),
      documentLoader: customLoader
    });

    expect(verificationResult).toBeDefined();
    expect(verificationResult.verified).toBeTruthy();
  });
});
