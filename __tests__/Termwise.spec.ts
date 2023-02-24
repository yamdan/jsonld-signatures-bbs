import jsigs from "jsonld-signatures";

import {
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
  testSignedDocumentMultiProofs,
  testRevealDocument,
  customLoader
} from "./__fixtures__";

import {
  BbsTermwiseSignatureProof2021,
  BbsTermwiseSignature2021,
  Bls12381G2KeyPair,
  deriveProof,
  verifyProofMulti
} from "../src/index";

import {
  signDeriveMultiJSigLike,
  signDeriveVerifyMulti,
  signDeriveVerifyMultiJSigLike
} from "./utils";

const expKey1 = new Bls12381G2KeyPair(expExampleBls12381KeyPair);
const expKey2 = new Bls12381G2KeyPair(expExampleBls12381KeyPair2);
const expKey3 = new Bls12381G2KeyPair(expExampleBls12381KeyPair3);

describe("BbsTermwise2021 and BbsTermwiseSignature2021", () => {
  it("should sign and verify a VC, then derive and verify a proof from it", async () => {
    const vc = { ...expVCDocument };
    const hiddenUris = [
      "http://example.org/credentials/1234",
      "http://example.org/credentials/9876",
      "http://example.org/credentials/abcd",
      "did:example:holder1",
      "did:example:cityA"
    ];

    await signDeriveVerifyMulti(
      [{ vc, revealDocument: expRevealDocument, key: expKey1 }],
      hiddenUris,
      customLoader,
      BbsTermwiseSignature2021,
      BbsTermwiseSignatureProof2021
    );
  });

  it("should sign and verify multiple VCs, then derive and verify proofs from them", async () => {
    const vc = { ...expVCDocument };
    const vc2 = { ...expVCDocument2 };
    const vc3 = { ...expVCDocument3 };
    const hiddenUris = [
      "http://example.org/credentials/1234",
      "http://example.org/credentials/9876",
      "http://example.org/credentials/abcd",
      "did:example:holder1",
      "did:example:cityA"
    ];

    await signDeriveVerifyMulti(
      [
        { vc, revealDocument: expRevealDocument, key: expKey1 },
        { vc: vc2, revealDocument: expRevealDocument2, key: expKey2 },
        { vc: vc3, revealDocument: expRevealDocument3, key: expKey3 }
      ],
      hiddenUris,
      customLoader,
      BbsTermwiseSignature2021,
      BbsTermwiseSignatureProof2021
    );
  });

  it("should sign and verify a VC, then derive and verify a proof from it using jsonld-signature-like APIs", async () => {
    const vc = { ...expVCDocument };
    const hiddenUris = [
      "http://example.org/credentials/1234",
      "http://example.org/credentials/9876",
      "http://example.org/credentials/abcd",
      "did:example:holder1",
      "did:example:cityA"
    ];

    await signDeriveVerifyMultiJSigLike(
      [{ vc, revealDocument: expRevealDocument, key: expKey1 }],
      hiddenUris,
      customLoader,
      BbsTermwiseSignature2021,
      BbsTermwiseSignatureProof2021
    );
  });

  it("should sign and verify multiple VCs, then derive and verify proofs from them using jsonld-signature-like APIs", async () => {
    const vc = { ...expVCDocument };
    const vc2 = { ...expVCDocument2 };
    const vc3 = { ...expVCDocument3 };
    const hiddenUris = [
      "http://example.org/credentials/1234",
      "http://example.org/credentials/9876",
      "http://example.org/credentials/abcd",
      "did:example:holder1",
      "did:example:cityA"
    ];

    await signDeriveVerifyMultiJSigLike(
      [
        { vc, revealDocument: expRevealDocument, key: expKey1 },
        { vc: vc2, revealDocument: expRevealDocument2, key: expKey2 },
        { vc: vc3, revealDocument: expRevealDocument3, key: expKey3 }
      ],
      hiddenUris,
      customLoader,
      BbsTermwiseSignature2021,
      BbsTermwiseSignatureProof2021
    );
  });

  it("should verify derived proofs", async () => {
    const vc = { ...expVCDocument };
    const hiddenUris = [
      "http://example.org/credentials/1234",
      "did:example:holder1",
      "did:example:cityA"
    ];

    const derivedProofs = await signDeriveMultiJSigLike(
      [{ vc, revealDocument: expRevealDocument, key: expKey1 }],
      hiddenUris,
      customLoader,
      BbsTermwiseSignature2021,
      BbsTermwiseSignatureProof2021
    );

    const result = await verifyProofMulti(derivedProofs, {
      suite: new BbsTermwiseSignatureProof2021(),
      purpose: new jsigs.purposes.AssertionProofPurpose(),
      documentLoader: customLoader
    });
    expect(result.verified).toBeTruthy();
  });

  it("should not verify derived proofs where credentialSubject.type is edited", async () => {
    const vc = { ...expVCDocument };
    const hiddenUris = [
      "http://example.org/credentials/1234",
      "did:example:holder1",
      "did:example:cityA"
    ];

    const derivedProofs = await signDeriveMultiJSigLike(
      [{ vc, revealDocument: expRevealDocument, key: expKey1 }],
      hiddenUris,
      customLoader,
      BbsTermwiseSignature2021,
      BbsTermwiseSignatureProof2021
    );

    let modifiedProofs = [...derivedProofs];
    modifiedProofs[0].credentialSubject.type = "PersonXXX";

    const result = await verifyProofMulti(modifiedProofs, {
      suite: new BbsTermwiseSignatureProof2021(),
      purpose: new jsigs.purposes.AssertionProofPurpose(),
      documentLoader: customLoader
    });

    expect(result.verified).toBeFalsy();
  });

  it("should not verify derived proofs where anonymized credential.id is edited", async () => {
    const vc = { ...expVCDocument };
    const hiddenUris = [
      "http://example.org/credentials/1234",
      "did:example:holder1",
      "did:example:cityA"
    ];

    const derivedProofs = await signDeriveMultiJSigLike(
      [{ vc, revealDocument: expRevealDocument, key: expKey1 }],
      hiddenUris,
      customLoader,
      BbsTermwiseSignature2021,
      BbsTermwiseSignatureProof2021
    );

    let modifiedProofs = [...derivedProofs];
    modifiedProofs[0].id = "urn:anon:999";

    const result = await verifyProofMulti(modifiedProofs, {
      suite: new BbsTermwiseSignatureProof2021(),
      purpose: new jsigs.purposes.AssertionProofPurpose(),
      documentLoader: customLoader
    });

    expect(result.verified).toBeFalsy();
  });

  it("should not verify derived proofs where anonymized credentialSubject.id is edited", async () => {
    const vc = { ...expVCDocument };
    const hiddenUris = [
      "http://example.org/credentials/1234",
      "did:example:holder1",
      "did:example:cityA"
    ];

    const derivedProofs = await signDeriveMultiJSigLike(
      [{ vc, revealDocument: expRevealDocument, key: expKey1 }],
      hiddenUris,
      customLoader,
      BbsTermwiseSignature2021,
      BbsTermwiseSignatureProof2021
    );

    let modifiedProofs = [...derivedProofs];
    modifiedProofs[0].credentialSubject.id = "urn:anon:999";

    const result = await verifyProofMulti(modifiedProofs, {
      suite: new BbsTermwiseSignatureProof2021(),
      purpose: new jsigs.purposes.AssertionProofPurpose(),
      documentLoader: customLoader
    });

    expect(result.verified).toBeFalsy();
  });

  it("should not verify derived proofs where anonymized credentialSubject.*.id is edited", async () => {
    const vc = { ...expVCDocument };
    const hiddenUris = [
      "http://example.org/credentials/1234",
      "did:example:holder1",
      "did:example:cityA"
    ];

    const derivedProofs = await signDeriveMultiJSigLike(
      [{ vc, revealDocument: expRevealDocument, key: expKey1 }],
      hiddenUris,
      customLoader,
      BbsTermwiseSignature2021,
      BbsTermwiseSignatureProof2021
    );

    let modifiedProofs = [...derivedProofs];
    modifiedProofs[0].credentialSubject.homeLocation.id = "urn:anon:999";

    const result = await verifyProofMulti(modifiedProofs, {
      suite: new BbsTermwiseSignatureProof2021(),
      purpose: new jsigs.purposes.AssertionProofPurpose(),
      documentLoader: customLoader
    });

    expect(result.verified).toBeFalsy();
  });

  it("should not sign VC with invalid context", async () => {
    let vc = { ...expVCDocument };
    vc["@context"] = [...vc["@context"]];
    vc["@context"].push("https://dummy.example.org/");

    const sign = () =>
      jsigs.sign(vc, {
        suite: new BbsTermwiseSignature2021({ key: expKey1 }),
        purpose: new jsigs.purposes.AssertionProofPurpose(),
        documentLoader: customLoader
      });
    await expect(sign).rejects.toThrow();
  });

  it("should not be panicked due to Wasm error when modifying proofValue", async () => {
    const vc = { ...expVCDocument };
    const hiddenUris = [
      "http://example.org/credentials/1234",
      "did:example:holder1",
      "did:example:cityA"
    ];

    const derivedProofs = await signDeriveMultiJSigLike(
      [{ vc, revealDocument: expRevealDocument, key: expKey1 }],
      hiddenUris,
      customLoader,
      BbsTermwiseSignature2021,
      BbsTermwiseSignatureProof2021
    );

    // remove first byte from proofValue
    let modifiedProofs = [...derivedProofs];
    modifiedProofs[0].proof.proofValue =
      modifiedProofs[0].proof.proofValue.slice(1);

    const result = await verifyProofMulti(modifiedProofs, {
      suite: new BbsTermwiseSignatureProof2021(),
      purpose: new jsigs.purposes.AssertionProofPurpose(),
      documentLoader: customLoader
    });

    expect(result.verified).toBeFalsy();
  });

  it("should derive proofs from multiple proof documents and be able to verify them", async () => {
    const result = await deriveProof(
      testSignedDocumentMultiProofs,
      testRevealDocument,
      {
        hiddenUris: [],
        suite: new BbsTermwiseSignatureProof2021(),
        documentLoader: customLoader
      }
    );

    // Verifier verifies proof
    const derivedProofVerified = await verifyProofMulti([result], {
      suite: new BbsTermwiseSignatureProof2021(),
      purpose: new jsigs.purposes.AssertionProofPurpose(),
      documentLoader: customLoader
    });

    expect(result).toBeDefined();
    expect(result.proof.length).toBe(2);
    expect(derivedProofVerified.verified).toBeTruthy();
  });

  it("should sign and verify a VC with array, then derive and verify a proof from it", async () => {
    const vc = { ...expVCDocumentWithArray };
    const hiddenUris = [
      "http://example.org/credentials/1234",
      "did:example:cityA",
      "did:example:cityB"
    ];

    await signDeriveVerifyMulti(
      [{ vc, revealDocument: expRevealDocument, key: expKey1 }],
      hiddenUris,
      customLoader,
      BbsTermwiseSignature2021,
      BbsTermwiseSignatureProof2021
    );
  });
});
