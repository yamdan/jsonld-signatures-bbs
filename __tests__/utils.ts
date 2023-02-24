import jsigs from "jsonld-signatures";
import { deriveProof, deriveProofMulti, verifyProofMulti } from "../src/index";
import { getProofs } from "../src/utilities";

export const signDeriveVerify = async (
  vc: any,
  reveal: any,
  key: any,
  customLoader: any,
  signSuite: any,
  proofSuite: any,
  subject?: any,
  hiddenUris?: string[]
) => {
  // Issuer issues VC
  const signedVc = await jsigs.sign(vc, {
    suite: new signSuite({ key }),
    purpose: new jsigs.purposes.AssertionProofPurpose(),
    documentLoader: customLoader
  });
  expect(signedVc).toBeDefined();

  // Holder verifies VC
  const verifiedVc = await jsigs.verify(signedVc, {
    suite: new signSuite(),
    purpose: new jsigs.purposes.AssertionProofPurpose(),
    documentLoader: customLoader
  });
  expect(verifiedVc.verified).toBeTruthy();

  // Holder derives Proof
  const derivedProof = await deriveProof(signedVc, reveal, {
    suite: new proofSuite(),
    documentLoader: customLoader,
    hiddenUris
  });
  subject && expect(derivedProof.credentialSubject).toEqual(subject);

  // Verifier verifies proof
  const { document, proofs } = await getProofs({
    document: derivedProof,
    proofType: proofSuite.proofType,
    documentLoader: customLoader
  });
  const suite = new proofSuite();
  const result = await suite.verifyProof({
    document,
    proof: proofs[0],
    documentLoader: customLoader,
    purpose: new jsigs.purposes.AssertionProofPurpose()
  });
  expect(result.verified).toBeTruthy();
};

export const signDeriveVerifyMulti = async (
  vcRevealKeys: any[],
  hiddenUris: string[],
  customLoader: any,
  signSuite: any,
  proofSuite: any
) => {
  // Issuers issue VCs
  for (const vcRevealKey of vcRevealKeys) {
    const { vc, key } = vcRevealKey;

    const signedVc = await jsigs.sign(vc, {
      suite: new signSuite({ key }),
      purpose: new jsigs.purposes.AssertionProofPurpose(),
      documentLoader: customLoader
    });
    expect(signedVc).toBeDefined();

    vcRevealKey["signedVc"] = signedVc;
  }

  // Holder verifies VCs
  for (const { signedVc } of vcRevealKeys) {
    const verifiedVc = await jsigs.verify(signedVc, {
      suite: new signSuite(),
      purpose: new jsigs.purposes.AssertionProofPurpose(),
      documentLoader: customLoader
    });
    expect(verifiedVc.verified).toBeTruthy();
  }

  // Holder gets proofs
  const suite = new proofSuite();
  for (const vcRevealKey of vcRevealKeys) {
    const { proofs, document } = await getProofs({
      document: vcRevealKey.signedVc,
      proofType: suite.supportedDeriveProofType,
      documentLoader: customLoader
    });

    if (proofs.length === 0) {
      throw new Error(
        `There were not any proofs provided that can be used to derive a proof with this suite.`
      );
    }

    vcRevealKey["proof"] = proofs;
    vcRevealKey["document"] = document;
  }

  // Holder derives proof
  const derivedProofs = await suite.deriveProofMulti({
    inputDocuments: vcRevealKeys,
    documentLoader: customLoader,
    hiddenUris
  });
  expect(derivedProofs.length).toEqual(vcRevealKeys.length);

  // Verifier verifies proof
  const result = await suite.verifyProofMulti({
    inputDocuments: derivedProofs,
    documentLoader: customLoader,
    purpose: new jsigs.purposes.AssertionProofPurpose()
  });

  expect(result.verified).toBeTruthy();
};

export const signDeriveVerifyMultiJSigLike = async (
  vcRevealKeys: any[],
  hiddenUris: string[],
  customLoader: any,
  signSuite: any,
  proofSuite: any
) => {
  const derivedProofs = await signDeriveMultiJSigLike(
    vcRevealKeys,
    hiddenUris,
    customLoader,
    signSuite,
    proofSuite
  );

  // Verifier verifies proof
  const result = await verifyProofMulti(derivedProofs, {
    suite: new proofSuite(),
    purpose: new jsigs.purposes.AssertionProofPurpose(),
    documentLoader: customLoader
  });

  expect(result.verified).toBeTruthy();
};

export const signDeriveMultiJSigLike = async (
  vcRevealKeys: any[],
  hiddenUris: string[],
  customLoader: any,
  signSuite: any,
  proofSuite: any
): Promise<any[]> => {
  // Issuers issues VCs
  const documents: [any, any][] = await Promise.all(
    vcRevealKeys.map(
      async ({ vc, revealDocument, key }): Promise<[any, any]> => {
        const signedVc = await jsigs.sign(vc, {
          suite: new signSuite({ key }),
          purpose: new jsigs.purposes.AssertionProofPurpose(),
          documentLoader: customLoader
        });
        expect(signedVc).toBeDefined();
        return [signedVc, revealDocument];
      }
    )
  );

  // Holder verifies VCs
  for (const [signedVc, _] of documents) {
    const verifiedVc = await jsigs.verify(signedVc, {
      suite: new signSuite(),
      purpose: new jsigs.purposes.AssertionProofPurpose(),
      documentLoader: customLoader
    });
    expect(verifiedVc.verified).toBeTruthy();
  }

  // Holder derives proof
  const derivedProofs = await deriveProofMulti(documents, {
    hiddenUris,
    suite: new proofSuite(),
    documentLoader: customLoader
  });

  expect(derivedProofs.length).toEqual(vcRevealKeys.length);

  return derivedProofs;
};
