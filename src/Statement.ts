/*
 * The code in this file partially originated from
 * @see https://github.com/digitalbazaar/rdf-canonize
 * Hence the following copyright notice applies
 *
 * Copyright (c) 2016-2021 Digital Bazaar, Inc. All rights reserved.
 */

import rdfCanonize from "rdf-canonize";
const NQuads = rdfCanonize.NQuads;

const RDF = "http://www.w3.org/1999/02/22-rdf-syntax-ns#";
const RDF_LANGSTRING = RDF + "langString";
export const XSD_STRING = "http://www.w3.org/2001/XMLSchema#string";
export const XSD_INTEGER = "http://www.w3.org/2001/XMLSchema#integer";
export const TYPE_NAMED_NODE = "NamedNode";
export const TYPE_BLANK_NODE = "BlankNode";
const U8_STRING = 0;
const U8_INTEGER = 1;

export type RDFTerm = {
  termType: string;
  value: string;
};

export type RDFObjectTerm = {
  termType: string;
  value: string;
  datatype?: RDFTerm;
  language?: string;
};

/**
 * Escape string to N-Quads literal
 */
const _escape = (s: string): string => {
  return s.replace(/["\\\n\r]/g, (match: string): string => {
    switch (match) {
      case '"':
        return '\\"';
      case "\\":
        return "\\\\";
      case "\n":
        return "\\n";
      case "\r":
        return "\\r";
      default:
        return "";
    }
  });
};

export class Statement {
  subject: RDFTerm;
  predicate: RDFTerm;
  object: RDFObjectTerm;
  graph: RDFTerm;

  constructor(
    terms?: string,
    subject?: RDFTerm,
    predicate?: RDFTerm,
    object?: RDFObjectTerm,
    graph?: RDFTerm
  ) {
    if (terms) {
      const rdfStatement = NQuads.parse(terms);
      if (rdfStatement.length < 1) {
        throw Error(
          "Cannot construct TermwiseStatement instance due to incorrect input"
        );
      }
      const statement = rdfStatement[0];
      this.subject = statement.subject;
      this.predicate = statement.predicate;
      this.object = statement.object;
      this.graph = statement.graph;
    } else if (subject && predicate && object && graph) {
      this.subject = { ...subject };
      this.predicate = { ...predicate };
      this.object = { ...object };
      if (object.datatype) {
        this.object.datatype = { ...object.datatype };
      }
      this.graph = { ...graph };
    } else {
      throw Error(
        "Either string or (subject, predicate, object, graph) must be given to Statement constructor"
      );
    }
  }

  toString(): string {
    return NQuads.serializeQuad({
      subject: this.subject,
      predicate: this.predicate,
      object: this.object,
      graph: this.graph
    });
  }

  toTerms(): [string, string, string, string] {
    const s = this.subject;
    const p = this.predicate;
    const o = this.object;
    const g = this.graph;

    // subject can only be NamedNode or BlankNode
    const sOut = s.termType === TYPE_NAMED_NODE ? `<${s.value}>` : `${s.value}`;

    // predicate can only be NamedNode
    const pOut = `<${p.value}>`;

    // object is NamedNode, BlankNode, or Literal
    let oOut = "";
    if (o.termType === TYPE_NAMED_NODE) {
      oOut = `<${o.value}>`;
    } else if (o.termType === TYPE_BLANK_NODE) {
      oOut = o.value;
    } else {
      oOut += `"${_escape(o.value)}"`;
      if (o.datatype?.value === RDF_LANGSTRING) {
        if (o.language) {
          oOut += `@${o.language}`;
        }
      } else if (o.datatype?.value !== XSD_STRING) {
        oOut += `^^<${o.datatype?.value}>`;
      }
    }

    // graph can only be NamedNode or BlankNode (or DefaultGraph, but that
    // does not add to `nquad`)
    let gOut = "";
    if (g?.termType === TYPE_NAMED_NODE) {
      gOut = `<${g.value}>`;
    } else if (g?.termType === TYPE_BLANK_NODE) {
      gOut = `${g.value}`;
    }

    return [sOut, pOut, oOut, gOut];
  }

  serialize(): Uint8Array[] {
    return this.toTerms().map((term) => {
      // integer (32-bit positive)
      if (term.endsWith(`"^^<${XSD_INTEGER}>`)) {
        const val = term.slice(1, -`"^^<${XSD_INTEGER}>`.length);
        if (val.match(/[1-9]\d*/)) {
          const num = parseInt(val);
          if (Number.isSafeInteger(num) && Math.abs(num) < 2 ** 31) {
            return Uint8Array.of(
              U8_INTEGER, // shows that this array encodes 32-bit integer (big endian)
              (num & 0xff000000) >> 24,
              (num & 0x00ff0000) >> 16,
              (num & 0x0000ff00) >> 8,
              (num & 0x000000ff) >> 0
            );
          }
        }
      }

      // string
      return new Uint8Array([
        U8_STRING, // shows that this array encodes string
        ...Buffer.from(term)
      ]);
    });
  }

  skolemize(auxilliaryIndex?: number): Statement {
    const index = auxilliaryIndex !== undefined ? `${auxilliaryIndex}` : "";

    const _skolemize = (from: {
      value: string;
      termType: string;
    }): { value: string; termType: string } => {
      const to = { ...from };
      if (from.termType === TYPE_BLANK_NODE) {
        to.value = from.value.replace(
          /^(_:c14n[0-9]+)$/,
          `urn:bnid:${index}:$1`
        );
        if (to.value !== from.value) {
          to.termType = TYPE_NAMED_NODE;
        }
      }
      return to;
    };

    return new Statement(
      undefined,
      _skolemize(this.subject),
      this.predicate,
      { ...this.object, ..._skolemize(this.object) },
      this.graph ? _skolemize(this.graph) : undefined
    );
  }

  /**
   * Transform the blank node identifier placeholders for the document statements
   * back into actual blank node identifiers
   * e.g., <urn:bnid:_:c14n0> => _:c14n0
   */
  deskolemize(): Statement {
    const _deskolemize = (from: {
      value: string;
      termType: string;
    }): { value: string; termType: string } => {
      const to = { ...from };
      if (from.termType === TYPE_NAMED_NODE) {
        to.value = from.value.replace(/^urn:bnid:(_:c14n[0-9]+)$/, "$1");
        if (to.value !== from.value) {
          to.termType = TYPE_BLANK_NODE;
        }
      }
      return to;
    };

    return new Statement(
      undefined,
      _deskolemize(this.subject),
      this.predicate,
      { ...this.object, ..._deskolemize(this.object) },
      this.graph ? _deskolemize(this.graph) : undefined
    );
  }

  replace(from: string, to: string): Statement {
    const s = { ...this.subject };
    const p = { ...this.predicate };
    const o = { ...this.object };
    if (this.object.datatype) {
      o.datatype = { ...this.object.datatype };
    }
    const g = { ...this.graph };

    s.value = s.value.replace(from, to);
    p.value = p.value.replace(from, to);
    o.value = o.value.replace(from, to);
    if (g) {
      g.value = g.value.replace(from, to);
    }

    return new Statement(undefined, s, p, o, g);
  }
}
