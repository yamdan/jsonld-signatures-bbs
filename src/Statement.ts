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
const XSD_STRING = "http://www.w3.org/2001/XMLSchema#string";
const TYPE_NAMED_NODE = "NamedNode";
const TYPE_BLANK_NODE = "BlankNode";

type Quad = {
  subject: {
    termType: string;
    value: string;
  };
  predicate: {
    termType: string;
    value: string;
  };
  object: {
    termType: string;
    value: string;
    datatype?: {
      termType: string;
      value: string;
    };
    language?: string;
  };
  graph?: {
    termType: string;
    value: string;
  };
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
  private readonly buffer: Quad;

  constructor(terms: string);
  constructor(terms: Quad);
  constructor(terms: string | Quad) {
    if (typeof terms === "string") {
      const rdfStatement = NQuads.parse(terms);
      if (rdfStatement.length < 1) {
        throw Error(
          "Cannot construct TermwiseStatement instance due to incorrect input"
        );
      }
      this.buffer = rdfStatement[0];
    } else {
      this.buffer = terms;
    }
  }

  toString(): string {
    return NQuads.serializeQuad(this.buffer);
  }

  toTerms(): [string, string, string, string] {
    const s = this.buffer.subject;
    const p = this.buffer.predicate;
    const o = this.buffer.object;
    const g = this.buffer.graph;

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
    return this.toTerms().map((term) => new Uint8Array(Buffer.from(term)));
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

    // deep copy
    const out: Quad = JSON.parse(JSON.stringify(this.buffer));
    out.subject = _skolemize(out.subject);
    out.object = { ...out.object, ..._skolemize(out.object) };
    if (out.graph) {
      out.graph = _skolemize(out.graph);
    }

    return new Statement(out);
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

    // deep copy
    const out: Quad = JSON.parse(JSON.stringify(this.buffer));
    out.subject = _deskolemize(out.subject);
    out.object = { ...out.object, ..._deskolemize(out.object) };
    if (out.graph) {
      out.graph = _deskolemize(out.graph);
    }

    return new Statement(out);
  }

  replace(from: string, to: string): Statement {
    // deep copy
    const replaced: Quad = JSON.parse(JSON.stringify(this.buffer));

    const s = replaced.subject;
    const p = replaced.predicate;
    const o = replaced.object;
    const g = replaced.graph;

    s.value = s.value.replace(from, to);
    p.value = p.value.replace(from, to);
    o.value = o.value.replace(from, to);
    if (g) {
      g.value = g.value.replace(from, to);
    }

    return new Statement(replaced);
  }
}
