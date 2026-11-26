// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Alexander S. Donahue
//
// Portable Forward-Mode Dual-Number AD & OALR `(with-region ...)` Evaluator
// for the SecMesh-PQSI Eshkol v1.3.6 S-expression modules (`eshkol/*.esk`).
// Enables deterministic cross-platform execution & exact AD derivative checks
// even on hosts where Tsotchke's native LLVM Eshkol compiler is not installed.

import fs from 'node:fs';

class Dual {
  constructor(val, dot = 0.0) {
    this.val = val;
    this.dot = dot;
  }
}

const isDual = (x) => x instanceof Dual;
const valOf = (x) => (isDual(x) ? x.val : x);
const dotOf = (x) => (isDual(x) ? x.dot : 0.0);
const toDual = (x) => (isDual(x) ? x : new Dual(x, 0.0));

function tokenize(src) {
  const tokens = [];
  let i = 0;
  while (i < src.length) {
    const ch = src[i];
    if (ch === ';') {
      while (i < src.length && src[i] !== '\n') i++;
    } else if (/\s/.test(ch)) {
      i++;
    } else if (ch === '(' || ch === ')' || ch === "'") {
      tokens.push(ch);
      i++;
    } else if (ch === '"') {
      let s = '"';
      i++;
      while (i < src.length && src[i] !== '"') {
        if (src[i] === '\\' && i + 1 < src.length) { s += src[i] + src[i + 1]; i += 2; }
        else { s += src[i]; i++; }
      }
      if (src[i] !== '"') throw new Error('Unterminated string literal');
      s += '"';
      i++;
      tokens.push(s);
    } else {
      let atom = '';
      while (i < src.length && !/[\s()";]/.test(src[i])) {
        atom += src[i++];
      }
      tokens.push(atom);
    }
  }
  return tokens;
}

function parse(tokens) {
  let pos = 0;
  function readExpr() {
    if (pos >= tokens.length) throw new Error('Unexpected EOF');
    const tok = tokens[pos++];
    if (tok === '(') {
      const list = [];
      while (pos < tokens.length && tokens[pos] !== ')') list.push(readExpr());
      if (tokens[pos] !== ')') throw new Error('Unclosed "("');
      pos++;
      return list;
    }
    if (tok === ')') throw new Error('Unexpected ")"');
    if (tok === "'") return [{ sym: 'quote' }, readExpr()];
    if (tok.startsWith('"')) return { str: JSON.parse(tok) };
    if (/^[+-]?(\d+\.?\d*|\.\d+)([eE][+-]?\d+)?$/.test(tok)) return Number(tok);
    return { sym: tok };
  }
  const forms = [];
  while (pos < tokens.length) forms.push(readExpr());
  return forms;
}

function dAdd(a, b) { return (isDual(a) || isDual(b)) ? new Dual(valOf(a) + valOf(b), dotOf(a) + dotOf(b)) : a + b; }
function dSub(a, b) { return (isDual(a) || isDual(b)) ? new Dual(valOf(a) - valOf(b), dotOf(a) - dotOf(b)) : a - b; }
function dMul(a, b) {
  if (isDual(a) || isDual(b)) {
    const da = toDual(a), db = toDual(b);
    return new Dual(da.val * db.val, da.dot * db.val + da.val * db.dot);
  }
  return a * b;
}
function dDiv(a, b) {
  if (isDual(a) || isDual(b)) {
    const da = toDual(a), db = toDual(b);
    return new Dual(da.val / db.val, (da.dot * db.val - da.val * db.dot) / (db.val * db.val));
  }
  return a / b;
}

export function evaluateEshkolSource(src) {
  const forms = parse(tokenize(src));
  const stdoutLines = [];
  let curLine = '';
  const regions = [];

  const env = new Map([
    ['+', (...args) => args.reduce(dAdd, 0)],
    ['-', (...args) => (args.length === 1 ? dSub(0, args[0]) : args.slice(1).reduce(dSub, args[0]))],
    ['*', (...args) => args.reduce(dMul, 1)],
    ['/', (...args) => (args.length === 1 ? dDiv(1, args[0]) : args.slice(1).reduce(dDiv, args[0]))],
    ['<=', (a, b) => valOf(a) <= valOf(b)],
    ['>=', (a, b) => valOf(a) >= valOf(b)],
    ['<', (a, b) => valOf(a) < valOf(b)],
    ['>', (a, b) => valOf(a) > valOf(b)],
    ['=', (a, b) => valOf(a) === valOf(b)],
    ['sqrt', (x) => (isDual(x) ? new Dual(Math.sqrt(x.val), x.dot / (2 * Math.sqrt(x.val))) : Math.sqrt(x))],
    ['log', (x) => (isDual(x) ? new Dual(Math.log(x.val), x.dot / x.val) : Math.log(x))],
    ['exp', (x) => (isDual(x) ? new Dual(Math.exp(x.val), Math.exp(x.val) * x.dot) : Math.exp(x))],
    ['sin', (x) => (isDual(x) ? new Dual(Math.sin(x.val), Math.cos(x.val) * x.dot) : Math.sin(x))],
    ['cos', (x) => (isDual(x) ? new Dual(Math.cos(x.val), -Math.sin(x.val) * x.dot) : Math.cos(x))],
    ['abs', (x) => (isDual(x) ? new Dual(Math.abs(x.val), (x.val >= 0 ? 1 : -1) * x.dot) : Math.abs(x))],
    ['derivative', (fn, x0) => {
      const res = fn(new Dual(valOf(x0), 1.0));
      return dotOf(res);
    }],
    ['display', (x) => { curLine += typeof x === 'number' ? String(x) : String(valOf(x)); }],
    ['newline', () => { stdoutLines.push(curLine); curLine = ''; }],
  ]);

  let evalSteps = 0;
  let evalDepth = 0;
  const MAX_EVAL_STEPS = 100000;
  const MAX_EVAL_DEPTH = 256;

  function evalExpr(expr, scope) {
    if (++evalSteps > MAX_EVAL_STEPS) throw new Error('Eshkol evaluator step budget exceeded');
    if (++evalDepth > MAX_EVAL_DEPTH) {
      evalDepth--;
      throw new Error('Eshkol evaluator recursion depth exceeded');
    }
    try {
      return evalExprInner(expr, scope);
    } finally {
      evalDepth--;
    }
  }

  function evalExprInner(expr, scope) {
    if (typeof expr === 'number' || typeof expr === 'boolean') return expr;
    if (expr && typeof expr === 'object' && 'str' in expr) return expr.str;
    if (expr && typeof expr === 'object' && 'sym' in expr) {
      for (let s = scope; s; s = s.parent) {
        if (s.map.has(expr.sym)) return s.map.get(expr.sym);
      }
      throw new Error(`Unbound symbol: ${expr.sym}`);
    }
    if (!Array.isArray(expr) || expr.length === 0) return null;
    const head = expr[0];
    if (head && typeof head === 'object' && 'sym' in head) {
      const kw = head.sym;
      if (kw === 'quote') return expr[1];
      if (kw === 'if') {
        return evalExpr(expr[1], scope) ? evalExpr(expr[2], scope) : (expr.length > 3 ? evalExpr(expr[3], scope) : null);
      }
      if (kw === 'or') {
        for (let i = 1; i < expr.length; i++) { const v = evalExpr(expr[i], scope); if (v) return v; }
        return false;
      }
      if (kw === 'and') {
        let v = true;
        for (let i = 1; i < expr.length; i++) { v = evalExpr(expr[i], scope); if (!v) return false; }
        return v;
      }
      if (kw === 'lambda') {
        const params = expr[1].map((p) => p.sym);
        const body = expr.slice(2);
        return (...args) => {
          const child = { map: new Map(), parent: scope };
          params.forEach((p, idx) => child.map.set(p, args[idx]));
          let out = null;
          for (const b of body) out = evalExpr(b, child);
          return out;
        };
      }
      if (kw === 'define') {
        if (Array.isArray(expr[1])) {
          const name = expr[1][0].sym;
          const params = expr[1].slice(1).map((p) => p.sym);
          const body = expr.slice(2);
          const fn = (...args) => {
            const child = { map: new Map(), parent: scope };
            params.forEach((p, idx) => child.map.set(p, args[idx]));
            let out = null;
            for (const b of body) out = evalExpr(b, child);
            return out;
          };
          scope.map.set(name, fn);
          return fn;
        }
        const val = evalExpr(expr[2], scope);
        scope.map.set(expr[1].sym, val);
        return val;
      }
      if (kw === 'let' || kw === 'let*') {
        const bindings = expr[1];
        const body = expr.slice(2);
        const child = { map: new Map(), parent: scope };
        if (kw === 'let') {
          const vals = bindings.map(([k, v]) => [k.sym, evalExpr(v, scope)]);
          for (const [k, v] of vals) child.map.set(k, v);
        } else {
          for (const [k, v] of bindings) child.map.set(k.sym, evalExpr(v, child));
        }
        let out = null;
        for (const b of body) out = evalExpr(b, child);
        return out;
      }
      if (kw === 'with-region') {
        const regionName = evalExpr(expr[1], scope);
        regions.push(regionName && regionName.sym ? regionName.sym : String(regionName));
        let out = null;
        for (const b of expr.slice(2)) out = evalExpr(b, scope);
        return out;
      }
    }
    const fn = evalExpr(head, scope);
    if (typeof fn !== 'function') throw new Error(`Not callable: ${JSON.stringify(head)}`);
    const args = expr.slice(1).map((a) => evalExpr(a, scope));
    return fn(...args);
  }

  const rootScope = { map: env, parent: null };
  let last = null;
  for (const f of forms) last = evalExpr(f, rootScope);
  if (curLine.length > 0) stdoutLines.push(curLine);
  return { lines: stdoutLines, regions, env: rootScope.map, last };
}

export function evaluateEshkolFile(filePath) {
  return evaluateEshkolSource(fs.readFileSync(filePath, 'utf8'));
}
