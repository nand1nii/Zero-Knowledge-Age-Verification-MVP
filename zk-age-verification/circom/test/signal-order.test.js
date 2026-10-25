// circom/test/signal-order.test.js
// Confirms the circuit's public-signal order matches shared/constants.js, in the source,
// in the compiled circuit (.sym file) and in the verification key.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const C = require('../../shared/constants');
const { PATHS } = require('./helpers');

describe('public signal order matches shared/constants.js', () => {
  const source = fs.readFileSync(PATHS.circuit, 'utf8');

  it('in the `component main {public [...]}` list', () => {
    const match = source.match(/component\s+main\s*\{\s*public\s*\[([^\]]*)\]/);
    assert.ok(match, 'could not find the main component');
    const listed = match[1].split(',').map((s) => s.trim()).filter(Boolean);
    assert.deepEqual(listed, [...C.PUBLIC_SIGNALS]);
  });

  it('in the order the public inputs are declared', () => {
    const declared = [...source.matchAll(/signal\s+input\s+(\w+)\s*;/g)].map((m) => m[1]);
    assert.deepEqual(declared.filter((n) => C.PUBLIC_SIGNALS.includes(n)), [...C.PUBLIC_SIGNALS]);
    assert.deepEqual(declared.filter((n) => !C.PUBLIC_SIGNALS.includes(n)).sort(), [...C.PRIVATE_INPUTS].sort());
  });

  it('in the compiled circuit: wires 1..6 are the public inputs, in order', () => {
    // .sym lines look like "labelId,wireId,componentId,main.signalName".
    const wireToName = new Map();
    for (const line of fs.readFileSync(PATHS.sym, 'utf8').split('\n')) {
      const [, wire, , name] = line.split(',');
      if (name && name.startsWith('main.') && !name.slice(5).includes('.')) wireToName.set(Number(wire), name.slice(5));
    }
    const firstWires = C.PUBLIC_SIGNALS.map((_, i) => wireToName.get(i + 1));
    assert.deepEqual(firstWires, [...C.PUBLIC_SIGNALS]);
  });

  it('in the verification key: nPublic equals NUM_PUBLIC_SIGNALS (6)', () => {
    const vkey = JSON.parse(fs.readFileSync(PATHS.vkey, 'utf8'));
    assert.equal(C.NUM_PUBLIC_SIGNALS, 6);
    assert.equal(vkey.nPublic, C.NUM_PUBLIC_SIGNALS);
  });
});
