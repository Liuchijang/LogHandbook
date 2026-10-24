#!/usr/bin/env node
/* Validates data.js: structural integrity + the "forgot to translate" bug class
   (an EN field silently falling back to its Vietnamese source text). Zero deps. */
"use strict";
const fs = require("fs");
const path = require("path");

const DATA_FILE = path.join(__dirname, "data.js");
const VI_DIACRITICS = /[àáạảãâầấậẩẫăằắặẳẵèéẹẻẽêềếệểễìíịỉĩòóọỏõôồốộổỗơờớợởỡùúụủũưừứựửữỳýỵỷỹđ]/i;
const ATTACK_ID_RE = /^T\d{4}(?:\.\d{3})?$/;

function loadData() {
  const src = fs.readFileSync(DATA_FILE, "utf8");
  const sandbox = {};
  new Function(
    "globalThis",
    src +
      "\nglobalThis.GROUPS=GROUPS;globalThis.SEV_I18N=SEV_I18N;globalThis.UI=UI;" +
      "globalThis.SRC=SRC;globalThis.EN_SRC=EN_SRC;globalThis.SRC_REFS=SRC_REFS;" +
      "globalThis.E=E;globalThis.EN_FIELDS=EN_FIELDS;globalThis.attackLinks=attackLinks;"
  )(sandbox);
  return sandbox;
}

function effectiveEnPath(key, SRC, EN_SRC) {
  const override = EN_SRC[key];
  return override && override[2] !== undefined ? override[2] : SRC[key][1];
}

function validate({ GROUPS, SEV_I18N, SRC, EN_SRC, SRC_REFS, E, EN_FIELDS }) {
  const errors = [];
  const warnings = [];
  const groupKeys = new Set(GROUPS.map((g) => g.k));
  const sevKeys = new Set(Object.keys(SEV_I18N.vi));
  const srcKeys = new Set(Object.keys(SRC));
  const perGroup = {};

  // SRC-level: every source must have reference docs, and its effective EN path
  // must not be leftover Vietnamese prose.
  for (const key of srcKeys) {
    if (!SRC_REFS[key] || SRC_REFS[key].length === 0) {
      warnings.push(`SRC_REFS["${key}"] is missing or empty (no reference docs for this log source).`);
    }
    const enPath = effectiveEnPath(key, SRC, EN_SRC);
    if (VI_DIACRITICS.test(enPath)) {
      errors.push(`SRC["${key}"]: effective EN log path still contains Vietnamese text: "${enPath}"`);
    }
  }

  const seenSrcId = new Set();
  E.forEach((r, i) => {
    const [srcKey, id, name, sev, attack, desc, fields, sample, hunt] = r;
    const where = `E[${i}] (${srcKey}/${id})`;

    // 1. duplicate (src,id) pairs
    const dupKey = `${srcKey}::${id}`;
    if (seenSrcId.has(dupKey)) errors.push(`${where}: duplicate src+id "${dupKey}".`);
    seenSrcId.add(dupKey);

    // 2. src must exist in SRC, and its group prefix must be a known group
    if (!srcKeys.has(srcKey)) errors.push(`${where}: unknown src key "${srcKey}" (not in SRC).`);
    const g = srcKey.split("-")[0];
    if (!groupKeys.has(g)) errors.push(`${where}: group prefix "${g}" is not in GROUPS.`);
    perGroup[g] = (perGroup[g] || 0) + 1;

    // 3. severity must be a known code
    if (!sevKeys.has(sev)) errors.push(`${where}: severity "${sev}" is not one of ${[...sevKeys].join(",")}.`);

    // 4. required non-bilingual fields present (empty `desc` is a deliberate, rare
    //    style for self-explanatory entries where name+sample already say it all)
    if (!name) errors.push(`${where}: missing name.`);
    if (!desc) warnings.push(`${where}: empty description (ok if name+sample are self-explanatory).`);

    // 5. ATT&CK IDs well-formed
    if (attack) {
      for (const tid of attack.split(",").map((s) => s.trim()).filter(Boolean)) {
        if (!ATTACK_ID_RE.test(tid)) errors.push(`${where}: malformed ATT&CK id "${tid}".`);
      }
    }

    // 6. EN overlay: replicate the app's ROWS merge, then check what the EN UI
    //    would actually render — this is the real "forgot to translate" check.
    const tr = EN_FIELDS[i] || {};
    const enName = tr.n || name;
    const enDesc = tr.d || desc;
    const enFields = tr.f !== undefined ? tr.f : fields;
    const enHunt = tr.h !== undefined ? tr.h : hunt;

    if (name && !tr.n) warnings.push(`${where}: EN_FIELDS[${i}].n missing, EN view falls back to VI name "${name}".`);
    if (desc && !tr.d) warnings.push(`${where}: EN_FIELDS[${i}].d missing, EN view falls back to VI description.`);
    if (fields && tr.f === undefined) warnings.push(`${where}: EN_FIELDS[${i}].f missing, EN view falls back to VI fields text.`);
    if (hunt && tr.h === undefined) warnings.push(`${where}: EN_FIELDS[${i}].h missing, EN view falls back to VI hunt text.`);

    for (const [label, text] of [["name", enName], ["desc", enDesc], ["fields", enFields], ["hunt", enHunt]]) {
      if (text && VI_DIACRITICS.test(text)) {
        errors.push(`${where}: EN ${label} still contains Vietnamese text: "${String(text).slice(0, 80)}..."`);
      }
    }
  });

  if (E.length !== EN_FIELDS.length) {
    errors.push(`E has ${E.length} entries but EN_FIELDS has ${EN_FIELDS.length} — they must stay index-aligned.`);
  }

  return { errors, warnings, perGroup, total: E.length };
}

function main() {
  const data = loadData();
  const { errors, warnings, perGroup, total } = validate(data);

  console.log(`Log Handbook data validation — ${total} entries`);
  console.log("Per-group counts:", perGroup);

  if (warnings.length) {
    console.log(`\n${warnings.length} warning(s):`);
    for (const w of warnings) console.log("  ! " + w);
  }

  if (errors.length) {
    console.log(`\n${errors.length} error(s):`);
    for (const e of errors) console.log("  x " + e);
    console.log("\nFAIL");
    process.exit(1);
  }

  console.log("\nPASS — no structural errors found.");
  process.exit(0);
}

main();
