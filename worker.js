/* RSAttax compute worker — runs Pyodide + the RSA attack & ISO/IEC suites off the main thread. */
importScripts("https://cdn.jsdelivr.net/pyodide/v0.26.4/full/pyodide.js");

let pyodide = null;

async function init() {
  pyodide = await loadPyodide();
  const files = ["rsakit.py", "rsattax_attacks.py", "pkc_iso_lab.py", "rsattax_iso.py"];
  const sources = await Promise.all(
    files.map((f) => fetch(f).then((r) => r.text()))
  );
  files.forEach((f, i) => pyodide.FS.writeFile(f, sources[i]));
  pyodide.runPython('import sys; sys.path.insert(0, "")');
  pyodide.runPython("import json; import rsattax_attacks as A; import rsattax_iso as ISO");
  postMessage({ type: "ready" });
}

const ready = init().catch((err) =>
  postMessage({ type: "fatal", error: String(err) })
);

function pyjson(expr) {
  return JSON.parse(pyodide.runPython("json.dumps(" + expr + ")"));
}

onmessage = async (e) => {
  await ready;
  const { id, cmd, aid, msg, n, exp } = e.data;
  try {
    let data;
    if (cmd === "iso_selftest") {
      data = pyjson("ISO.standards_selftest()");
    } else if (cmd === "iso_validate") {
      pyodide.globals.set("_n", n);
      pyodide.globals.set("_e", exp);
      data = pyjson("ISO.validate_public_key(_n, _e)");
    } else {
      pyodide.globals.set("_aid", aid);
      pyodide.globals.set("_msg", msg);
      data = pyjson("A.run(_aid, _msg)");
    }
    postMessage({ type: "result", id, data });
  } catch (err) {
    postMessage({
      type: "result",
      id,
      data: { success: false, name: aid || cmd, recovered: "error: " + String(err), error: String(err) },
    });
  }
};
