"use strict";

const readline = require("readline");

let sharedRl = null;

function getShared() {
  if (!sharedRl) {
    sharedRl = readline.createInterface({ input: process.stdin, output: process.stdout });
  }
  return sharedRl;
}

function closeShared() {
  if (sharedRl) {
    sharedRl.close();
    sharedRl = null;
  }
}

/** Plain visible prompt. Reuses one readline interface across calls — creating
 * a fresh one per call drops already-buffered stdin data on non-TTY input. */
function ask(question) {
  return new Promise((resolve) => {
    getShared().question(question, (answer) => resolve(answer.trim()));
  });
}

/** Masked prompt (passphrases) — echoes '*' per keystroke, no dependency needed. */
function askHidden(question) {
  closeShared(); // readline and raw-mode reads can't share stdin at once
  return new Promise((resolve, reject) => {
    const stdin = process.stdin;
    process.stdout.write(question);

    let input = "";
    const onData = (chunk) => {
      const str = chunk.toString("utf8");
      for (const ch of str) {
        if (ch === "\n" || ch === "\r") {
          cleanup();
          process.stdout.write("\n");
          return resolve(input);
        }
        if (ch === "\u0003") {
          cleanup();
          process.stdout.write("\n");
          return reject(new Error("aborted"));
        }
        if (ch === "\u007f" || ch === "\b") {
          if (input.length > 0) {
            input = input.slice(0, -1);
            process.stdout.write("\b \b");
          }
          continue;
        }
        input += ch;
        process.stdout.write("*");
      }
    };

    function cleanup() {
      stdin.removeListener("data", onData);
      if (stdin.isTTY) stdin.setRawMode(false);
      stdin.pause();
    }

    if (stdin.isTTY) stdin.setRawMode(true);
    stdin.resume();
    stdin.setEncoding("utf8");
    stdin.on("data", onData);
  });
}

module.exports = { ask, askHidden, closeShared };
