import readline from "node:readline";

export function prompt(question) {
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    rl.question(question, (answer) => {
      rl.close();
      resolve(answer.trim());
    });
  });
}

export async function choose(question, choices) {
  const opts = choices.map((c) => c.key).join("/");
  while (true) {
    const ans = (await prompt(`${question} [${opts}] `)).toLowerCase();
    const hit = choices.find((c) => c.key === ans || c.aliases?.includes(ans));
    if (hit) return hit.key;
  }
}
