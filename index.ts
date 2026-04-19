import * as os from "os";
import { exec } from "child_process";

async function adb(cmd: string): Promise<string> {
  return new Promise((resolve) => {
    exec(`adb shell ${cmd}`, (error, stdout) => {
      resolve(error ? "" : stdout.trim());
    });
  });
}

interface Connection {
  remote: string;
  port: number;
  state: string;
}

async function getConnections(): Promise<Connection[]> {
  const raw = await adb("cat /proc/net/tcp");
  const conns: Connection[] = [];
  for (const line of raw.split("\n").slice(1)) {
    const parts = line.split(/\s+/);
    if (parts.length < 4) continue;
    const remoteHex = parts[2];
    if (!remoteHex.includes(":")) continue;
    const [addrPart, portPart] = remoteHex.rsplit(":", 1);
    const port = parseInt(portPart, 16);
    if (port === 0) continue;
    const bytes = Buffer.from(addrPart, "hex");
    const ip = `${bytes[3]}.${bytes[2]}.${bytes[1]}.${bytes[0]}`;
    conns.push({
      remote: `${ip}:${port}`,
      port,
      state: parts[3],
    });
  }
  return conns;
}

async function main() {
  console.log("\n🔍 Network Sniffer (TypeScript)\n");
  const conns = await getConnections();
  console.log(`${conns.length} active connections:\n`);
  console.log("Remote IP:Port".padEnd(25) + "State");
  console.log("─".repeat(40));
  for (const c of conns.slice(0, 20)) {
    console.log(c.remote.padEnd(25) + c.state);
  }
}

main().catch(console.error);
