import { execSync } from "child_process";
import * as fs from "fs";
import * as chalk from "chalk";
import * as yargs from "yargs";

interface TrafficFrame {
  timestamp: Date;
  protocol: string;
  src: string;
  dst: string;
  srcPort?: number;
  dstPort?: number;
  size: number;
  data?: string;
}

function parseTraffic(tcpdumpOutput: string): TrafficFrame[] {
  const frames: TrafficFrame[] = [];
  const lines = tcpdumpOutput.split("\n");

  for (const line of lines) {
    if (!line.trim()) continue;

    // Parse tcpdump format: "HH:MM:SS.ffffff IP src.port > dst.port: flags seq ack win"
    const match = line.match(
      /(\d{2}:\d{2}:\d{2}\.\d+)\s+IP\s+([\d.]+)\.(\d+)\s+>\s+([\d.]+)\.(\d+)/
    );
    if (!match) continue;

    const [, time, srcIp, srcPort, dstIp, dstPort] = match;
    const protocol = line.includes("TCP") ? "TCP" : line.includes("UDP") ? "UDP" : "OTHER";

    frames.push({
      timestamp: new Date(),
      protocol,
      src: srcIp,
      dst: dstIp,
      srcPort: parseInt(srcPort),
      dstPort: parseInt(dstPort),
      size: parseInt(line.match(/(\d+)\s+bytes/)?.[1] || "0"),
    });
  }

  return frames;
}

async function main() {
  const argv = yargs
    .option("app", { description: "Package name to filter", type: "string" })
    .option("duration", { description: "Capture duration in seconds", type: "number", default: 30 })
    .option("output", { description: "Output file (JSON)", type: "string" })
    .option("filter", { description: "Filter by protocol", type: "string" })
    .parseSync();

  console.log(chalk.cyan("\n📊 Network Sniffer — Android Traffic Analyzer"));
  console.log(chalk.gray("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"));

  try {
    // Start tcpdump on device
    const cmd = `adb shell "timeout ${argv.duration} tcpdump -i any -nn -q 2>/dev/null"`;
    console.log(chalk.yellow(`⏱  Capturing ${argv.duration}s of traffic...\n`));

    const output = execSync(cmd, { encoding: "utf-8", stdio: "pipe" });
    const frames = parseTraffic(output);

    // Filter
    let filtered = frames;
    if (argv.filter) {
      filtered = frames.filter((f) => f.protocol.toLowerCase() === argv.filter?.toLowerCase());
    }

    // Display
    console.log(`Found ${filtered.length} packets:\n`);
    console.log(
      chalk.dim(
        `${"Protocol":<10} ${"Source":<18} ${"Destination":<18} ${"Size (B)":<8}`
      )
    );
    console.log(chalk.gray("─".repeat(60)));

    for (const frame of filtered.slice(0, 50)) {
      const src = `${frame.src}:${frame.srcPort || "?"}`;
      const dst = `${frame.dst}:${frame.dstPort || "?"}`;
      console.log(
        `${frame.protocol.<10} ${src.<18} ${dst.<18} ${frame.size.toString().<8}`
      );
    }

    if (argv.output) {
      fs.writeFileSync(argv.output, JSON.stringify(filtered, null, 2));
      console.log(`\n✅ Saved to ${chalk.bold(argv.output)}`);
    }

    console.log(`\n📈 Summary: ${filtered.length} packets captured`);
  } catch (error: any) {
    console.error(chalk.red(`✗ Error: ${error.message}`));
    process.exit(1);
  }
}

main();
