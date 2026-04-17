import * as fs from "fs";
import * as readline from "readline";

interface PacketRecord {
    timestamp: string;
    srcIP: string;
    dstIP: string;
    srcPort: number;
    dstPort: number;
    protocol: string;
    domain?: string;
    bytes: number;
}

class NetworkSniffer {
    packets: PacketRecord[] = [];
    suspiciousDomains = new Set([
        "analytics", "facebook", "google-analytics", "crashlytics",
        "bugsnag", "amplitude", "mixpanel", "doubleclick",
        "ads", "tracking", "telemetry",
    ]);

    async loadPCAP(filePath: string) {
        console.log(`📖 Loading ${filePath}...`);
        const fileStream = fs.createReadStream(filePath);
        const rl = readline.createInterface({
            input: fileStream,
            crlfDelay: Infinity,
        });

        let count = 0;
        for await (const line of rl) {
            if (line.startsWith("#")) continue;
            const parts = line.split("	");
            if (parts.length < 6) continue;

            this.packets.push({
                timestamp: parts[0],
                srcIP: parts[1],
                dstIP: parts[2],
                srcPort: parseInt(parts[3]),
                dstPort: parseInt(parts[4]),
                protocol: parts[5],
                domain: parts[6],
                bytes: parseInt(parts[7]) || 0,
            });
            count++;
        }
        console.log(`✅ Loaded ${count} packets
`);
    }

    flagSuspicious() {
        console.log("🚨 Suspicious domains detected:
");
        const suspicious: { [key: string]: number } = {};
        for (const p of this.packets) {
            if (!p.domain) continue;
            for (const sus of this.suspiciousDomains) {
                if (p.domain.toLowerCase().includes(sus)) {
                    suspicious[p.domain] = (suspicious[p.domain] || 0) + p.bytes;
                }
            }
        }

        const sorted = Object.entries(suspicious)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 20);

        for (const [domain, bytes] of sorted) {
            console.log(`  📡 ${domain} (${(bytes / 1024).toFixed(1)} KB)`);
        }
    }

    topDestinations() {
        console.log("
📊 Top destination IPs:
");
        const ips: { [key: string]: number } = {};
        for (const p of this.packets) {
            ips[p.dstIP] = (ips[p.dstIP] || 0) + p.bytes;
        }
        Object.entries(ips)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 15)
            .forEach(([ip, bytes]) => {
                console.log(`  ${ip.padEnd(16)} ${(bytes / 1024).toFixed(1)} KB`);
            });
    }
}

async function main() {
    const args = process.argv.slice(2);
    if (!args[0]) {
        console.log("Usage: npx ts-node sniffer.ts <pcap.txt> [--suspicious] [--top-ips]");
        return;
    }

    const sniffer = new NetworkSniffer();
    await sniffer.loadPCAP(args[0]);

    if (args.includes("--suspicious")) sniffer.flagSuspicious();
    if (args.includes("--top-ips")) sniffer.topDestinations();
}

main();
