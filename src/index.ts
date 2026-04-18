import * as pcap from "pcap";
import chalk from "chalk";

interface PacketInfo {
    timestamp: Date;
    srcIp: string;
    dstIp: string;
    protocol: string;
    port: number;
    size: number;
    app?: string;
}

export class NetworkSniffer {
    private packets: PacketInfo[] = [];

    start(deviceIp?: string): void {
        console.log(chalk.cyan("\n📡 Network Sniffer Started"));
        console.log(chalk.dim("Listening for packets...\n"));

        const pcapSession = pcap.createSession("", {
            filter: "ip",
            buffer_size: 10 * 1024 * 1024,
        });

        pcapSession.on("packet", (rawPacket: any) => {
            try {
                const packet = pcap.decode.packet(rawPacket);
                if (packet.payload?.payload) {
                    const info = this.parsePacket(packet);
                    if (info) {
                        this.packets.push(info);
                        this.printPacket(info);
                        if (this.packets.length % 50 === 0) {
                            console.log(chalk.gray(`✓ Captured ${this.packets.length} packets`));
                        }
                    }
                }
            } catch (e) {
                // Silently skip parse errors
            }
        });

        process.on("SIGINT", () => {
            this.printSummary();
            process.exit(0);
        });
    }

    private parsePacket(packet: any): PacketInfo | null {
        try {
            const ipLayer = packet.payload;
            const srcIp = ipLayer.saddr.addr.join(".");
            const dstIp = ipLayer.daddr.addr.join(".");
            
            let protocol = "UNKNOWN";
            let port = 0;

            if (ipLayer.protocol === 6) { // TCP
                protocol = "TCP";
                const tcpLayer = ipLayer.payload;
                port = tcpLayer?.dport || 0;
            } else if (ipLayer.protocol === 17) { // UDP
                protocol = "UDP";
                const udpLayer = ipLayer.payload;
                port = udpLayer?.dport || 0;
            }

            return {
                timestamp: new Date(),
                srcIp,
                dstIp,
                protocol,
                port,
                size: ipLayer.total_length || 0,
            };
        } catch {
            return null;
        }
    }

    private printPacket(info: PacketInfo): void {
        const proto = chalk.yellow(info.protocol);
        const ip = chalk.cyan(\`\${info.dstIp}\`);
        const port = info.port > 0 ? chalk.gray(\`:\${info.port}\`) : "";
        console.log(\`  \${proto} → \${ip}\${port} (\${info.size}B)\`);
    }

    private printSummary(): void {
        const byProto = this.groupBy(this.packets, (p) => p.protocol);
        console.log(chalk.bold("\n📊 Summary"));
        console.log(chalk.dim("━".repeat(40)));
        console.log(\`Total packets: \${this.packets.length}\`);
        Object.entries(byProto).forEach(([proto, pkts]: [string, any]) => {
            console.log(\`  \${proto}: \${pkts.length}\`);
        });
    }

    private groupBy<T>(arr: T[], fn: (x: T) => string): Record<string, T[]> {
        return arr.reduce((acc, x) => {
            const key = fn(x);
            if (!acc[key]) acc[key] = [];
            acc[key].push(x);
            return acc;
        }, {} as Record<string, T[]>);
    }
}
