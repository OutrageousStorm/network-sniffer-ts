// sniffer.ts - Packet analyzer for Android network traffic
import * as child_process from 'child_process';

interface Packet {
    timestamp: string;
    protocol: string;
    src: string;
    dst: string;
    port: number;
    size: number;
    flags?: string;
}

class NetworkSniffer {
    packets: Packet[] = [];
    
    async captureWithTcpdump(duration: number = 30): Promise<void> {
        console.log(`\n📡 Capturing traffic for ${duration}s...`);
        const cmd = `adb shell tcpdump -i any -w /sdcard/capture.pcap & sleep ${duration}; killall tcpdump`;
        child_process.execSync(cmd, { stdio: 'inherit' });
        child_process.execSync('adb pull /sdcard/capture.pcap .', { stdio: 'inherit' });
    }
    
    parseNetstat(): Packet[] {
        const result = child_process.execSync('adb shell netstat -tulnp 2>/dev/null || true', { encoding: 'utf-8' });
        const packets: Packet[] = [];
        
        for (const line of result.split('\n')) {
            if (line.includes('ESTABLISHED')) {
                const match = line.match(/(\d+\.\d+\.\d+\.\d+):(\d+)/);
                if (match) {
                    packets.push({
                        timestamp: new Date().toISOString(),
                        protocol: line.includes('tcp') ? 'TCP' : 'UDP',
                        src: match[1],
                        dst: '',
                        port: parseInt(match[2]),
                        size: 0
                    });
                }
            }
        }
        return packets;
    }
    
    classifyTraffic(): Map<string, number> {
        const classification = new Map<string, number>();
        
        for (const p of this.packets) {
            let category = 'Other';
            if ([443, 8443].includes(p.port)) category = 'HTTPS';
            else if (p.port === 80) category = 'HTTP';
            else if ([53, 5353].includes(p.port)) category = 'DNS';
            else if (p.port === 22) category = 'SSH';
            
            classification.set(category, (classification.get(category) || 0) + 1);
        }
        return classification;
    }
    
    report(): void {
        console.log(`\n📊 Traffic Analysis (${this.packets.length} packets)`);
        const classified = this.classifyTraffic();
        for (const [category, count] of classified) {
            console.log(`  ${category}: ${count}`);
        }
    }
}

async function main() {
    const sniffer = new NetworkSniffer();
    sniffer.packets = sniffer.parseNetstat();
    sniffer.report();
}

main().catch(console.error);
