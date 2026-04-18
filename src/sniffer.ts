import { spawn } from 'child_process';
import { EventEmitter } from 'events';

interface Packet {
  protocol: string;
  source: string;
  destination: string;
  size: number;
  timestamp: Date;
}

class NetworkSniffer extends EventEmitter {
  private tcpdumpProcess: any = null;
  private isRunning = false;

  constructor() {
    super();
  }

  /**
   * Start sniffing network packets via ADB tcpdump
   * @param filter Optional tcpdump filter (e.g., "tcp port 80")
   * @param device Optional ADB device serial
   */
  start(filter = '', device = ''): void {
    if (this.isRunning) {
      console.log('Sniffer already running');
      return;
    }

    const adbCmd = device ? `adb -s ${device}` : 'adb';
    const tcpdumpFilter = filter || 'tcp or udp';
    const cmd = `${adbCmd} shell tcpdump -i any -n '${tcpdumpFilter}'`;

    console.log(`🔍 Starting packet capture...`);
    this.tcpdumpProcess = spawn('sh', ['-c', cmd]);
    this.isRunning = true;

    this.tcpdumpProcess.stdout.on('data', (data: Buffer) => {
      const lines = data.toString().split('\n').filter((l: string) => l.trim());
      for (const line of lines) {
        const packet = this.parsePacket(line);
        if (packet) {
          this.emit('packet', packet);
        }
      }
    });

    this.tcpdumpProcess.stderr.on('data', (data: Buffer) => {
      console.error('tcpdump error:', data.toString());
    });
  }

  stop(): void {
    if (this.tcpdumpProcess) {
      this.tcpdumpProcess.kill();
      this.isRunning = false;
      console.log('✓ Packet capture stopped');
    }
  }

  private parsePacket(line: string): Packet | null {
    // Example: "IP 192.168.1.100.54321 > 8.8.8.8.443: Flags [S], seq ..."
    const match = line.match(/IP\s+([\w.]+)\.(\d+)\s+>\s+([\w.]+)\.(\d+)/);
    if (!match) return null;

    const [, source, , destination] = match;
    const protocolMatch = line.match(/(tcp|udp|icmp)/i);
    const protocol = protocolMatch ? protocolMatch[1].toUpperCase() : 'IP';

    return {
      protocol,
      source,
      destination,
      size: line.length,
      timestamp: new Date(),
    };
  }
}

// Usage example
const sniffer = new NetworkSniffer();

sniffer.on('packet', (packet: Packet) => {
  console.log(`📦 ${packet.protocol} ${packet.source} → ${packet.destination}`);
});

// Start sniffing TCP on port 443 (HTTPS)
sniffer.start('tcp port 443');

// Stop after 30 seconds
setTimeout(() => sniffer.stop(), 30000);

export default NetworkSniffer;
