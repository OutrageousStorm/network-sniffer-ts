#!/usr/bin/env node
/**
 * network-sniffer-ts -- Capture and analyze network packets on Android
 * Usage: npx ts-node src/index.ts --filter "8.8.8.8" --limit 50
 */

import { execSync } from 'child_process';
import { ArgumentParser } from 'argparse';

interface Packet {
  src: string;
  dst: string;
  proto: string;
  size: number;
  flags?: string;
}

class AndroidSniffer {
  private packets: Packet[] = [];

  adb(cmd: string): string {
    try {
      return execSync(`adb shell ${cmd}`, { encoding: 'utf-8' }).trim();
    } catch (e) {
      return '';
    }
  }

  start(duration: number = 10, filter?: string): void {
    console.log(`\n📡 Capturing packets for ${duration}s...\n`);
    const end_time = Date.now() + duration * 1000;

    // Parse netstat output repeatedly
    while (Date.now() < end_time) {
      const output = this.adb('netstat -tuln');
      this.parseNetstat(output, filter);
      process.stdout.write('.');
    }
    console.log('\n');
    this.displayResults();
  }

  parseNetstat(output: string, filter?: string): void {
    const lines = output.split('\n');
    for (const line of lines) {
      const match = line.match(/(\S+)\s+\d+\s+\d+\s+(\S+)\s+(\S+)\s+(\S+)/);
      if (!match) continue;

      const [, proto, recv_q, src, dst, state] = match;
      if (filter && !src.includes(filter) && !dst.includes(filter)) continue;

      this.packets.push({
        src,
        dst,
        proto,
        size: parseInt(recv_q) || 0,
      });
    }
  }

  displayResults(): void {
    if (this.packets.length === 0) {
      console.log('No packets captured.');
      return;
    }

    console.log(`\n${'Src':<25} ${'Dst':<25} ${'Proto':<8} ${'Size'}`);
    console.log('─'.repeat(70));

    const seen = new Set<string>();
    for (const pkt of this.packets) {
      const key = `${pkt.src}→${pkt.dst}`;
      if (!seen.has(key)) {
        console.log(`${pkt.src:<25} ${pkt.dst:<25} ${pkt.proto:<8} ${pkt.size}`);
        seen.add(key);
      }
    }

    console.log(`\nTotal unique flows: ${seen.size}`);
  }
}

const parser = new ArgumentParser({ description: 'Android network sniffer' });
parser.add_argument('--duration', { type: 'int', default: 10, help: 'Capture duration in seconds' });
parser.add_argument('--filter', { help: 'Filter by IP address' });
parser.add_argument('--limit', { type: 'int', default: 50, help: 'Max packets to display' });

const args = parser.parse_args();
const sniffer = new AndroidSniffer();
sniffer.start(args.duration, args.filter);
