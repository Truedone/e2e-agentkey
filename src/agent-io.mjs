// agent-io.mjs: one ssh-agent exchange, run as a child process so the callers in agent.mjs stay synchronous. It reads
// { socket, request } from stdin (request: the message body, base64, type byte first), writes it to the agent with its
// length, and prints the reply body, base64, or nothing when the agent closes the connection first. Exit 2 when the
// socket cannot be reached. The protocol is draft-miller-ssh-agent: every message is a uint32 length and that many bytes
import net from 'node:net';
import fs from 'node:fs';

const { socket, request } = JSON.parse(fs.readFileSync(0, 'utf8'));
const body = Buffer.from(request, 'base64');
const len = Buffer.alloc(4); len.writeUInt32BE(body.length);
const c = net.createConnection(socket);
let got = Buffer.alloc(0);
c.on('error', (e) => { process.stderr.write(`${e.code || e.message}\n`); process.exit(2); });
c.on('connect', () => c.write(Buffer.concat([len, body])));
c.on('data', (d) => {
  got = Buffer.concat([got, d]);
  if (got.length >= 4 && got.length >= 4 + got.readUInt32BE(0)) {
    process.stdout.write(got.subarray(4, 4 + got.readUInt32BE(0)).toString('base64'));
    c.end();
  }
});
c.on('close', () => process.exit(0));
