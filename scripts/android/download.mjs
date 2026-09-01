import { createWriteStream } from 'node:fs';
import { pipeline } from 'node:stream/promises';
import { Readable } from 'node:stream';

const [url, destination] = process.argv.slice(2);
if (!url || !destination) throw new Error('DOWNLOAD_ARGUMENTS_REQUIRED');
const response = await fetch(url, { redirect: 'follow' });
if (!response.ok || !response.body) throw new Error(`DOWNLOAD_FAILED:${response.status}`);
await pipeline(Readable.fromWeb(response.body), createWriteStream(destination, { flags: 'wx' }));
