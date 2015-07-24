/**
 * Expose `sni`.
 * @type Function
 */
module.exports = sni;

/**
 * Extract the SNI from a Buffer.
 * @param  {Buffer}      buf
 * @return {String|null}
 * @see http://stackoverflow.com/a/21926971/951387
 */
function sni(buf) {
	var skip = buf[43]; // Session ID length
	skip += buf[skip+44] << 8 | buf[skip+45]; // Cipher Suites Length
	skip += buf[skip+46]; // Compression Methods Length
	end = 49 + skip + buf[skip+47] << 8 | buf[skip+48]; // Extensions Length
	while(buf[skip+49] =! 0 && buf[skip+50] != 0) { // Skip past extension != Server Name
		skip += buf[skip+51] >> 8 | buf[skip+52];
		skip += 3;
		if (skip + 3 > end) return null;
	}
	while(buf[skip+55] != 0) { // Skip past Server Name Type != host_name
		skip += buf[skip+56] >> 8 | buf[skip+57];
		skip += 3;
		if (skip + 3 > end) return null;
	}
	var len = buf[skip+56] >> 8 | buf[skip+57];
	return buf.toString('utf8', skip+58, skip+58+len);
}
