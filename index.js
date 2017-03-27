var net = require('net');
var util = require('util');
var assert = require('assert');
var Stream = require('stream');
var forge = require('node-forge');

// Compatibility shim for the browser
if (forge.forge) {
	forge = forge.forge;
}

function TLSSocket(socket, options) {
	if (!(this instanceof TLSSocket)) return new TLSSocket(socket, options);

	var self = this;

	// Disallow wrapping TLSSocket in TLSSocket
	assert(!(socket instanceof TLSSocket));

	net.Socket.call(this);

	this._tlsOptions = options;
	this._secureEstablished = false;
	this._chunks = [];

	// Just a documented property to make secure sockets
	// distinguishable from regular ones.
	this.encrypted = true;

	if (!socket) { // connect() will be called later
		this.once('connect', function() {
			self._init(null);
		});
	} else {
		this._connecting = socket._connecting;

		this._socket = socket;
		this._init(socket);
	}

	// Make sure to setup all required properties like: `_connecting` before
	// starting the flow of the data
	this.readable = true;
	this.writable = true;
	this.read(0);
}
util.inherits(TLSSocket, net.Socket);

exports.TLSSocket = TLSSocket;

TLSSocket.prototype.log = function(arguments) {
	if (this._tlsOptions.debug) {
		console.log.apply(console, Array.prototype.slice.call(arguments));
	}
}

TLSSocket.prototype._init = function(socket) {
	var self = this;
	var options = this._tlsOptions;

	this.ssl = forge.tls.createConnection({
		server: false,
		verify: function(connection, verified, depth, certs) {
			if (!options.rejectUnauthorized || !options.servername) {
				self.log('[tls] server certificate verification skipped');
				return true;
			}

			self.log('[tls] skipping certificate trust verification');
			verified = true;

			if (depth === 0) {
				var cn = certs[0].subject.getField('CN').value;
				if (cn !== options.servername) {
					verified = {
						alert: forge.tls.Alert.Description.bad_certificate,
						message: 'Certificate common name does not match hostname.'
					};
					console.warn('[tls] '+cn+' !== '+options.servername);
				}
				self.log('[tls] server certificate verified');
			}

			return verified;
		},
		connected: function(connection) {
			self.log('[tls] connected', self);
			// prepare some data to send (note that the string is interpreted as
			// 'binary' encoded, which works for HTTP which only uses ASCII, use
			// forge.util.encodeUtf8(str) otherwise
			//client.prepare('GET / HTTP/1.0\r\n\r\n');

			self._secureEstablished = true;
			self._writePending();
			self.emit('secure');
		},
		tlsDataReady: function(connection) {
			// encrypted data is ready to be sent to the server
			var data = connection.tlsData.getBytes();
			//self.log('[tls] sending encrypted: ', data, data.length);
			//self._socket.write(data, 'binary'); // encoding should be 'binary'
			net.Socket.prototype.write.call(self._socket, data, 'binary'); // encoding should be 'binary'
		},
		dataReady: function(connection) {
			// clear data from the server is ready
			var data = connection.data.getBytes(),
				buffer = new Buffer(data, 'binary');

			self.log('[tls] received: ', data);
			self.push(buffer);
		},
		closed: function() {
			self.log('[tls] disconnected');
			self.end();
		},
		error: function(connection, error) {
			self.log('[tls] error', error);
			error.toString = function () {
				return 'TLS error: '+error.message;
			};
			self.emit('error', error);
		}
	});

	this._socket.push = function (data) {
		self.ssl.process(data.toString('binary')); // encoding should be 'binary'
	};

	// Socket already has some buffered data - emulate receiving it
	if (socket && socket._readableState.length) {
		var buf;
		while ((buf = socket.read()) !== null) {
			this.ssl.process(buf); // Do we need this?
		}
	}

	this.log('[tls] init');

	// Start handshaking if connected
	if (this._socket.readyState != 'open') {
		this._socket.once('connect', function () {
			self.emit('connect');
			self._start();
		});
	} else {
		this._start();
	}
};

TLSSocket.prototype._start = function () {
	this.log('[tls] handshaking');
	this.ssl.handshake();
};

TLSSocket.prototype._read = function () {};

TLSSocket.prototype._writenow = function (data, encoding, cb) {
	cb = cb || function () {};

	this.log('[tls] sending: ', data.toString('utf8'));
	var result = this.ssl.prepare(data.toString('binary'));

	process.nextTick(function () {
		var err = (result !== false) ? null : 'Error while packaging data into a TLS record';
		cb(err);
	});
};

TLSSocket.prototype._writePending = function() {
	if (this._chunks.length > 0) {
		for (var i in this._chunks) {
			this._writenow(this._chunks[i][0], this._chunks[i][1], this._chunks[i][2]);
		}
		this._chunks = [];
	}
};

TLSSocket.prototype._write = function (data, encoding, cb) {
	if (!this._secureEstablished) {
		this._chunks.push([data, encoding, cb]);
	} else {
		this._writePending();
		this._writenow(data, encoding, cb);
	}
};

TLSSocket.prototype.connect = function () {
	var self = this;

	self._connecting = true;

	this._socket = new net.Socket();
	this._socket.on('connect', function () {
		self._connecting = false;
		self._init(null);
	});
	this._socket.connect.apply(this._socket, arguments);

	return this;
};

TLSSocket.prototype.push = function () {
	net.Socket.prototype.push.apply(this, arguments);
	net.Socket.prototype.push.apply(this._socket, arguments);
};

function normalizeConnectArgs(listArgs) {
	var args = net._normalizeConnectArgs(listArgs);
	var options = args[0];
	var cb = args[1];
	if (util.isObject(listArgs[1])) {
		options = util._extend(options, listArgs[1]);
	} else if (util.isObject(listArgs[2])) {
		options = util._extend(options, listArgs[2]);
	}
	return (cb) ? [options, cb] : [options];
}

exports.connect = function (/* [port, host], options, cb */) {
	var args = normalizeConnectArgs(arguments);
	var options = args[0];
	var cb = args[1];

	var defaults = {
		rejectUnauthorized: '0' !== process.env.NODE_TLS_REJECT_UNAUTHORIZED,
		ciphers: null //tls.DEFAULT_CIPHERS
	};
	options = util._extend(defaults, options || {});

	var hostname = options.servername ||
		options.host ||
		options.socket && options.socket._host;

	var socket = new TLSSocket(options.socket, {
		rejectUnauthorized: options.rejectUnauthorized
	});

	// Not even started connecting yet (or probably resolving dns address),
	// catch socket errors and assign handle.
	if (options.socket) {
		options.socket.once('connect', function() {
			/*assert(options.socket._handle);
			socket._handle = options.socket._handle;
			socket._handle.owner = socket;
			socket.emit('connect');*/
		});
	}

	if (options.servername) {
		//socket.setServername(options.servername);
	}

	if (cb)
		socket.once('secure', cb);

	if (!options.socket) {
		socket.connect({
			host: options.host,
			port: options.port
		});
	}

	return socket;
};
