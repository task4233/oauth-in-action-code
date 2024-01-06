var express = require("express");
var url = require("url");
var bodyParser = require('body-parser');
var randomstring = require("randomstring");
var cons = require('consolidate');
var nosql = require('nosql').load('database.nosql');
var querystring = require('querystring');
var __ = require('underscore');
const { request } = require("http");
__.string = require('underscore.string');

var app = express();

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true })); // support form-encoded bodies (for the token endpoint)

app.engine('html', cons.underscore);
app.set('view engine', 'html');
app.set('views', 'files/authorizationServer');
app.set('json spaces', 4);

// authorization server information
var authServer = {
	authorizationEndpoint: 'http://localhost:9001/authorize',
	tokenEndpoint: 'http://localhost:9001/token'
};

// client information
var clients = [

	/*
	 * Enter client information here
	 */
	{
		"client_id": "oauth-client-1",
		"client_secret": "oauth-client-secret-1",
		"redirect_uris": ["http://localhost:9000/callback"],
	}
];

var codes = {};

var requests = {};

var getClient = function (clientId) {
	return __.find(clients, function (client) { return client.client_id == clientId; });
};

app.get('/', function (req, res) {
	res.render('index', { clients: clients, authServer: authServer });
});

app.get("/authorize", function (req, res) {

	/*
	 * Process the request, validate the client, and send the user to the approval page
	 */
	const client = getClient(req.query.client_id);
	if (!client) {
		res.render('error', { error: 'Unknown client.'});
		return;
	}

	if (!__.contains(client.redirect_uris, req.query.redirect_uri)) {
		res.render('error', { error: 'Invalid redirect URI.'});
		return;
	}

	// in order to preserve query parameters in an initial authorization request
	const req_id = randomstring.generate(8);
	requests[req_id] = req.query;

	res.render('approve', {client: client, reqid: req_id});
});

app.post('/approve', function (req, res) {

	/*
	 * Process the results of the approval page, authorize the client
	 */

	// find the initial authorization request information(query)
	const req_id = req.body.reqid;
	const query = requests[req_id];
	delete requests[req_id];
	if (!query) {
		res.render('error', { error: 'No matching authorization request'});
		return;
	}

	// if the request is not approved, the authorization server denies an access and redirect to the client.
	if (!req.body.approve) {
		const urlParsed = buildUrl(query.redirect_uri, {
			error: 'access_denied',
		});
		res.redirect(urlParsed);
		return;
	}

	if (query.response_type !== 'code') {

		const urlParsed = buildUrl(query.redirect_uri, {
			error: 'unsupported_response_type'
		});
		res.redirect(urlParsed);
		return;
	}

	const code = randomstring.generate(8);
	codes[code] = {request: query};
	const urlParsed = buildUrl(query.redirect_uri, {
		code: code,
		state: query.state
	});
	res.redirect(urlParsed);
	return;
});

app.post("/token", function (req, res) {

	/*
	 * Process the request, issue an access token
	 */

	const auth = req.headers['authorization'];
	let clientID = null;
	let clientSecret = null;
	if (auth) {
		const clientCredentials = decodeClientCredentials(auth);
		clientID = clientCredentials.id;
		clientSecret = clientCredentials.secret;
	}

	if (req.body.client_id) {
		if (clientID) {
			res.status(401).json({ error: 'invalid_client_duplicate'});
			return;
		}

		clientID = req.body.client_id;
		clientSecret = req.body.client_secret;
	}

	// find client and validate client_secret
	const client = getClient(clientID);
	if (!client) {
		res.status(401).json({error: 'invalid_client_find'});
		return;
	}
	if (client.client_secret !== clientSecret) {
		res.status(401).json({error: 'invalid_client_secret'});
		return;
	}

	// confirm grant_type
	if (req.body.grant_type !== 'authorization_code') {
		res.status(401).json({error: 'invalid_grant_type'});
		return;
	}

	// find the code
	const code = codes[req.body.code];
	if (!code) {
		res.status(400).json({error: 'invalid_grant'});
		return;
	}

	// use the code
	delete codes[req.body.code];
	if (code.request.client_id !== clientID) {
		res.status(400).json({error: 'invalid_grant'});
		return;
	}

	const access_token = randomstring.generate();
	nosql.insert({access_token: access_token, client_id: clientID});

	const token_response = {
		access_token: access_token,
		token_type: 'Bearer'
	}
	res.status(200).json(token_response);
});

var buildUrl = function (base, options, hash) {
	var newUrl = url.parse(base, true);
	delete newUrl.search;
	if (!newUrl.query) {
		newUrl.query = {};
	}
	__.each(options, function (value, key, list) {
		newUrl.query[key] = value;
	});
	if (hash) {
		newUrl.hash = hash;
	}

	return url.format(newUrl);
};

var decodeClientCredentials = function (auth) {
	var clientCredentials = Buffer.from(auth.slice('basic '.length), 'base64').toString().split(':');
	var clientId = querystring.unescape(clientCredentials[0]);
	var clientSecret = querystring.unescape(clientCredentials[1]);
	return { id: clientId, secret: clientSecret };
};

app.use('/', express.static('files/authorizationServer'));

// clear the database
nosql.clear();

var server = app.listen(9001, 'localhost', function () {
	var host = server.address().address;
	var port = server.address().port;

	console.log('OAuth Authorization Server is listening at http://%s:%s', host, port);
});

