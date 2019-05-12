'use strict';

const fs = require('fs')
    , https = require('https')
    , os = require('os')
    , httpSignature = require('http-signature')
    , jsSHA = require("jssha")
    , config = require('config')
;

var tenancyId      = config.get('tenant.tenancyId')
  , keyFingerprint = config.get('tenant.keyFingerprint')
  , authUserId     = config.get('tenant.authUserId')
  , privateKeyPath = config.get('tenant.privateKeyPath')
;

if(privateKeyPath.indexOf("~/") === 0) {
	privateKeyPath = privateKeyPath.replace("~", os.homedir());
}
var privateKey = fs.readFileSync(privateKeyPath, 'ascii');

function sign(request, options) {

	var apiKeyId = options.tenancyId + "/" + options.userId + "/" + options.keyFingerprint;

	var headersToSign = [
  	"host",
  	"date",
  	"(request-target)"
	];

	var methodsThatRequireExtraHeaders = ["POST", "PUT"];

	if(methodsThatRequireExtraHeaders.indexOf(request.method.toUpperCase()) !== -1) {
		options.body = options.body || "";
		var shaObj = new jsSHA("SHA-256", "TEXT");
		shaObj.update(options.body);
		request.setHeader("Content-Length", options.body.length);
		request.setHeader("x-content-sha256", shaObj.getHash('B64'));
		headersToSign = headersToSign.concat([
  		"content-type",
  		"content-length",
  		"x-content-sha256"
		]);
	}

	httpSignature.sign(request, {
		key: options.privateKey,
		keyId: apiKeyId,
		headers: headersToSign
	});

	var newAuthHeaderValue = request.getHeader("Authorization").replace("Signature ", "Signature version=\"1\",");
	request.setHeader("Authorization", newAuthHeaderValue);
}

function handleRequest(callback) {
	return function(response) {
		var responseBody = "";
		response.on('data', function(chunk) {
			responseBody += chunk;
		});
		response.on('end', function() {
      response.body = responseBody;
			callback(response);
		});
	}
}

function request(method, serviceDomain, uri, headers, body, callback) {
  var options = {
    host: serviceDomain,
    method: method,
    path: uri
  };
  if (headers) {
    options.headers = headers;
  }
  var request = https.request(options, handleRequest(callback));
  var signOptions = {
		privateKey: privateKey,
		keyFingerprint: keyFingerprint,
		tenancyId: tenancyId,
		userId: authUserId
	};
  if (body) {
    var myBody = JSON.stringify(body);
    signOptions.body = myBody;
    sign(request, signOptions);
  	request.end(myBody);
  } else {
    sign(request, signOptions);
  	request.end();
  }
}

module.exports = {
  request: request
};
