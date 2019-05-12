'use strict';

// Module imports
var express = require('express')
  , bodyParser = require('body-parser')
  , https = require('https')
  , oci = require('./oci')
  , cors = require('cors')
  , util = require('util')
  , fs = require('fs')
  , log = require('npmlog-ts')
  , config = require('config')
  , _ = require('lodash')
  , basicAuth = require('express-basic-auth')
  , bcrypt = require('bcrypt')
;

log.stream = process.stdout;
log.timestamp = true;
log.level = 'verbose';

// Custom headers
const WEDOSERVICEURI = 'wedo-service-uri'
;

const PORT = 2443
    , URI  = '/*'
    , PROCESS = "PROCESS"
    , REST = "REST"
    , USERNAME = 'wedo'
    , HASHEDPASSWORD = '$2b$10$dOh6Dvo56VxcDYFM1o43iu9WW2qYwBzh8ACd99wdQ7L0I3Zjpob0q';
;

const options = {
  cert: fs.readFileSync(config.get('ssl.privatecert')).toString(),
  key: fs.readFileSync(config.get('ssl.privatekey')).toString()
};

var app    = express()
  , router = express.Router()
  , server = https.createServer(options, app)
;

// ************************************************************************
// Main code STARTS HERE !!
// ************************************************************************

// Main handlers registration - BEGIN
// Main error handler
process.on('uncaughtException', function (err) {
  log.error(PROCESS,"Uncaught Exception: " + err);
  log.error(PROCESS,"Uncaught Exception: " + err.stack);
});
// Detect CTRL-C
process.on('SIGINT', function() {
  log.error(PROCESS,"Caught interrupt signal");
  log.error(PROCESS,"Exiting gracefully");
  process.exit(2);
});
// Main handlers registration - END

const HEADERSWHITELIST = [
  'content-type',
  'accept'
];

app.use(cors());
app.use(bodyParser.json());
app.use(basicAuth( { authorizer: myAuthorizer } ));
app.all(URI, (req, res, next) => {
  if (!req.headers["wedo-service-uri"]) {
    res.status(400).send("'wedo-service-uri' header not found").end();
  }

  var headers = {};
  _.forOwn(req.headers, (v, k) => {
    if (_.includes(HEADERSWHITELIST,k.toLowerCase())) {
      headers[k] = v;
    }
  });
  oci.request(req.method, req.headers["wedo-service-uri"], req.url, headers, (req.body) ? req.body : null, (response) => {
    res.set(response.headers);
    res.status(response.statusCode).send(response.body).end();
  });
});

server.listen(PORT, () => {
  log.info(REST,"Listening for any request at https://localhost:%s%s", PORT, URI);
});

function myAuthorizer(username, password) {
    return (username === USERNAME) && bcrypt.compareSync(password, HASHEDPASSWORD);
}
