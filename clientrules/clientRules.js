"use strict";

var app = new (require('express'))();
var wt = require('webtask-tools');
var jwtDecode = require('jwt-decode');

var fetch = require("isomorphic-fetch");
var P = require("bluebird");

var clientRules = function (ctx, req, res){
    P.join(retrieveClientNameList(ctx.secrets.domain, ctx.secrets.apiToken), 
      retrieveRules(ctx.secrets.domain, ctx.secrets.apiToken),
      (clientNames, rules) => {
        let clientRules = {};
        clientNames.forEach(clientName => {      // initialize the hash table for storing client/rule mapping
          clientRules[clientName] = [];
        });
        rules.forEach(rule => {
          let mappedClientName = parseClientName(rule.script);
          if (mappedClientName && clientRules[mappedClientName]) {
            clientRules[mappedClientName].push({id: rule.id, name: rule.name});
          }
        });
        res.writeHead(200, { 'Content-Type': 'application/json '});
        res.write(JSON.stringify(clientRules));
        res.end();
      })
      .catch( err => {
            res.writeHead(500);
            res.write(err.message);
            res.end();
          });
}

var retrieveClientNameList = function (domain, token) {
  var url = `https://${domain}/api/v2/clients`;
  return fetch(url, {
    method: "GET",
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/json"
    }
  })
  .then( res => 
   res.json()
    .then(clients => clients.map(client => client.name))
  )
}

var retrieveRules = function (domain, token) {
  var url = `https://${domain}/api/v2/rules`;
  return fetch(url, {
    method: "GET",
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/json"
    }
  })
  .then( res => 
   res.json()
    .then(rules => rules)
  );
}

var parseClientName = function(ruleScript) {
  var regex = /context.clientName\s*(?:===|!==)\s*(?:\'|\")(.+)(?:\'|\")/; // match the javascript code that associates a client name to the rule
  var match = ruleScript.match(regex);
  console.log(match);
  if (!match) {
    return null;
  }
  return match[1]; // the actual client name for the rule
}

module.exports = wt.auth0(clientRules, {
    clientId: (ctx, req) => ctx.secrets.clientId,
    clientSecret: (ctx, req) => ctx.secrets.clientSecret,
    domain: (ctx, req) => ctx.secrets.domain,
    getAccessToken: function (ctx, req) {
      return req.query.access_token;
    },
    validateToken: function (ctx, req, token, cb) {
      var decodedToken = jwtDecode(token)
      if (decodedToken.exp < Date.now() / 1000) {
        cb(new Error("Token expired.")); 
      }
      cb(null, {email: decodedToken.email, email_verified: decodedToken.email_verified});
    },
    authorized: [
      "debbiepeng@gmail.com",
      "@auth0.com"
    ]
});

