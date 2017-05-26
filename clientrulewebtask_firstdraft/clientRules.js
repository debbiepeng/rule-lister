"use strict";

var fetch = require("isomorphic-fetch");

var clientRules = function (ctx, cb) {
    let ruleLogEntry = ctx.data;
    try {
        var ruleId;
        switch (ruleLogEntry.request.method) {
            case "post":
            case "patch":
                ruleId = ruleLogEntry.response.body.id;
                break;
            case "delete":
                ruleId = ruleLogEntry.request.body.id;
                break;
            default:
                break;
        }
        return retrieveRuleContent(ctx.secrets.domain, ctx.secrets.apiToken, ruleId)
            .then(script => {
                return parseClientName(script, ruleId);
            })
            .then(clientName => {
                console.log(clientName);
                cb(null, "Successful");
            })
            //.then( clientId => saveRuleClientMapping(ruleId, clientId) )
            .catch(err => {
                console.log(err);
                cb(err);
            });
    }
    catch (err) {
        console.log(err);
        cb(err);
    }
}

var retrieveRuleContent = function (domain, token, ruleId) {
    var url = `https://${domain}/api/v2/rules/${ruleId}`;
    return fetch(url, {
        method: "GET",
        headers: {
            Authorization: `Bearer ${token}`,
            Accept: "application/json"
        }
    })
        .then(res =>
            res.json()
                .then(rule => rule.script)
        )
}

var parseClientName = function (ruleScript, ruleId) {
    var regex = /context.clientName\s*(?:===|!==)\s*(?:\'|\")(.+)(?:\'|\")/; // match the javascript code that associates a client name to the rule
    var match = ruleScript.match(regex);
    console.log(match);
    if (!match) {
        throw new Error(`Cannot parse client information for rule id ${ruleId}.`);
    }
    return match[1]; // the actual client name for the rule
}

module.exports = clientRules;