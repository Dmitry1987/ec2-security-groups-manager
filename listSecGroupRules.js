/*
List chosen SG rules.
*/

"use strict";
var AWS = require('aws-sdk');

var ec2 = new AWS.EC2({ region: 'us-west-2', maxRetries: 5 , sslEnabled: true });

var allSG = require('./security-groups/index.js');

// clear all ingress rules from SG, before applying new ones
function listSG(oneSG, callback) {
    var sgParams = {
        DryRun: false,
        GroupIds: [ oneSG.info.id ]
    };
    ec2.describeSecurityGroups(sgParams, function (err, data) {
        if (err) {
            console.log(err, err.stack)
            callback(err, err.stack)
        } else {
            // "data" has SecurityGroups which is all info about this SG.
            //console.log( data.SecurityGroups[0].IpPermissions);
            callback(null, data.SecurityGroups[0], sgParams.GroupIds[0] )
        }
    });
}

allSG.forEach(function(sg){
    listSG(sg, function (err, IPdata, SGname){
        var num = 0;
        if (err) {
            console.log(err + " : " + IPdata);
        } else {
            //if data arrived, iterate through IpPermissions array and list rules
            IPdata.IpPermissions.forEach(function (IpPermissions){
                num += IpPermissions.IpRanges.length;

                    if (IpPermissions.IpProtocol !== "-1") {
                        console.log("# --- SG ID: " + SGname + "  #");
                        console.log("Ports: " + IpPermissions.FromPort + " -> " + IpPermissions.ToPort + " , Protocol: " + IpPermissions.IpProtocol);
                        console.log(IpPermissions.IpRanges);
                    } else {
                        console.log("# --- SG ID: " + SGname + "  #");
                        console.log("Ports: ALL");
                        console.log(IpPermissions.IpRanges);
                    }
                })
        }
        console.log("############################################");
        console.log("TOTAL FOR " + SGname + " : " + num);
        console.log("############################################");
    } );
});

