/*
Read config files in folder "security-groups" with client IPs, and update chosen SGs.
*/

"use strict";

//var forEach = require('async-foreach').forEach;
var AWS = require('aws-sdk');
var async = require('async');


var ec2 = new AWS.EC2({ region: 'us-west-2', maxRetries: 5 , sslEnabled: true });

// load SG config files to sync all
var allSG = require('./security-groups/index.js');


// a sleep func to limit request rate to AWS
function sleep(time, callback) {
    var stop = new Date().getTime();
    while(new Date().getTime() < stop + time) {
        ;
    }
    callback();
}


// clear all ingress rules from SG, before applying new ones
function clearSG(oneSG, callback) {
    var sgParams = {
        DryRun: false,
        GroupIds: [ oneSG.info.id ]
    };
    ec2.describeSecurityGroups(sgParams, function (err, data) {
        if (err) {
            console.log(err, err.stack);
            callback(err);
        } else {
            // "data" has SecurityGroups[0] which is all info about this SG.
            //console.log( data.SecurityGroups[0].IpPermissions);
            // iterate through all "data.SecurityGroups[0].IpPermissions"  array and revoke all rules.
            // (to begin, assign object to temporary, and clean "UserIdGroupPairs" and "PrefixListIds"
            // that breaks the "revokeSecurityGroupIngress" if used together with "cidr".
            // But 'describe" returns them both)

            var totalSets = data.SecurityGroups[0].IpPermissions.length
            var totalSetsRevoked = 0
            // if empty SG, callback now (run update now).
            // in other cases update runs only after the last 'revoke' completed.
            // to keep track if current callback is from 'last' revoke operation or there are more,
            // i used simple counter "totalSetsRevoked" vs "totalSets"(array length)
            if (totalSets === 0){
                callback(null, totalSets, totalSetsRevoked);
            } else {
                // if some inbound rules found, iterate through their sets and when all cleared,
                // callback and run updateSG. ("sets" are used and not single IPs because 'describeSecurityGroups'
                // returns sets of CIDRs grouped by common ports. Those sets are inside 'IpPermissions')
                data.SecurityGroups[0].IpPermissions.forEach(function (oneSetOfCIDRs) {
                    var modifiedIpPermissions = oneSetOfCIDRs;
                    //console.log("ONE  SET: " + oneSetOfCIDRs + " of CIDRs");

                    // deleting the fields we not need (it breaks revoke function if passed "as is" from 'describe' func)
                    delete modifiedIpPermissions.UserIdGroupPairs;
                    delete modifiedIpPermissions.PrefixListIds;

                    var ruleParams = {
                        GroupId: oneSG.info.id,
                        IpPermissions: [modifiedIpPermissions]
                    };

                    ec2.revokeSecurityGroupIngress(ruleParams, function (err, data) {
                        if (err) {
                            console.log(" Error: " + err, err.stack);
                            callback(err);
                        }
                        else {
                            totalSetsRevoked++
                            console.log("[ " + oneSG.info.name + " ] - Deleted set " + totalSetsRevoked + " from " + totalSets);
                            callback(null, totalSets, totalSetsRevoked);
                        }
                    });

                })
            }
        }
    });
}

function updateSG(oneSG) {
    var rulesNum = 0;
    var params;
    var newBunchOfIP;
    var oldPortGroupTo = oneSG.rules[0].ToPort;
    var portGroupTo = oneSG.rules[0].ToPort;
    var oldPortGroupFrom = oneSG.rules[0].FromPort;
    var portGroupFrom = oneSG.rules[0].FromPort;

    var pushIP = "0.0.0.0";

    oneSG.rules.forEach( function (oneRule) {
        // create params only on 1st run with 1st CIDR, then only push more IPs or IP groups
        portGroupTo = oneRule.ToPort;
        portGroupFrom = oneRule.FromPort;
        if ( (rulesNum == 0) && (oldPortGroupTo == portGroupTo) && (oldPortGroupFrom == portGroupFrom) ) {
            // only first time, initialize the array "IpPermissions" and params. afterwards, add to it.
            rulesNum++
            params = {
                DryRun: false,
                GroupId: oneSG.info.id,
                IpPermissions: [
                    {
                        FromPort: oneRule.FromPort,
                        IpProtocol: oneRule.Protocol,
                        ToPort: oneRule.ToPort,
                        IpRanges: [
                            {
                                CidrIp: oneRule.cidr
                            }
                        ]
                    }
                ]
            }
        } else if ((oldPortGroupTo == portGroupTo) && (oldPortGroupFrom == portGroupFrom)) {
            // for each next rule line, add to array, if it's same port group from and to.
            pushIP = { CidrIp: oneRule.cidr };
            // because we incremented rulesNum, point to 'previous bunch of IPs' here:
            params.IpPermissions[rulesNum - 1].IpRanges.push(pushIP);
        } else {
            // if one of the ports changed, then it's a new "bunch" of settings
            // that goes as object into array params.IpPermissions[]
            newBunchOfIP = {
                        FromPort: oneRule.FromPort,
                        IpProtocol: oneRule.Protocol,
                        ToPort: oneRule.ToPort,
                        IpRanges: [
                            {
                                CidrIp: oneRule.cidr
                            }
                        ]
                    };
            params.IpPermissions[rulesNum] = newBunchOfIP;

            rulesNum++;
            // update current ports that are in use, to add more of the same to array
            oldPortGroupTo = oneRule.ToPort;
            oldPortGroupFrom = oneRule.FromPort;
        }
        // end rules foreach
        });

        // add the rules to SG, and show the number of successful rules added
        ec2.authorizeSecurityGroupIngress(params, function (err, data) {
            if (err) console.log(err, err.stack);
            else     console.log("[ " + oneSG.info.name + " ] auth rules packs success " + rulesNum); // success
        });
}

// verify that no SG has more than 31 rules, otherwise exit (this is our limit in account, but you can change this).
for (var i in allSG){
    if (allSG[i].rules.length > 31){
        console.log("error: more than 31 inbound rules assigned to " + allSG[i].info.id);
        console.log("please fix the error (create new file with more rules, don't pass 31) and retry");
        process.exit()
    } else {
        console.log(allSG[i].info.name + "  - has " + allSG[i].rules.length + " rules in file.")
    }
}

// iterate array with all SGs, and clear rules + apply rules from files.
// allSG is array holding all chosen SGs like [sg1,sg2,sg3].

async.each(allSG, function(sg){
    clearSG(sg, function (err, totalSets, totalSetsRevoked){
        if (!err) {
            // if clearing current rules - was successful,
            // and total of revoked sets in SG === current revoked sets,
            // then write new rules into SG.
            if (totalSets === totalSetsRevoked){
                sleep(1000, function() {
                    // executes after one second, and blocks the thread
                    updateSG(sg)
                });
            }
        } else {
            console.log(err);
        }
    } );
}, function(err){
    // if any of the SG processing produced an error, err would equal that error
    if( err ) {
        // One of the iterations produced an error.
        // All processing will now stop.
        console.log('A SG failed to process');
    } else {
        console.log('All SG have been processed successfully');
    }
});
