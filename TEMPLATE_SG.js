// ----------------------------------------------------------------------------------
// This file describes single security group in AWS.
// "info" must have the ID and Name of SG. "rules" array needs all IPs to be allowed.
// in "rules" use "Protocol": "-1" to specify all traffic (from/to port then is '0')
//-----------------------------------------------------------------------------------
var info = {
	// ID is what you see in AWS console as security group id
    "id": "sg-010101abcd",
    "name": "sg name"
};
var rules = [
    // HTTPS rules
    { "cidr": "1.1.1.1/24", "FromPort": 443 , "ToPort": 443 , "Protocol": "tcp"},
    // All Traffic rule
    { "cidr": "2.2.2.2/27", "FromPort": 0 , "ToPort": 0 , "Protocol": "-1"},
	// etc'   all based on 2 examples above.
];

var exported =  { "info": info, "rules": rules }
module.exports = exported;