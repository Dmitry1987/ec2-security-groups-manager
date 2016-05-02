// ----------------------------------------------------------------------------------------
// This file loads every security group file and will pass it to main script when required.
//-----------------------------------------------------------------------------------------

var fs = require('fs'),
    path = require('path');

module.exports = [];

function getExtension(filename) {
    var ext = path.extname(filename || '').split('.');
    return ext[ext.length - 1];
}

fs.readdirSync(__dirname).forEach(function(file) {
    if (file == path.basename(__filename))
        return;
    if (getExtension(file) != "js")
        return;

    try {
        module.exports.push(require(__dirname + "/" + file));
    } catch(e) {
        console.error("Error loading " + file + ": " + e);
    }
});