#!/usr/bin/env node
const fs = require('fs');
const path = require('path');

var argv = require('yargs/yargs')(process.argv.slice(2))
    .usage(`\x1b[33m
    MalCode Analyzer for PHP v1.0.0
    ──▄──▄────▄▀
───▀▄─█─▄▀▄▄▄
▄██▄████▄██▄▀█▄
─▀▀─█▀█▀▄▀███▀
──▄▄▀─█──▀▄▄

    Usage: $0 [options]
    \x1b[0m`)
    .example('$0 -d phpscript', 'Scan a directory')
    .alias('d', 'directory')
    .nargs('d', 1)
    .describe('d', 'Directory to scan')
    .demandOption(['d'])
    .help('h')
    .alias('h', 'help')
    .argv;



const dir = path.join(__dirname, argv.directory);
//const files = fs.readdirSync(dir);

// Base64 and URL encoding
const filters = [
    "eval\\(base64_decode\\(.*\\)\\)",
    "eval\\(gzinflate\\(base64_decode\\(.*\\)\\)\\)",
    "eval\\(gzuncompress\\(base64_decode\\(.*\\)\\)\\)",
    "eval\\(str_rot13\\(base64_decode\\(.*\\)\\)\\)",
    "eval\\(strrev\\(base64_decode\\(.*\\)\\)\\)",
    "eval\\(base64_decode\\(str_rot13\\(.*\\)\\)\\)",
    "eval\\(base64_decode\\(strrev\\(.*\\)\\)\\)",
    "eval\\(base64_decode\\(gzinflate\\(.*\\)\\)\\)",
    "eval\\(base64_decode\\(gzuncompress\\(.*\\)\\)\\)",
]

const base64Regex = new RegExp(filters.join("|"), "g");
const urlRegex = new RegExp("eval\\(base64_decode\\(urldecode\\(.*\\)\\)\\)", "g");


// Function injection to check if the string is base64 or url encoded
function isBase64OrUrlEncoded(str) {
    if (str.match(base64Regex)) {
        return {
            type: "base64",
            matches: str.match(base64Regex)
        };
    } else if (str.match(urlRegex)) {
        return {
            type: "url",
            matches: str.match(urlRegex)
        }
    } else {
        return false;
    }
}


// File inclusion
const lfi = [
    "file_get_contents\\(.*\\)",
    "fopen\\(.*\\)",
    "readfile\\(.*\\)",
    "include\\(.*\\)",
    "require\\(.*\\)",
    "include_once\\(.*\\)",
    "require_once\\(.*\\)",
]

const lfiRegex = new RegExp(lfi.join("|"), "g");

// LFI detection
function isLFI(str) {
    if (str.match(lfiRegex)) {
        return {
            type: "lfi",
            matches: str.match(lfiRegex)
        };
    } else {
        return false;
    }
}


// Command injection
// Regex to match command injection
const command = [
    "exec\\(.*\\)",
    "passthru\\(.*\\)",
    "system\\(.*\\)",
    "shell_exec\\(.*\\)",
    "popen\\(.*\\)",
    "proc_open\\(.*\\)",
    "pcntl_exec\\(.*\\)",
]

const commandRegex = new RegExp(command.join("|"), "g");

// Command injection detection
function isCommandInjection(str) {
    if (str.match(commandRegex)) {
        return {
            type: "command",
            matches: str.match(commandRegex)
        };
    } else {
        return false;
    }
}



// no such file or directory
if (!fs.existsSync(dir)) {
    console.log("Directory does not exist");
    process.exit(1);
} else {
    console.log(`\x1b[36m
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
| Directory: ${dir}                    |
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        \x1b[0m`);
    const files = fs.readdirSync(dir);
    const ReadFileAndCheck = (path, file) => {
        fs.readFile(path + "/" + file, "utf8", (err, data) => {
            const str = data;
            if (isBase64OrUrlEncoded(str)) {
                console.log({
                    file: `${dir}/${file}`,
                    type: isBase64OrUrlEncoded(str).type,
                    matches: isBase64OrUrlEncoded(str).matches[0].substring(0, 50)
                })
            }
            if (isLFI(str)) {
                console.log({
                    file: `${dir}/${file}`,
                    type: isLFI(str).type,
                    matches: isLFI(str).matches
                })
            }
            if (isCommandInjection(str)) {
                console.log({
                    file: `${dir}/${file}`,
                    type: isCommandInjection(str).type,
                    matches: isCommandInjection(str).matches
                })
            }

        })
    }


    files.forEach(file => {
        ReadFileAndCheck(dir, file);
    })
}