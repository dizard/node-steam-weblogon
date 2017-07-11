var crypto = require('crypto');

var request = require('request');
var SteamCrypto = require('steam-crypto');


var SteamEResultOK = 1;

function handleLogOnResponse(logOnResponse) {
    if (logOnResponse.eresult === SteamEResultOK) {
        this._webLoginKey = logOnResponse.webapi_authenticate_user_nonce;
    }
}

function SteamWebLogOn(steamClient, steamUser) {
    this._steamClient = steamClient;
    this._steamUser = steamUser;

    this._steamClient.on('logOnResponse', handleLogOnResponse.bind(this));
}

SteamWebLogOn.prototype.webLogOn = function (callback, proxy) {
    var sessionKey = SteamCrypto.generateSessionKey();
    console.log(proxy);

    args = {
        steamid: this._steamClient.steamID,
        sessionkey: sessionKey.encrypted,
        encrypted_loginkey: SteamCrypto.symmetricEncrypt(
            new Buffer(this._webLoginKey),
            sessionKey.plain
        )
    };

    var data = Object.keys(args).map(function(key) {
        var value = args[key];
        if (Array.isArray(value))
            return value.map(function(value, index) {
                return key + '[' + index + ']=' + value;
            }).join('&');
        else if (Buffer.isBuffer(value))
            return key + '=' + value.toString('hex').replace(/../g, '%$&');
        else
            return key + '=' + encodeURIComponent(value);
    }).join('&');

    request.post({
        'url':'https://api.steampowered.com/ISteamUserAuth/AuthenticateUser/v1',
        'body' : data,
        'headers' : {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Content-Length': data.length
        },
        'proxy':proxy
    }, function (error, response, body) {
        if (error || response.statusCode !== 200) {
            this._steamUser.requestWebAPIAuthenticateUserNonce(function (nonce) {
                this._webLoginKey = nonce.webapi_authenticate_user_nonce;
                this.webLogOn(callback, proxy);
            }.bind(this));
            return;
        }

        body = JSON.parse(body);

        this.sessionID = crypto.randomBytes(12).toString('hex');
        this.cookies = [
            'sessionid=' + this.sessionID,
            'steamLogin=' + body.authenticateuser.token,
            'steamLoginSecure=' + body.authenticateuser.tokensecure
        ];

        callback(this.sessionID, this.cookies);
    }.bind(this));
};

module.exports = SteamWebLogOn;
