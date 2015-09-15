'use strict';

var yub = require('yub'),
    passport = require('passport-strategy'),
    util = require('util');

function Strategy(options, verify) {
    if(typeof options == 'function' || !verify) {
        throw new TypeError('YubikeyStrategy requires API keys in options');
    }

    passport.Strategy.call(this);
    this._clientID = options.clientID;
    this._secret = options.APISecret
    this.name = 'yubikey';
    this._verify = verify;
}

util.inherits(Strategy, passport.Strategy);

Strategy.prototype.authenticate = function(req) {
    if(!req.body.yubikey || req.body.yubikey.length < 32) {
        return this.fail({
            message: 'No valid yubikey provided'
        }, 400);
    }

    yub.init(this._clientID, this._secret);

    var self = this;

    function verified(err, user, info) {
        if (err) { return self.error(err); }
        if (!user) { return self.fail(info); }
        self.success(user, info);
    }

    yub.verify(req.body.yubikey, function(err, data) {
        if(data.status === 'OK') {
            self._verify(data.identity, verified);
        } else {
            return self.fail({message: 'Yubikey validation failed'});
        }
    });
};

exports = module.exports = Strategy;

exports.Strategy = Strategy;
