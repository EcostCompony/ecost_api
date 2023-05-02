const ExtractJwt = require('passport-jwt').ExtractJwt
const JwtStrategy = require('passport-jwt').Strategy
const config = require('./../config')

const options = {
	"jwtFromRequest": ExtractJwt.fromAuthHeaderAsBearerToken(),
	"secretOrKey": config.JWT
}

module.exports = passport => passport.use(new JwtStrategy(options, (payload, done) => done(null, payload)))