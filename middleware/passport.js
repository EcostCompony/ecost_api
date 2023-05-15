module.exports = passport => passport.use(new (require('passport-jwt').Strategy)({
	"jwtFromRequest": require('passport-jwt').ExtractJwt.fromAuthHeaderAsBearerToken(),
	"secretOrKey": require('./../config').JWT_SECRET_KEY
}, (payload, done) => done(null, payload)))